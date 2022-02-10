package controllers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"gopkg.in/validator.v2"

	"github.com/ydataai/authentication-service/internal/configurations"
	authErrors "github.com/ydataai/authentication-service/internal/errors"
	"github.com/ydataai/authentication-service/internal/handlers"
	"github.com/ydataai/authentication-service/internal/models"
	"github.com/ydataai/authentication-service/internal/services"
	"github.com/ydataai/go-core/pkg/common/logging"
	"github.com/ydataai/go-core/pkg/common/server"
)

// RESTController defines rest controller.
type RESTController struct {
	configuration         configurations.RESTControllerConfiguration
	oidcService           services.OIDCService
	credentials           []handlers.CredentialsHandler
	provisionTokenService services.ProvisionTokens
	logger                logging.Logger
}

// NewRESTController initializes rest controller.
func NewRESTController(
	logger logging.Logger,
	configuration configurations.RESTControllerConfiguration,
	oidcService services.OIDCService,
	credentials []handlers.CredentialsHandler,
	provisionTokenService services.ProvisionTokens,
) RESTController {
	return RESTController{
		configuration:         configuration,
		oidcService:           oidcService,
		credentials:           credentials,
		provisionTokenService: provisionTokenService,
		logger:                logger,
	}
}

// Boot initializes creating some routes.
func (rc RESTController) Boot(s *server.Server) {
	s.Router.Use(rc.skipURLsMiddleware())

	s.Router.GET(rc.configuration.AuthServiceURL, rc.CheckForAuthentication)
	s.Router.GET(rc.configuration.OIDCCallbackURL, gin.WrapF(rc.OIDCProviderCallback))
	s.Router.GET(rc.configuration.UserInfoURL, gin.WrapF(rc.UserInfo))
	s.Router.POST(rc.configuration.LogoutURL, gin.WrapF(rc.Logout))

	profileTokensURL := s.Router.Group("/profiles/:profile-uuid")
	profileTokensURL.GET("/tokens", rc.CheckForAuthentication, rc.ListProfileTokens)
	profileTokensURL.GET("/tokens/:tokenUUID", rc.CheckForAuthentication, rc.GetProfileToken)
	profileTokensURL.POST("/tokens", rc.CheckForAuthentication, rc.CreateProfileToken)
	profileTokensURL.DELETE("/tokens/:tokenUUID", rc.CheckForAuthentication, rc.DeleteProfileToken)
	synthesizerTokensURL := s.Router.Group("/synthesizers/:synthesizer-uuid")
	synthesizerTokensURL.GET("/tokens", rc.CheckForAuthentication, rc.ListSynthesizerTokens)
	synthesizerTokensURL.GET("/tokens/:tokenUUID", rc.CheckForAuthentication, rc.GetSynthesizerToken)
	synthesizerTokensURL.POST("/tokens", rc.CheckForAuthentication, rc.CreateSynthesizerToken)
	synthesizerTokensURL.DELETE("/tokens/:tokenUUID", rc.CheckForAuthentication, rc.DeleteSynthesizerToken)

	s.Router.Any("/:forward", rc.CheckForAuthentication)
	s.Router.Any("/:forward/*any", rc.CheckForAuthentication)
}

// CheckForAuthentication is responsible for knowing if the user already has a valid credential or not.
// If so, forward 200 OK + UserID Headers.
// If not, begin OIDC Flow.
func (rc RESTController) CheckForAuthentication(c *gin.Context) {
	r, w := c.Request, c.Writer
	// workflow to identify if there is a token present.
	token, authType, err := rc.getCredentials(r)
	// if a token is not found, the OIDC flow will be started.
	if authErrors.IsTokenNotFound(err) {
		rc.RedirectToOIDCProvider(w, r)
		return
	}

	userInfo, err := rc.oidcService.Decode(token)
	// check if the token is expired or signature invalid.
	// if so, the OIDC flow will be started to recreate a token.
	if authErrors.IsTokenExpired(err) || authErrors.IsTokenSignatureInvalid(err) {
		if authType == "HeaderCredentialsHandler" {
			rc.forbidden(w, err)
			c.Abort()
			return
		}
		rc.logger.Warn(err)
		rc.RedirectToOIDCProvider(w, r)
		return
	}
	// if a token was passed but it is not valid, the flow must be stopped.
	if err != nil {
		rc.forbidden(w, fmt.Errorf("an error occurred while decoding token: %v", err))
		return
	}

	// if the token passed is valid, let's get the UserInfo to write in the header.
	rc.logger.Debugf("Valid Token: %s", token)
	rc.logger.Infof("Authorizing request for UserID: %v", userInfo.Email)

	// set UserID Header + 200 OK
	w.Header().Set(rc.configuration.UserIDHeader, userInfo.Email)
	w.WriteHeader(http.StatusOK)
	c.Next()
}

// RedirectToOIDCProvider is the handler responsible for redirecting to the OIDC Provider.
func (rc RESTController) RedirectToOIDCProvider(w http.ResponseWriter, r *http.Request) {
	rc.logger.Info("Starting OIDC flow")
	oidcProviderURL, err := rc.oidcService.GetOIDCProviderURL()
	if err != nil {
		rc.internalServerError(w, err)
		return
	}

	rc.logger.Info("Redirecting to OIDC Provider URL...")
	http.Redirect(w, r, oidcProviderURL, http.StatusFound)
}

// OIDCProviderCallback uses the authentication code returned from the OIDC Provider
// to generate an OAuth Token, validate it and create our own JWT.
func (rc RESTController) OIDCProviderCallback(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), rc.configuration.HTTPRequestTimeout)
	defer cancel()

	// Receive the state and auth code from the OIDC Provider.
	stateProvider := r.URL.Query().Get("state")
	codeProvider := r.URL.Query().Get("code")

	// Creates an OAuth2 token with the auth code returned from the OIDC Provider.
	token, err := rc.oidcService.Claims(ctx, codeProvider)
	if err != nil {
		rc.forbidden(w, err)
		return
	}

	// To improve security, we need to combine the state and nonce created earlier
	// with the callback from the OIDC Provider.
	safe, err := rc.oidcService.IsFlowSecure(stateProvider, token)
	if !safe {
		rc.forbidden(w, err)
		return
	}

	// If the flow is secure, a JWT will be created...
	jwt, err := rc.oidcService.Create(token.CustomClaims, rc.configuration.UserJWTExpires)
	if err != nil {
		rc.forbidden(w, fmt.Errorf("an error occurred while creating a JWT. Error: %v", err))
		return
	}
	// ...set a session cookie.
	rc.setSessionCookie(w, r, rc.configuration.AccessTokenCookie, jwt.AccessToken)

	rc.logger.Infof("Redirecting back to %s", rc.configuration.AuthServiceURL)
	http.Redirect(w, r, rc.configuration.AuthServiceURL, http.StatusFound)
}

// UserInfo shows user info from the OIDC Provider.
func (rc RESTController) UserInfo(w http.ResponseWriter, r *http.Request) {
	// workflow to identify if there is a token present.
	token, authType, err := rc.getCredentials(r)
	// if a token is not found, return Forbidden.
	if authErrors.IsTokenNotFound(err) {
		rc.forbidden(w, err)
		return
	}
	userInfo, err := rc.oidcService.Decode(token)
	if authErrors.IsTokenExpired(err) || authErrors.IsTokenSignatureInvalid(err) {
		if authType == "HeaderCredentialsHandler" {
			rc.forbidden(w, err)
			return
		}
		rc.logger.Warn(err)
		rc.RedirectToOIDCProvider(w, r)
		return
	}
	if err != nil {
		rc.forbidden(w, fmt.Errorf("an error occurred while decoding token: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(userInfo)
}

// Logout is responsible for revoking a token and deleting an authentication cookie.
func (rc RESTController) Logout(w http.ResponseWriter, r *http.Request) {
	// workflow to identify if there is a token present.
	_, authType, err := rc.getCredentials(r)
	// if a token is not found, return Forbidden.
	if authErrors.IsTokenNotFound(err) {
		rc.forbidden(w, err)
		return
	}

	if authType == "HeaderCredentialsHandler" {
		rc.badRequest(w, errors.New("unable to logout without a cookie"))
	}
	rc.deleteSessionCookie(w, rc.configuration.AccessTokenCookie)
	w.WriteHeader(http.StatusOK)
}

// GetProfileToken returns profile data from the Vault.
func (rc RESTController) GetProfileToken(c *gin.Context) {
	uuid := c.Params.ByName("profile-uuid")
	path := fmt.Sprintf("profiles/data/%s", uuid)

	rc.getToken(c, path)
}

// GetSynthesizerToken returns synthesizer data from the Vault.
func (rc RESTController) GetSynthesizerToken(c *gin.Context) {
	uuid := c.Params.ByName("synthesizer-uuid")
	path := fmt.Sprintf("synthesizers/data/%s", uuid)

	rc.getToken(c, path)
}

// ListProfileTokens returns a profile data list from the Vault.
func (rc RESTController) ListProfileTokens(c *gin.Context) {
	uuid := c.Params.ByName("profile-uuid")
	path := fmt.Sprintf("profiles/data/%s", uuid)

	rc.listTokens(c, path)
}

// ListSynthesizerTokens returns a synthesizer data list from the Vault.
func (rc RESTController) ListSynthesizerTokens(c *gin.Context) {
	uuid := c.Params.ByName("synthesizer-uuid")
	path := fmt.Sprintf("synthesizers/data/%s", uuid)

	rc.listTokens(c, path)
}

// CreateProfileToken stores profile data into Vault.
func (rc RESTController) CreateProfileToken(c *gin.Context) {
	uuid := c.Params.ByName("profile-uuid")
	path := fmt.Sprintf("profiles/data/%s", uuid)

	rc.createToken(c, path)
}

// CreateSynthesizerToken stores synthesizer data into Vault.
func (rc RESTController) CreateSynthesizerToken(c *gin.Context) {
	uuid := c.Params.ByName("synthesizer-uuid")
	path := fmt.Sprintf("synthesizers/data/%s", uuid)

	rc.createToken(c, path)
}

// DeleteProfileToken removes a profile data from the Vault.
func (rc RESTController) DeleteProfileToken(c *gin.Context) {
	uuid := c.Params.ByName("profile-uuid")
	path := fmt.Sprintf("profiles/data/%s", uuid)

	rc.deleteToken(c, path)
}

// DeleteSynthesizerToken removes a synthesizer data from the Vault.
func (rc RESTController) DeleteSynthesizerToken(c *gin.Context) {
	uuid := c.Params.ByName("synthesizer-uuid")
	path := fmt.Sprintf("synthesizers/data/%s", uuid)

	rc.deleteToken(c, path)
}

// getToken returns data from the Vault.
func (rc RESTController) getToken(c *gin.Context, path string) {
	tokenID := c.Params.ByName("tokenUUID")
	data, err := rc.provisionTokenService.Get(path, tokenID)
	if err != nil {
		rc.notFound(c.Writer, err)
		return
	}

	json.NewEncoder(c.Writer).Encode(data)
	c.Writer.WriteHeader(http.StatusOK)
}

// listTokens returns a data list from the Vault.
func (rc RESTController) listTokens(c *gin.Context, path string) {
	data, err := rc.provisionTokenService.List(path)
	if err != nil {
		rc.badRequest(c.Writer, err)
		return
	}

	json.NewEncoder(c.Writer).Encode(data)
	c.Writer.WriteHeader(http.StatusOK)
}

// createToken stores data into Vault.
func (rc RESTController) createToken(c *gin.Context, path string) {
	var newProvisionToken models.ProvisionTokenRequest
	if err := c.ShouldBindJSON(&newProvisionToken); err != nil {
		rc.internalServerError(c.Writer, err)
		return
	}

	if err := validator.Validate(newProvisionToken); err != nil {
		rc.badRequest(c.Writer, err)
		return
	}

	data, err := rc.provisionTokenService.Create(path, newProvisionToken)
	if err != nil {
		rc.badRequest(c.Writer, err)
		return
	}

	expirationDays := time.Duration(newProvisionToken.Expiration) * (time.Hour * 24)
	jsonBody, err := rc.oidcService.Create(data, expirationDays)
	if err != nil {
		rc.internalServerError(c.Writer, err)
		return
	}

	json.NewEncoder(c.Writer).Encode(jsonBody)
	c.Writer.WriteHeader(http.StatusCreated)
}

// deleteToken removes a data from the Vault.
func (rc RESTController) deleteToken(c *gin.Context, path string) {
	tokenToBeDeleted := c.Params.ByName("tokenUUID")
	if tokenToBeDeleted == "" {
		rc.notFound(c.Writer, errors.New("no token was provided in the query string"))
		return
	}

	err := rc.provisionTokenService.Delete(path, tokenToBeDeleted)
	if err != nil {
		rc.badRequest(c.Writer, err)
	}

	c.Writer.WriteHeader(http.StatusOK)
}

// getCredentials is responsible for simply getting credentials.
func (rc RESTController) getCredentials(r *http.Request) (string, string, error) {
	rc.logger.Info("Get request credentials...")
	for _, auth := range rc.credentials {
		token, err := auth.Extract(r)
		if authErrors.IsTokenNotFound(err) {
			continue
		}
		rc.logger.Debug(token)
		// credentials sent.
		return token, reflect.TypeOf(auth).Elem().Name(), nil
	}
	// back to start OIDC flow.
	return "", "", authErrors.ErrorTokenNotFound
}

func (rc RESTController) setSessionCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   rc.configuration.CookieMaxAge,
		Path:     rc.configuration.AuthServiceURL,
		Secure:   r.TLS != nil,
		HttpOnly: false,
	}
	http.SetCookie(w, c)
}

func (rc RESTController) deleteSessionCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, MaxAge: -1, Path: rc.configuration.AuthServiceURL})
}

func (rc RESTController) errorResponse(w http.ResponseWriter, code int, err error) {
	rc.logger.Error(err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	jsonBody := models.ErrorResponse{
		Message:   err.Error(),
		Timestamp: time.Now(),
	}
	json.NewEncoder(w).Encode(jsonBody)
}

func (rc RESTController) forbidden(w http.ResponseWriter, err error) {
	rc.errorResponse(w, http.StatusForbidden, err)
}

func (rc RESTController) internalServerError(w http.ResponseWriter, err error) {
	rc.errorResponse(w, http.StatusInternalServerError, err)
}

func (rc RESTController) badRequest(w http.ResponseWriter, err error) {
	rc.errorResponse(w, http.StatusBadRequest, err)
}

func (rc RESTController) notFound(w http.ResponseWriter, err error) {
	rc.errorResponse(w, http.StatusNotFound, err)
}

// skipURLsMiddleware is a middleware that skips all requests configured in SKIP_URL.
func (rc RESTController) skipURLsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		for _, skipURL := range rc.configuration.SkipURLs {
			if strings.HasPrefix(c.Request.URL.Path, skipURL) {
				rc.logger.Infof("URL %s was skipped. Accepted without authorization.", c.Request.URL.Path)
				c.Abort()
				return
			}
		}
		c.Next()
	}
}
