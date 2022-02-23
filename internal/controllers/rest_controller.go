package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

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
	configuration configurations.RESTControllerConfiguration
	oidcService   services.OIDCService
	credentials   []handlers.CredentialsHandler
	logger        logging.Logger
}

// NewRESTController initializes rest controller.
func NewRESTController(
	logger logging.Logger,
	configuration configurations.RESTControllerConfiguration,
	oidcService services.OIDCService,
	credentials []handlers.CredentialsHandler,
) RESTController {
	return RESTController{
		configuration: configuration,
		oidcService:   oidcService,
		credentials:   credentials,
		logger:        logger,
	}
}

// Boot initializes creating some routes.
func (rc RESTController) Boot(s *server.Server) {
	s.Router.Use(rc.skipURLsMiddleware())

	s.Router.GET(rc.configuration.AuthServiceURL, gin.WrapF(rc.CheckForAuthentication))
	s.Router.GET(rc.configuration.OIDCCallbackURL, gin.WrapF(rc.OIDCProviderCallback))
	s.Router.GET(rc.configuration.UserInfoURL, gin.WrapF(rc.UserInfo))
	s.Router.POST(rc.configuration.LogoutURL, gin.WrapF(rc.Logout))

	s.Router.Any("/:forward", gin.WrapF(rc.CheckForAuthentication))
	s.Router.Any("/:forward/*any", gin.WrapF(rc.CheckForAuthentication))
}

// CheckForAuthentication is responsible for knowing if the user already has a valid credential or not.
// If so, forward 200 OK + UserID Headers.
// If not, begin OIDC Flow.
func (rc RESTController) CheckForAuthentication(w http.ResponseWriter, r *http.Request) {
	// workflow to identify if there is a token present.
	token, err := rc.getCredentials(r)
	// if a token is not found, the OIDC flow will be started.
	if authErrors.IsTokenNotFound(err) {
		rc.RedirectToOIDCProvider(w, r)
		return
	}

	userInfo, err := rc.oidcService.Decode(token)
	// check if the token is expired or signature invalid.
	// if so, the OIDC flow will be started to recreate a token.
	if authErrors.IsTokenExpired(err) || authErrors.IsTokenSignatureInvalid(err) {
		rc.logger.Warn(err)
		rc.RedirectToOIDCProvider(w, r)
		return
	}
	// if a token was passed but it is not valid, the flow must be stopped.
	if err != nil {
		rc.forbiddenResponse(w, fmt.Errorf("an error occurred while decoding token: %v", err))
		return
	}

	// if the token passed is valid, let's get the UserInfo to write in the header.
	rc.logger.Debugf("Valid Token: %s", token)
	rc.logger.Infof("Authorizing request for UserID: %v", userInfo.Email)

	// set UserID Header + 200 OK
	w.Header().Set(rc.configuration.UserIDHeader, userInfo.Email)
	w.WriteHeader(http.StatusOK)
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
		rc.forbiddenResponse(w, err)
		return
	}

	// To improve security, we need to combine the state and nonce created earlier
	// with the callback from the OIDC Provider.
	safe, err := rc.oidcService.IsFlowSecure(stateProvider, token)
	if !safe {
		rc.forbiddenResponse(w, err)
		return
	}

	// If the flow is secure, a JWT will be created...
	jwt, err := rc.oidcService.Create(token.CustomClaims)
	if err != nil {
		rc.forbiddenResponse(w, fmt.Errorf("an error occurred while creating a JWT. Error: %v", err))
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
	token, err := rc.getCredentials(r)
	// if a token is not found, return Forbidden.
	if authErrors.IsTokenNotFound(err) {
		rc.forbiddenResponse(w, err)
		return
	}
	userInfo, err := rc.oidcService.Decode(token)
	if err != nil {
		rc.forbiddenResponse(w, fmt.Errorf("an error occurred while decoding token: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(userInfo)
}

// Logout is responsible for revoking a token and deleting an authentication cookie.
func (rc RESTController) Logout(w http.ResponseWriter, r *http.Request) {
	// workflow to identify if there is a token present.
	_, err := rc.getCredentials(r)
	// if a token is not found, return Forbidden.
	if authErrors.IsTokenNotFound(err) {
		rc.forbiddenResponse(w, err)
		return
	}

	rc.deleteSessionCookie(w, rc.configuration.AccessTokenCookie)
	w.WriteHeader(http.StatusOK)
}

// getCredentials is responsible for simply getting credentials.
func (rc RESTController) getCredentials(r *http.Request) (string, error) {
	rc.logger.Info("Get request credentials...")
	for _, auth := range rc.credentials {
		token, err := auth.Extract(r)
		if authErrors.IsTokenNotFound(err) {
			continue
		}
		// credentials sent.
		rc.logger.Debug(token)
		return token, nil
	}
	// back to start OIDC flow.
	return "", authErrors.ErrorTokenNotFound
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

func (rc RESTController) forbiddenResponse(w http.ResponseWriter, err error) {
	rc.errorResponse(w, http.StatusForbidden, err)
}

func (rc RESTController) internalServerError(w http.ResponseWriter, err error) {
	rc.errorResponse(w, http.StatusInternalServerError, err)
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
