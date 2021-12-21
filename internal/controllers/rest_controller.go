package controllers

import (
	"context"
	"encoding/json"
	"net/http"
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
	oidcService   services.OIDCServiceInterface
	credentials   []handlers.CredentialsHandler
	logger        logging.Logger
}

// NewRESTController initializes rest controller.
func NewRESTController(
	logger logging.Logger,
	configuration configurations.RESTControllerConfiguration,
	oidcService services.OIDCServiceInterface,
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
	s.Router.GET(rc.configuration.AuthServiceURL, gin.WrapF(rc.CheckForAuthentication))
	s.Router.GET(rc.configuration.OIDCCallbackURL, gin.WrapF(rc.OIDCProviderCallback))
	s.Router.GET(rc.configuration.LogoutURL, gin.WrapF(rc.Logout))
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

	w.Header().Set("Content-Type", "application/json")

	tokenInfo, err := rc.oidcService.Decode(token)
	// check if the token is expired.
	// if so, the OIDC flow will be started to recreate a token.
	if authErrors.IsTokenExpired(err) {
		rc.logger.Warn(err)
		rc.RedirectToOIDCProvider(w, r)
		return
	}
	// if a token was passed but it is not valid, the flow must be stopped.
	if err != nil {
		rc.logger.Errorf("an error occurred while decoding token: %v", err)
		rc.forbiddenResponse(w, err)
		return
	}

	// if the token passed is valid, let's get the TokenInfo to write in the header.
	rc.logger.Debugf("Valid Token: %s", token)
	rc.logger.Infof("Authorizing request for UserID: %v", tokenInfo.UID)

	// set UserID Header + 200 OK
	w.Header().Set(rc.configuration.UserIDHeader, tokenInfo.UID)
	w.WriteHeader(http.StatusOK)
}

// RedirectToOIDCProvider is the handler responsible for redirecting to the OIDC Provider.
func (rc RESTController) RedirectToOIDCProvider(w http.ResponseWriter, r *http.Request) {
	rc.logger.Info("Starting OIDC flow")
	oidcProviderURL, err := rc.oidcService.GetOIDCProviderURL()
	if err != nil {
		rc.logger.Error(err.Error())
		rc.forbiddenResponse(w, err)
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
		rc.logger.Error(err)
		rc.forbiddenResponse(w, err)
		return
	}

	// To improve security, we need to combine the state and nonce created earlier
	// with the callback from the OIDC Provider.
	safe, err := rc.oidcService.IsFlowSecure(stateProvider, token)
	if !safe {
		rc.logger.Error(err)
		rc.forbiddenResponse(w, err)
		return
	}

	// If the flow is secure, a JWT will be created...
	jwt, err := rc.oidcService.Create(&token.CustomClaims)
	if err != nil {
		rc.logger.Errorf("an error occurred while creating a JWT. Error: %v", err)
		rc.forbiddenResponse(w, err)
		return
	}
	// ...set a session cookie.
	rc.setSessionCookie(w, r, "access_token", jwt.AccessToken)

	rc.logger.Infof("Redirecting back to %s", rc.configuration.AuthServiceURL)
	http.Redirect(w, r, rc.configuration.AuthServiceURL, http.StatusFound)
}

// Logout is responsible for revoking a token and deleting an authentication cookie.
func (rc RESTController) Logout(w http.ResponseWriter, r *http.Request) {
	// TODO: revoke token
	rc.deleteSessionCookie(w, "access_token")
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
	return "", authErrors.ErrTokenNotFound
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

func (rc RESTController) forbiddenResponse(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusForbidden)
	jsonBody := models.ErrorResponse{
		Message:   err.Error(),
		Timestamp: time.Now(),
	}
	json.NewEncoder(w).Encode(jsonBody)
}
