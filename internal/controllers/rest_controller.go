package controllers

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/ydataai/authentication-service/internal/authentications"
	"github.com/ydataai/authentication-service/internal/configurations"
	"github.com/ydataai/authentication-service/internal/models"
	"github.com/ydataai/authentication-service/internal/services"
	"github.com/ydataai/go-core/pkg/common/logging"
	"github.com/ydataai/go-core/pkg/common/server"
)

// RESTController defines rest controller.
type RESTController struct {
	configuration   configurations.RESTControllerConfiguration
	oidcService     services.OIDCService
	authentications []authentications.CredentialsHandler
	logger          logging.Logger
}

// NewRESTController initializes rest controller.
func NewRESTController(
	logger logging.Logger,
	configuration configurations.RESTControllerConfiguration,
	oidcService services.OIDCService,
	authentications []authentications.CredentialsHandler,
) RESTController {
	return RESTController{
		configuration:   configuration,
		oidcService:     oidcService,
		authentications: authentications,
		logger:          logger,
	}
}

// Boot initialize creating some routes.
func (rc RESTController) Boot(s *server.Server) {
	s.Router.GET(rc.configuration.AuthServiceURL, gin.WrapF(rc.AuthenticationSession))
	s.Router.GET(rc.configuration.OIDCCallbackURL, gin.WrapF(rc.OIDCProviderCallback))
	s.Router.GET(rc.configuration.LogoutURL, gin.WrapF(rc.Logout))
}

// AuthenticationSession is responsible for knowing if the user is already authenticated or not.
// If so, forward 200 OK + UserID Headers.
// If not logged in, begin OIDC Flow.
func (rc RESTController) AuthenticationSession(w http.ResponseWriter, r *http.Request) {
	// workflow to identify if there is a token present.
	claims, err := rc.authenticationWorkflow(r)
	// if a token is not identified, the OIDC flow will be started.
	if err == nil && claims == nil {
		rc.RedirectToOIDCProvider(w, r)
		return
	}

	w.Header().Set("Content-Type", "application/json")

	// if a token was passed but it is not valid, display the error and stop the flow.
	if err != nil && claims != nil {
		w.WriteHeader(http.StatusBadRequest)
		jsonBody := models.JSONResponse{
			Error:            http.StatusText(http.StatusBadRequest),
			ErrorDescription: err.Error(),
		}
		json.NewEncoder(w).Encode(jsonBody)
		return
	}

	// we've a valid token, let's get the UserInfo to write in the header.
	userInfo := rc.oidcService.GetUserInfo(claims)
	rc.logger.Infof("Authorizing request for UserID: %v", userInfo.ID)

	for k, v := range rc.userInfoToHeaders(userInfo) {
		w.Header().Set(k, v)
	}

	w.WriteHeader(http.StatusOK)
	jsonBody := models.JSONResponse{
		AccessToken: userInfo.AccessToken,
	}
	json.NewEncoder(w).Encode(jsonBody)
}

// RedirectToOIDCProvider is the handler responsible for redirecting to the OIDC Provider.
func (rc RESTController) RedirectToOIDCProvider(w http.ResponseWriter, r *http.Request) {
	rc.logger.Info("Starting OIDC flow")
	oidcProviderURL, err := rc.oidcService.GetOIDCProviderURL()
	if err != nil {
		rc.logger.Errorf(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
	token, err := rc.oidcService.ClaimsToken(ctx, codeProvider)
	if err != nil {
		rc.logger.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// To improve security, we need to combine the state and nonce created earlier
	// with the callback from the OIDC Provider.
	safe, err := rc.oidcService.IsFlowSecure(stateProvider, token)
	if !safe {
		rc.logger.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// If the flow is secure, a JWT will be created...
	jwt, err := rc.oidcService.CreateJWT(&token.CustomClaims)
	if err != nil {
		rc.logger.Error("an error occurred while creating a JWT. Error: " + err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
	rc.deleteCookie(w, "access_token")
}

// authenticationWorkflow is responsible for running the authentication workflow.
func (rc RESTController) authenticationWorkflow(r *http.Request) (map[string]interface{}, error) {
	rc.logger.Info("Authenticating request...")
	for i, auth := range rc.authentications {
		claims, err := auth.Extract(r)
		if err != nil {
			if claims != nil {
				return claims, err
			}
			rc.logger.Debugf("error authenticating request using authenticator %d: %v", i, err)
			continue
		}
		// there's no error but somehow the claim returned nil.
		if claims == nil {
			continue
		}
		// successful authentication.
		return claims, nil
	}
	// back to start OIDC flow
	return nil, nil
}

func (rc RESTController) userInfoToHeaders(info models.UserInfo) map[string]string {
	return map[string]string{
		rc.configuration.UserIDHeader: rc.configuration.UserIDPrefix + info.ID,
	}
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

func (rc RESTController) deleteCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, MaxAge: -1, Path: rc.configuration.AuthServiceURL})
}
