package controllers

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/coreos/go-oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"

	"github.com/ydataai/authentication-service/internal/clients"
	"github.com/ydataai/authentication-service/internal/services"
	"github.com/ydataai/go-core/pkg/common/logging"
	"github.com/ydataai/go-core/pkg/common/server"
)

// RESTController defines rest controller
type RESTController struct {
	restService   *services.RESTService
	configuration RESTControllerConfiguration
	oidcClient    *clients.OIDCClient
	logger        logging.Logger
}

// NewRESTController initializes rest controller
func NewRESTController(restService *services.RESTService,
	configuration RESTControllerConfiguration,
	oidcClient *clients.OIDCClient,
	logger logging.Logger) RESTController {
	return RESTController{
		restService:   restService,
		configuration: configuration,
		oidcClient:    oidcClient,
		logger:        logger,
	}
}

// Boot ...
func (rc RESTController) Boot(s *server.Server) {
	s.Router.GET("/healthz", rc.healthCheck())

	s.Router.GET(rc.configuration.AuthServiceURL, gin.WrapF(rc.RedirectAuthEndpoint))
	s.Router.GET(rc.configuration.OIDCCallbackURL, gin.WrapF(rc.Callback))
	// s.Router.POST(rc.configuration.LogoutURL, gin.WrapF(rc.Logout))
}

func (rc RESTController) healthCheck() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Status(http.StatusNoContent)
	}
}

// RedirectAuthEndpoint is the handler responsible for redirecting to the auth endpoint.
func (rc RESTController) RedirectAuthEndpoint(w http.ResponseWriter, r *http.Request) {
	state, err := rc.restService.RandomString(16)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		rc.logger.Errorf("Internal Error %v", http.StatusInternalServerError)
		return
	}
	nonce, err := rc.restService.RandomString(16)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		rc.logger.Errorf("Internal Error %v", http.StatusInternalServerError)
		return
	}
	rc.restService.SetSessionCookie(w, r, "state", state, rc.configuration.SessionMaxAge)
	rc.restService.SetSessionCookie(w, r, "nonce", nonce, rc.configuration.SessionMaxAge)

	rc.logger.Info("Redirect to Authorization Endpoint")
	http.Redirect(w, r, rc.oidcClient.OAuth2Config.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
}

// Callback is the handler responsible for authenticating the user's session.
func (rc RESTController) Callback(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), rc.configuration.HTTPRequestTimeout)
	defer cancel()

	// TODO: should we do the status check and nonce?
	// if so, we should save somewhere to compare it with the request.

	oauth2Token, err := rc.oidcClient.OAuth2Config.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}
	idToken, err := rc.oidcClient.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp := struct {
		OAuth2Token   *oauth2.Token
		IDTokenClaims *json.RawMessage // ID Token payload is just JSON.
	}{oauth2Token, new(json.RawMessage)}

	if err := idToken.Claims(&resp.IDTokenClaims); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data, err := json.MarshalIndent(resp, "", "    ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rc.logger.Info("Login validated with ID token")
	w.Write(data)
}

// Logout is the handler responsible for revoking the user's session.
// func (rc RESTController) Logout(w http.ResponseWriter, r *http.Request) {
//
// }
