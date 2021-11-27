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
	// router.HandleFunc(r.serverConfig.LogoutURL.String(), s.Logout).Methods(http.MethodPost)
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
	rc.restService.SetSessionCookie(w, r, "state", state)
	rc.restService.SetSessionCookie(w, r, "nonce", nonce)

	rc.logger.Info("Redirect to Authorization Endpoint")
	http.Redirect(w, r, rc.oidcClient.OAuth2Config.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
}

// Callback is the handler responsible for authenticating the user's session.
func (rc RESTController) Callback(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	state, err := r.Cookie("state")
	if err != nil {
		http.Error(w, "state not found", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("state") != state.Value {
		http.Error(w, "state did not match", http.StatusBadRequest)
		return
	}

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

	nonce, err := r.Cookie("nonce")
	if err != nil {
		http.Error(w, "nonce not found", http.StatusBadRequest)
		return
	}
	if idToken.Nonce != nonce.Value {
		http.Error(w, "nonce did not match", http.StatusBadRequest)
		return
	}

	oauth2Token.AccessToken = "*REDACTED*"

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
	w.Write(data)

	rc.logger.Infof("Login validated with ID token, redirecting to %v.", rc.configuration.AfterLoginURL)
	http.Redirect(w, r, rc.configuration.AfterLoginURL, http.StatusFound)
}

// Logout is the handler responsible for revoking the user's session.
// func (rc RESTController) Logout(w http.ResponseWriter, r *http.Request) {
//
// }
