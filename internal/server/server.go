package server

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/coreos/go-oidc"
	"github.com/tevino/abool"
	"golang.org/x/oauth2"

	"github.com/ydataai/authentication-service/internal/clients"
	"github.com/ydataai/go-core/pkg/common/logging"
)

// Server defines a struct that can be used
type Server struct {
	configuration ServerConfiguration
	oidcClient    clients.OIDCClient
	logger        logging.Logger
}

// NewServer defines a new values for the server
func NewServer(logger logging.Logger, c ServerConfiguration,
	oc clients.OIDCClient) *Server {

	return &Server{
		configuration: c,
		oidcClient:    oc,
		logger:        logger,
	}
}

func (s *Server) RedirectAuthEndpoint(w http.ResponseWriter, r *http.Request) {
	state, err := randString(16)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		s.logger.Errorf("Internal Error %v", http.StatusInternalServerError)
		return
	}
	nonce, err := randString(16)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		s.logger.Errorf("Internal Error %v", http.StatusInternalServerError)
		return
	}
	setCallbackCookie(w, r, "state", state)
	setCallbackCookie(w, r, "nonce", nonce)

	s.logger.Info("Redirect to Authorization Endpoint")
	http.Redirect(w, r, s.oidcClient.OAuth2Config.AuthCodeURL(state, oidc.Nonce(nonce)), http.StatusFound)
}

// Callback is the handler responsible for authenticating the user's session.
func (s *Server) Callback(w http.ResponseWriter, r *http.Request) {
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

	oauth2Token, err := s.oidcClient.OAuth2Config.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return
	}
	idToken, err := s.oidcClient.Verifier.Verify(ctx, rawIDToken)
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
	s.logger.Infof("Login validated with ID token, redirecting to %v.", s.configuration.AfterLoginURL)
	http.Redirect(w, r, s.configuration.AfterLoginURL.String(), http.StatusFound)
}

// Logout is the handler responsible for revoking the user's session.
// func (s *Server) Logout(w http.ResponseWriter, r *http.Request) {
//
// }

// Readiness is the handler that checks if the authservice is ready for serving requests
// Currently, it checks if the provider is nil, meaning that the setup hasn't finished yet.
func Readiness(isReady *abool.AtomicBool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := http.StatusOK
		if !isReady.IsSet() {
			code = http.StatusServiceUnavailable
		}
		w.WriteHeader(code)
	}
}
