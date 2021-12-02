package services

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/ydataai/authentication-service/internal/clients"
	"github.com/ydataai/go-core/pkg/common/logging"
	"golang.org/x/oauth2"
)

// Tokens defines the token struct
type Tokens struct {
	OAuth2Token   *oauth2.Token
	IDTokenClaims *json.RawMessage // ID Token payload is just JSON
}

// OIDCService defines the oidc server struct
type OIDCService struct {
	Tokens
	logger logging.Logger
}

// NewOIDCService creates tokens
func NewOIDCService(ctx context.Context, logger logging.Logger, oidcClient *clients.OIDCClient,
	w http.ResponseWriter, r *http.Request) *OIDCService {

	// TODO: should we do the status check and nonce?
	// if so, we should save somewhere to compare it with the request.

	oauth2Token, err := oidcClient.OAuth2Config.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return nil
	}
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return nil
	}
	idToken, err := oidcClient.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return nil
	}

	idTokenClaims := new(json.RawMessage)
	if err := idToken.Claims(&idTokenClaims); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil
	}

	return &OIDCService{
		Tokens: Tokens{
			OAuth2Token:   oauth2Token,
			IDTokenClaims: idTokenClaims,
		},
		logger: logger,
	}
}
