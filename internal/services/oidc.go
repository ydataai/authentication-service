package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/ydataai/authentication-service/internal/clients"
	"github.com/ydataai/authentication-service/internal/models"
	"github.com/ydataai/go-core/pkg/common/logging"
	"golang.org/x/oauth2"
)

// OIDCService defines the oidc server struct
type OIDCService struct {
	client *clients.OIDCClient
	logger logging.Logger
}

// NewOIDCService creates a new OIDC Service
func NewOIDCService(logger logging.Logger, client *clients.OIDCClient) *OIDCService {
	return &OIDCService{
		client: client,
		logger: logger,
	}
}

// ClaimsToken creates token claims
func (osvc *OIDCService) ClaimsToken(ctx context.Context,
	w http.ResponseWriter, r *http.Request) (*models.Tokens, error) {

	oauth2Token, err := osvc.createOAuth2Token(ctx, w, r)
	if err != nil {
		msg := fmt.Sprintf("Failed to exchange token. Error: %v", err)
		osvc.logger.Error(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return nil, err
	}
	idToken, err := osvc.validateIDToken(ctx, oauth2Token, w, r)
	if err != nil {
		msg := fmt.Sprintf("An error occurred while validating ID Token. Error: %v", err)
		osvc.logger.Error(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return nil, err
	}

	idTokenClaims := new(json.RawMessage)
	if err := idToken.Claims(&idTokenClaims); err != nil {
		msg := fmt.Sprintf("An error occurred while validating ID Token. Error: %v", err)
		osvc.logger.Error(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return nil, err
	}

	userInfo, err := osvc.GetUserInfo(ctx, oauth2Token)
	if err != nil {
		msg := fmt.Sprintf("Failed to get UserInfo. Error: %v", err)
		osvc.logger.Error(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return nil, err
	}

	cc := models.CustomClaims{}
	if err := idToken.Claims(&cc); err != nil {
		msg := fmt.Sprintf("An unexpected error has occurred. Error: %v", err)
		osvc.logger.Error(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return nil, err
	}

	return &models.Tokens{
		OAuth2Token:   oauth2Token,
		IDTokenClaims: idTokenClaims,
		UserInfo:      userInfo,
		CustomClaims:  cc,
	}, nil
}

// createOAuth2Token creates a new OAuth2 token
func (osvc *OIDCService) createOAuth2Token(ctx context.Context,
	w http.ResponseWriter, r *http.Request) (*oauth2.Token, error) {

	oauth2Token, err := osvc.client.OAuth2Config.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		return nil, err
	}

	return oauth2Token, nil
}

// CreateOIDCProviderURL creates OIDC provider URL with some properties
func (osvc *OIDCService) CreateOIDCProviderURL(state, nonce string) string {
	return osvc.client.OAuth2Config.AuthCodeURL(state, oidc.Nonce(nonce))
}

// GetReadyzFunc make sure if oidc provider is ready
func (osvc *OIDCService) GetReadyzFunc() bool {
	return osvc.client.GetReadyzFunc()
}

// GetUserInfo gets User Info from the OAuth2 Token.
func (osvc *OIDCService) GetUserInfo(ctx context.Context, oauth2Token *oauth2.Token) (*oidc.UserInfo, error) {
	userInfo, err := osvc.client.GetProvider().UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token))
	if err != nil {
		return nil, err
	}

	return userInfo, nil
}

// GetValueFromToken gets the nonce from the ID Token.
func (osvc *OIDCService) GetValueFromToken(value string, t *models.Tokens) (interface{}, error) {
	var m map[string]interface{}
	if err := json.Unmarshal(*t.IDTokenClaims, &m); err != nil {
		return "", err
	}

	if key, ok := m[value]; ok {
		return key, nil
	}
	return "", nil
}

// validateIDToken validates the ID token
func (osvc *OIDCService) validateIDToken(ctx context.Context, oauth2Token *oauth2.Token,
	w http.ResponseWriter, r *http.Request) (*oidc.IDToken, error) {

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		err := errors.New("no id_token field in oauth2 token")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return nil, err
	}
	idToken, err := osvc.client.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return nil, err
	}
	osvc.logger.Info("[✔️] Login validated with ID token")

	return idToken, nil
}
