package clients

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/ydataai/authentication-service/internal/configurations"
	"github.com/ydataai/authentication-service/internal/models"
	"github.com/ydataai/go-core/pkg/common/logging"
	"golang.org/x/oauth2"
)

// OAuth2OIDCClient defines a struct for OAuth2 OIDC Client.
type OAuth2OIDCClient struct {
	configuration configurations.OIDCClientConfiguration
	oauth2config  *oauth2.Config
	provider      *oidc.Provider
	logger        logging.Logger
}

// OIDCClient defines a interface for OIDC Client.
type OIDCClient interface {
	StartSetup()
	AuthCodeURL(state, nonce string) string
	Exchange(ctx context.Context, code string) (models.OAuth2Token, error)
	Decode(ctx context.Context, rawIDToken string) (models.Tokens, error)
}

// NewOAuth2OIDCClient defines a new values for the server.
func NewOAuth2OIDCClient(logger logging.Logger,
	config configurations.OIDCClientConfiguration) OIDCClient {

	return &OAuth2OIDCClient{
		configuration: config,
		logger:        logger,
	}
}

// StartSetup initializes setup for OIDC Provider.
func (oc *OAuth2OIDCClient) StartSetup() {
	var err error
	ctx := context.Background()

	for {
		oc.provider, err = oidc.NewProvider(ctx, oc.configuration.OIDProviderURL)
		if err == nil {
			oc.logger.Info("✔️ Connected to OIDC Provider")
			break
		}
		oc.logger.Errorf("✖️ OIDC Provider setup failed. Error: %v", err)
		time.Sleep(time.Second * 5)
	}

	// Configure an OpenID Connect aware OAuth2 client.
	oc.oauth2config = &oauth2.Config{
		ClientID:     oc.configuration.ClientID,
		ClientSecret: oc.configuration.ClientSecret,
		Endpoint:     oc.provider.Endpoint(), // Discovery returns the OAuth2 endpoints.
		RedirectURL:  oc.configuration.OIDCRedirectURL,
		Scopes:       oc.configuration.OIDCScopes,
	}
}

// AuthCodeURL is an oidc lib proxy that returns a URL to OAuth 2.0 provider's consent page that asks
//  for permissions for the required scopes explicitly.
// for more information, see: https://pkg.go.dev/golang.org/x/oauth2#Config.AuthCodeURL
func (oc *OAuth2OIDCClient) AuthCodeURL(state, nonce string) string {
	return oc.oauth2config.AuthCodeURL(state, oidc.Nonce(nonce))
}

// Exchange is an oidc lib proxy that converts an authorization code into a token.
// for more information, see: https://pkg.go.dev/golang.org/x/oauth2#Config.Exchange
func (oc OAuth2OIDCClient) Exchange(ctx context.Context, code string) (models.OAuth2Token, error) {
	exchange, err := oc.oauth2config.Exchange(ctx, code)
	if err != nil {
		return models.OAuth2Token{}, err
	}

	rawIDToken, ok := exchange.Extra("id_token").(string)
	if !ok {
		return models.OAuth2Token{}, errors.New("no id_token field in oauth2 token")
	}

	return models.OAuth2Token{
		AccessToken:  exchange.AccessToken,
		TokenType:    exchange.TokenType,
		RefreshToken: exchange.RefreshToken,
		Expiry:       exchange.Expiry,
		RawIDToken:   rawIDToken,
	}, nil
}

// Decode is an improvement from Verify that parses a raw ID Token, verifies it's been signed
// by the provider, performs any additional checks depending on the Config, and returns the payload.
// for more information, see: https://pkg.go.dev/github.com/coreos/go-oidc/v3/oidc#IDTokenVerifier.Verify
func (oc OAuth2OIDCClient) Decode(ctx context.Context, rawIDToken string) (models.Tokens, error) {
	verifier := oc.provider.Verifier(&oidc.Config{ClientID: oc.configuration.ClientID})
	verify, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return models.Tokens{}, err
	}

	idTokenClaims := new(json.RawMessage)
	if err := verify.Claims(&idTokenClaims); err != nil {
		return models.Tokens{}, fmt.Errorf("an error occurred while validating ID Token. Error: %v", err)
	}

	cc := models.CustomClaims{}
	if err := verify.Claims(&cc); err != nil {
		return models.Tokens{}, fmt.Errorf("an unexpected error has occurred. Error: %v", err)
	}

	return models.Tokens{
		IDTokenClaims: idTokenClaims,
		CustomClaims:  cc,
	}, nil
}
