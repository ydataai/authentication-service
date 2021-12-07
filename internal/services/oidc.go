package services

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/ydataai/authentication-service/internal/clients"
	"github.com/ydataai/authentication-service/internal/models"
	"github.com/ydataai/authentication-service/internal/storages"
	"github.com/ydataai/go-core/pkg/common/logging"
	"golang.org/x/oauth2"
)

// OIDCService defines the oidc server struct.
type OIDCService struct {
	client         clients.OIDCClient
	sessionStorage *storages.SessionStorage
	logger         logging.Logger
}

// NewOIDCService creates a new OIDC Service.
func NewOIDCService(logger logging.Logger,
	client clients.OIDCClient,
	sessionStorage *storages.SessionStorage) *OIDCService {
	return &OIDCService{
		client:         client,
		sessionStorage: sessionStorage,
		logger:         logger,
	}
}

// GetOIDCProviderURL gets OIDC provider URL from the OAuth2 configuration.
func (osvc *OIDCService) GetOIDCProviderURL() (string, error) {
	// Creates a temporary session with state and nonce to validate
	// when there is callback from the OIDC Provider.
	session, err := models.CreateSession()
	if err != nil {
		return "", err
	}

	osvc.sessionStorage.StoreSession(session)

	return osvc.client.OAuth2Config.AuthCodeURL(
		session.State,
		oidc.Nonce(session.Nonce),
	), nil
}

// ClaimsToken creates claims token.
func (osvc *OIDCService) ClaimsToken(ctx context.Context, code string) (models.Tokens, error) {
	if code == "" {
		return models.Tokens{}, errors.New("unable to authenticate without code returned from OIDC Provider")
	}

	oauth2Token, err := osvc.client.OAuth2Config.Exchange(ctx, code)
	if err != nil {
		return models.Tokens{}, errors.New("failed to exchange token. Error: " + err.Error())
	}
	idToken, err := osvc.validateIDToken(ctx, oauth2Token)
	if err != nil {
		return models.Tokens{}, err
	}

	idTokenClaims := new(json.RawMessage)
	if err := idToken.Claims(&idTokenClaims); err != nil {
		return models.Tokens{}, errors.New("An error occurred while validating ID Token. Error: " + err.Error())
	}

	cc := models.CustomClaims{}
	if err := idToken.Claims(&cc); err != nil {
		return models.Tokens{}, errors.New("An unexpected error has occurred. Error: " + err.Error())
	}

	return models.Tokens{
		OAuth2Token:   oauth2Token,
		IDTokenClaims: idTokenClaims,
		CustomClaims:  cc,
	}, nil
}

// IsFlowSecure ensures the flow is secure and then, returns a JWT token.
func (osvc *OIDCService) IsFlowSecure(state string, token models.Tokens) (bool, error) {
	if state == "" {
		return false, errors.New("unable to follow a secure flow without the state returned from the OIDC Provider")
	}

	session, err := osvc.sessionStorage.GetSession(state)
	if err != nil {
		return false, err
	}

	nonceToken, err := osvc.getValueFromToken("nonce", token)
	if err != nil {
		return false, err
	}
	if !session.MatchNonce(nonceToken.(string)) {
		return false, errors.New("nonce did not match")
	}

	return true, nil
}

// CreateJWT creates a new token and the claims you would like it to contain.
func (osvc *OIDCService) CreateJWT(cc *models.CustomClaims) (models.CustomClaims, error) {
	// For HMAC signing method, the key can be any []byte
	hmacRandSecret, err := randomByte(1990)
	if err != nil {
		osvc.logger.Errorf("An error occurred while generating HMAC. Error: %v", err)
		return models.CustomClaims{}, err
	}

	customClaims := models.CustomClaims{
		Name:    cc.Name,
		Email:   cc.Email,
		Profile: cc.Profile,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(osvc.client.Configuration.JWTExpires))),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, customClaims)

	// Sign and get the complete encoded token as a string using the secret.
	customClaims.AccessToken, err = token.SignedString(hmacRandSecret)

	return customClaims, err
}

// getValueFromToken gets the nonce from the ID Token.
func (osvc *OIDCService) getValueFromToken(value string, t models.Tokens) (interface{}, error) {
	var m map[string]interface{}
	if err := json.Unmarshal(*t.IDTokenClaims, &m); err != nil {
		return "", errors.New("an unexpected error occurred when getting the nonce from ID Token")
	}

	if key, ok := m[value]; ok {
		return key, nil
	}
	return "", nil
}

// validateIDToken validates the ID token.
func (osvc *OIDCService) validateIDToken(ctx context.Context, oauth2Token *oauth2.Token) (oidc.IDToken, error) {
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		return oidc.IDToken{}, errors.New("no id_token field in oauth2 token")
	}
	idToken, err := osvc.client.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return oidc.IDToken{}, errors.New("failed to verify ID Token. Error: " + err.Error())
	}
	osvc.logger.Info("[✔️] Login validated with ID token")

	return *idToken, nil
}

// randomByte creates a random byte value.
func randomByte(nByte int) ([]byte, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}
