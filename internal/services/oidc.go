package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/oauth2"

	"github.com/ydataai/authentication-service/internal/clients"
	"github.com/ydataai/authentication-service/internal/configurations"
	authErrors "github.com/ydataai/authentication-service/internal/errors"
	"github.com/ydataai/authentication-service/internal/models"
	"github.com/ydataai/authentication-service/internal/storages"
	"github.com/ydataai/go-core/pkg/common/logging"
)

// OIDCService defines the OIDC Service struct.
type OIDCService struct {
	configuration  configurations.OIDCServiceConfiguration
	client         clients.OIDCClient
	sessionStorage *storages.SessionStorage
	logger         logging.Logger
}

// OIDCServiceInterface defines a interface for OIDC Service.
type OIDCServiceInterface interface {
	GetOIDCProviderURL() (string, error)
	Claims(ctx context.Context, code string) (models.Tokens, error)
	IsFlowSecure(state string, token models.Tokens) (bool, error)

	Create(cc *models.CustomClaims) (models.CustomClaims, error)
	Decode(tokenString string) (map[string]interface{}, error)
	GetUserInfo(info map[string]interface{}) models.TokenInfo
}

// NewOIDCService creates a new OIDC Service struct.
func NewOIDCService(logger logging.Logger,
	configuration configurations.OIDCServiceConfiguration,
	client clients.OIDCClient,
	sessionStorage *storages.SessionStorage) OIDCServiceInterface {
	return &OIDCService{
		configuration:  configuration,
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

// Claims creates claims tokens based on the auth code returned from the OIDC provider.
func (osvc *OIDCService) Claims(ctx context.Context, code string) (models.Tokens, error) {
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

// Create a new JWT token based on Custom Claims models.
func (osvc *OIDCService) Create(cc *models.CustomClaims) (models.CustomClaims, error) {
	var err error

	customClaims := models.CustomClaims{
		Name:    cc.Name,
		Email:   cc.Email,
		Profile: cc.Profile,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(osvc.configuration.UserJWTExpires))),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, customClaims)

	// Sign and get the complete encoded token as a string using the secret.
	customClaims.AccessToken, err = token.SignedString(osvc.configuration.HMACSecret)

	return customClaims, err
}

// Decode validates the token and returns the claims.
func (osvc *OIDCService) Decode(tokenString string) (map[string]interface{}, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return osvc.configuration.HMACSecret, nil
	})

	if token == nil {
		return nil, errors.New("an unexpected error occurred while validating the JWT token")
	}

	if token.Valid {
		return token.Claims.(jwt.MapClaims), nil
	}

	if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			return nil, errors.New("that's not even a token")

		} else if ve.Errors&jwt.ValidationErrorExpired != 0 {
			return nil, authErrors.ErrTokenExpired
		} else if ve.Errors&jwt.ValidationErrorNotValidYet != 0 {
			return nil, authErrors.ErrTokenInactiveYet
		} else {
			return nil, errors.New("couldn't handle this token: " + err.Error())
		}
	}

	return nil, errors.New("couldn't handle this token: " + err.Error())
}

// GetUserInfo returns the token with user information.
func (osvc *OIDCService) GetUserInfo(info map[string]interface{}) models.TokenInfo {
	return models.TokenInfo{
		UID:       osvc.configuration.UserIDPrefix + info[osvc.configuration.UserIDClaim].(string),
		Name:      info[osvc.configuration.UserNameClaim].(string),
		ExpiresAt: time.Unix(int64(info["exp"].(float64)), 0),
	}
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
