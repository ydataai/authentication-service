package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"

	"github.com/ydataai/authentication-service/internal/clients"
	"github.com/ydataai/authentication-service/internal/configurations"
	authErrors "github.com/ydataai/authentication-service/internal/errors"
	"github.com/ydataai/authentication-service/internal/models"
	"github.com/ydataai/authentication-service/internal/storages"
	"github.com/ydataai/go-core/pkg/common/logging"
)

// OAuth2OIDCService defines the OAuth2 OIDC Service struct.
type OAuth2OIDCService struct {
	configuration  configurations.OIDCServiceConfiguration
	client         clients.OIDCClient
	sessionStorage *storages.SessionStorage
	logger         logging.Logger
}

// OIDCService defines a interface for OIDC Service.
type OIDCService interface {
	GetOIDCProviderURL() (string, error)
	Claims(ctx context.Context, code string) (models.Tokens, error)
	IsFlowSecure(state string, token models.Tokens) (bool, error)

	Create(cc models.CustomClaims) (models.CustomClaims, error)
	Decode(tokenString string) (models.UserInfo, error)
}

// NewOAuth2OIDCService creates a new OAuth2 OIDC Service struct.
func NewOAuth2OIDCService(logger logging.Logger,
	configuration configurations.OIDCServiceConfiguration,
	client clients.OIDCClient,
	sessionStorage *storages.SessionStorage) OIDCService {
	return &OAuth2OIDCService{
		configuration:  configuration,
		client:         client,
		sessionStorage: sessionStorage,
		logger:         logger,
	}
}

// GetOIDCProviderURL gets OIDC provider URL from the OAuth2 configuration.
func (osvc *OAuth2OIDCService) GetOIDCProviderURL() (string, error) {
	// Creates a temporary session with state and nonce to validate
	// when there is callback from the OIDC Provider.
	session, err := models.CreateSession()
	if err != nil {
		return "", err
	}

	osvc.sessionStorage.StoreSession(session)

	return osvc.client.AuthCodeURL(session.State, session.Nonce), nil
}

// Claims creates claims tokens based on the auth code returned from the OIDC provider.
func (osvc *OAuth2OIDCService) Claims(ctx context.Context, code string) (models.Tokens, error) {
	if code == "" {
		return models.Tokens{}, errors.New("unable to authenticate without code returned from OIDC Provider")
	}

	oauth2Token, err := osvc.client.Exchange(ctx, code)
	if err != nil {
		return models.Tokens{}, fmt.Errorf("failed to exchange token. Error: %v", err)
	}

	tokens, err := osvc.client.Decode(ctx, oauth2Token.RawIDToken)
	if err != nil {
		return models.Tokens{}, fmt.Errorf("failed to verify ID Token. Error: %v", err)
	}
	osvc.logger.Info("✔️ Login validated with ID token")

	return tokens, nil
}

// IsFlowSecure ensures the flow is secure and then, returns a JWT token.
func (osvc *OAuth2OIDCService) IsFlowSecure(state string, token models.Tokens) (bool, error) {
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
func (osvc *OAuth2OIDCService) Create(cc models.CustomClaims) (models.CustomClaims, error) {
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
func (osvc *OAuth2OIDCService) Decode(tokenString string) (models.UserInfo, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return osvc.configuration.HMACSecret, nil
	})

	if token == nil {
		return models.UserInfo{}, authErrors.ErrorTokenContainsInvalidSegments
	}

	if token.Valid {
		claims := token.Claims.(jwt.MapClaims)
		return models.UserInfo{
			UID:  claims[osvc.configuration.UserIDClaim].(string),
			Name: claims[osvc.configuration.UserNameClaim].(string),
		}, nil
	}

	if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			return models.UserInfo{}, authErrors.ErrorTokenMalformed
		} else if ve.Errors&jwt.ValidationErrorExpired != 0 {
			return models.UserInfo{}, authErrors.ErrorTokenExpired
		} else if ve.Errors&jwt.ValidationErrorNotValidYet != 0 {
			return models.UserInfo{}, authErrors.ErrorTokenInactive
		} else if ve.Errors&jwt.ValidationErrorSignatureInvalid != 0 {
			return models.UserInfo{}, authErrors.ErrorTokenSignatureInvalid
		}
	}
	return models.UserInfo{}, fmt.Errorf("couldn't handle this token: %v", err)
}

// getValueFromToken gets the nonce from the ID Token.
func (osvc *OAuth2OIDCService) getValueFromToken(value string, t models.Tokens) (interface{}, error) {
	var m map[string]interface{}
	if err := json.Unmarshal(*t.IDTokenClaims, &m); err != nil {
		return "", errors.New("an unexpected error occurred when getting the nonce from ID Token")
	}

	if key, ok := m[value]; ok {
		return key, nil
	}
	return "", nil
}
