package services

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v4"
	"github.com/ydataai/authentication-service/internal/clients"
	"github.com/ydataai/authentication-service/internal/models"
	"github.com/ydataai/go-core/pkg/common/logging"
	"golang.org/x/oauth2"
)

// OIDCService defines the oidc server struct
type OIDCService struct {
	client         *clients.OIDCClient
	sessionStorage *models.SessionStorage
	logger         logging.Logger
}

// NewOIDCService creates a new OIDC Service
func NewOIDCService(logger logging.Logger,
	client *clients.OIDCClient,
	sessionStorage *models.SessionStorage) *OIDCService {
	return &OIDCService{
		client:         client,
		sessionStorage: sessionStorage,
		logger:         logger,
	}
}

// GetReadyzFunc make sure if oidc provider is ready
func (osvc *OIDCService) GetReadyzFunc() func() bool {
	return osvc.client.ReadyzFunc
}

// GetOIDCProviderURL gets OIDC provider URL from the OAuth2 configuration.
func (osvc *OIDCService) GetOIDCProviderURL(w http.ResponseWriter, r *http.Request) string {
	// Sets a temporary session with state and nonce to validate
	// when there is callback from the OIDC Provider.
	session := osvc.sessionStorage.CreateSession()

	return osvc.client.OAuth2Config.AuthCodeURL(
		session.State,
		oidc.Nonce(session.Nonce),
	)
}

// GetUserInfo gets User Info from the OAuth2 Token.
func (osvc *OIDCService) GetUserInfo(ctx context.Context, oauth2Token *oauth2.Token) (*oidc.UserInfo, error) {
	userInfo, err := osvc.client.Provider.UserInfo(ctx, oauth2.StaticTokenSource(oauth2Token))
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

// IsFlowSecure ensures the flow is secure and then, returns a JWT token.
func (osvc *OIDCService) IsFlowSecure(ctx context.Context,
	w http.ResponseWriter, r *http.Request) []byte {

	token, err := osvc.claimsToken(ctx, w, r)
	if err != nil {
		return nil
	}

	session := osvc.sessionStorage.GetSession(r)
	if session == nil {
		msg := "An error occurred when trying to receive the session <nil>"
		osvc.logger.Error(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return nil
	}

	nonceToken, err := osvc.GetValueFromToken("nonce", token)
	if err != nil {
		msg := fmt.Sprintf("An unexpected error occurred when getting the nonce from ID Token. Err: %v", err)
		osvc.logger.Errorf(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return nil
	}
	if !session.MatchNonce(nonceToken.(string), r) {
		msg := "nonce did not match"
		osvc.logger.Error(msg)
		http.Error(w, msg, http.StatusBadRequest)
		return nil
	}

	jwt, err := osvc.createJWT(&token.CustomClaims)
	if err != nil {
		msg := fmt.Sprintf("An error occurred while creating a JWT. Error: %v", err)
		osvc.logger.Error(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return nil
	}

	// If all goes well, then create the JSON data to display as body content.
	jsonBody, err := json.Marshal(jwt)
	if err != nil {
		msg := fmt.Sprintf("An error occurred while validating some tokens. Error: %v", err)
		osvc.logger.Errorf(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return nil
	}

	return jsonBody
}

// claimsToken creates token claims
func (osvc *OIDCService) claimsToken(ctx context.Context,
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

// createJWT creates a new token and the claims you would like it to contain.
func (osvc *OIDCService) createJWT(cc *models.CustomClaims) (*models.CustomClaims, error) {
	// For HMAC signing method, the key can be any []byte
	hmacRandSecret, err := randomByte(1990)
	if err != nil {
		osvc.logger.Errorf("An error occurred while generating HMAC. Error: %v", err)
		return nil, err
	}

	customClaims := &models.CustomClaims{
		Name:          cc.Name,
		Email:         cc.Email,
		EmailVerified: cc.EmailVerified,
		Picture:       cc.Picture,
		Profile:       cc.Profile,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(osvc.client.Configuration.JWTExpires))),
			Issuer:    osvc.client.Configuration.Issuer,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, customClaims)

	// Sign and get the complete encoded token as a string using the secret
	customClaims.AccessToken, err = token.SignedString(hmacRandSecret)

	return customClaims, err
}

// randomByte creates a random byte value.
func randomByte(nByte int) ([]byte, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}
