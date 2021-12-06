package services

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/ydataai/authentication-service/internal/models"
	"github.com/ydataai/go-core/pkg/common/logging"
)

// SessionService is a struct to temporarily saving state and nonce
type SessionService struct {
	configuration SessionConfiguration

	// State is there to protect the end user from cross site request forgery(CSRF) attacks.
	// It is introduced from OAuth 2.0 protocol RFC6749 (https://www.rfc-editor.org/rfc/rfc6749#section-10.12).
	// Protocol states that:
	// Once authorization has been obtained from the end-user, the authorization server redirects
	// the end-user's user-agent back to the client with the required binding value contained in
	// the "state" parameter. The binding value enables the client to verify the validity of the
	// request by matching the binding value to the user-agent's authenticated state.
	state string

	// Nonce serves as a token validation parameter and is introduced from OIDC specification.
	// https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowSteps
	// According to Google, you should enforce protection against replay attacks by ensuring
	// it is presented only once.
	nonce string

	logger logging.Logger
}

// NewSessionService creates a new session
func NewSessionService(logger logging.Logger, config SessionConfiguration) *SessionService {
	return &SessionService{
		configuration: config,
		logger:        logger,
	}
}

// SetState sets a temporary state.
func (s *SessionService) SetState() {
	state, err := randomString(16)
	if err != nil {
		s.logger.Error("An error occurred while creating a temporary state.")
		s.state = ""
	}
	s.state = state
}

// GetState gets a temporary state.
func (s *SessionService) GetState() string {
	return s.state
}

// SetNonce sets a temporary nonce.
func (s *SessionService) SetNonce() {
	nonce, err := randomString(16)
	if err != nil {
		s.logger.Error("An error occurred while creating a temporary nonce.")
		s.state = ""
	}
	s.nonce = nonce
}

// GetNonce gets a temporary nonce.
func (s *SessionService) GetNonce() string {
	return s.nonce
}

// SetCookies sets a cookie with with temporary state and nonce.
func (s *SessionService) SetCookies(w http.ResponseWriter, r *http.Request) {
	s.setSessionCookie(w, r, "state", s.state)
	s.setSessionCookie(w, r, "nonce", s.nonce)
}

// MatchState matches the cookie value with the URL query string.
func (s *SessionService) MatchState(r *http.Request) bool {
	key := s.getCookieValueOrFallback("state", s.state, r)

	if r.URL.Query().Get("state") != key {
		s.logger.Error("state did not match", key)
		return false
	}

	return true
}

// MatchNonce matches the cookie value with the nonce claim of the ID Token.
func (s *SessionService) MatchNonce(nonce string, r *http.Request) bool {
	key := s.getCookieValueOrFallback("nonce", s.nonce, r)

	if nonce != key {
		s.logger.Error("nonce did not match", key)
		return false
	}

	return true
}

// CreateJWT creates a new token and the claims you would like it to contain.
func (s *SessionService) CreateJWT(cc *models.CustomClaims) (*models.CustomClaims, error) {
	// For HMAC signing method, the key can be any []byte
	hmacRandSecret, err := randomByte(1990)
	if err != nil {
		s.logger.Errorf("An error occurred while generating HMAC. Error: %v", err)
		return nil, err
	}

	customClaims := &models.CustomClaims{
		Name:          cc.Name,
		Email:         cc.Email,
		EmailVerified: cc.EmailVerified,
		Picture:       cc.Picture,
		Profile:       cc.Profile,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(s.configuration.JWTExpires))),
			Issuer:    s.configuration.Issuer,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, customClaims)

	// Sign and get the complete encoded token as a string using the secret
	customClaims.AccessToken, err = token.SignedString(hmacRandSecret)

	return customClaims, err
}

// randomString creates a random string and does a base64 encoding
func randomString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// randomByte creates a random byte value.
func randomByte(nByte int) ([]byte, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// getCookieValueOrFallback gets a cookie value with or fallback option.
func (s *SessionService) getCookieValueOrFallback(value string, fallback string, r *http.Request) string {
	key, err := r.Cookie(value)
	if err != nil {
		return fallback
	}

	return key.Value
}

// setSessionCookie sets a cookie for the session
func (s SessionService) setSessionCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   s.configuration.MaxAge,
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, c)
}
