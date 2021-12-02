package services

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"

	"github.com/coreos/go-oidc"
	"github.com/ydataai/authentication-service/internal/clients"
	"github.com/ydataai/go-core/pkg/common/logging"
)

// Session is a struct to temporarily saving state and nonce
type Session struct {
	configuration SessionConfiguration
	State         string
	Nonce         string
	logger        logging.Logger
}

// NewSession creates a new session with temporary state and nonce
func NewSession(logger logging.Logger, configuration SessionConfiguration,
	w http.ResponseWriter, r *http.Request) (*Session, error) {

	state, err := randomString(16)
	if err != nil {
		return nil, err
	}
	nonce, err := randomString(16)
	if err != nil {
		return nil, err
	}

	s := &Session{
		configuration: configuration,
		State:         state,
		Nonce:         nonce,
		logger:        logger,
	}

	s.setSessionCookie(w, r, "state", state)
	s.setSessionCookie(w, r, "nonce", nonce)

	return s, nil
}

// randomString creates a random string and does a base64 encoding
func randomString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// setSessionCookie sets a cookie for the session
func (s Session) setSessionCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   s.configuration.MaxAge,
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, c)
}

// CreateOIDCProviderURL creates OIDC provider URL with some properties
func (s Session) CreateOIDCProviderURL(oidcClient *clients.OIDCClient) string {
	return oidcClient.OAuth2Config.AuthCodeURL(s.State, oidc.Nonce(s.Nonce))
}
