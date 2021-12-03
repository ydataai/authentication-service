package services

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"

	"github.com/ydataai/go-core/pkg/common/logging"
)

// SessionService is a struct to temporarily saving state and nonce
type SessionService struct {
	configuration SessionConfiguration
	State         string
	Nonce         string
	logger        logging.Logger
}

// NewSessionService creates a new session
func NewSessionService(logger logging.Logger, config SessionConfiguration) *SessionService {
	return &SessionService{
		configuration: config,
		logger:        logger,
	}
}

// CreateCookie creates a cookie with with temporary state and nonce
func (s *SessionService) CreateCookie(w http.ResponseWriter,
	r *http.Request) (*SessionService, error) {

	state, err := randomString(16)
	if err != nil {
		return nil, err
	}
	nonce, err := randomString(16)
	if err != nil {
		return nil, err
	}

	s.setSessionCookie(w, r, "state", state)
	s.setSessionCookie(w, r, "nonce", nonce)

	return &SessionService{
		State: state,
		Nonce: nonce,
	}, nil
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
