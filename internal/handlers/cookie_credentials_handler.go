package handlers

import (
	"errors"
	"net/http"

	"github.com/ydataai/go-core/pkg/common/logging"
)

// CookieCredentialsHandler defines a CookieCredentialsHandler struct.
type CookieCredentialsHandler struct {
	logger logging.Logger
}

// NewCookieCredentialsHandler defines a new CookieCredentialsHandler struct.
func NewCookieCredentialsHandler(logger logging.Logger) CredentialsHandler {
	return &CookieCredentialsHandler{
		logger: logger,
	}
}

// Extract is an interface that extracts credential information from the cookie.
func (ac *CookieCredentialsHandler) Extract(r *http.Request) (string, error) {
	token, err := r.Cookie("access_token")
	if err != nil || token.Value == "" {
		return "", errors.New("'access_token' cookie not found")
	}

	ac.logger.Infof("'access_token' cookie found: %s", token.Value)
	return token.Value, nil
}
