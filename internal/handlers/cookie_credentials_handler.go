package handlers

import (
	"net/http"

	authErrors "github.com/ydataai/authentication-service/internal/errors"
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
	if err != nil {
		ac.logger.Infof("%s cookie", notFoundMsg)
		return "", authErrors.ErrorTokenNotFound
	}

	ac.logger.Infof("%s cookie", foundMsg)
	return token.Value, nil
}
