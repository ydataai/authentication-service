package authentications

import (
	"errors"
	"net/http"

	"github.com/ydataai/go-core/pkg/common/logging"
)

// CookieCredentialsHandler defines a authentication cookie struct.
type CookieCredentialsHandler struct {
	logger logging.Logger
}

// NewCookieCredentialsHandler defines a new CookieCredentialsHandler struct.
func NewCookieCredentialsHandler(logger logging.Logger) CredentialsHandler {
	return &CookieCredentialsHandler{
		logger: logger,
	}
}

// Extract is an interface that provides authentication from the cookie.
func (ac *CookieCredentialsHandler) Extract(r *http.Request) (string, error) {
	// Try to get session from cookie
	token, err := r.Cookie("access_token")
	if err != nil || token.Value == "" {
		return "", errors.New("'access_token' cookie not found")
	}

	ac.logger.Infof("'access_token' cookie found: %s", token.Value)
	return token.Value, nil
}
