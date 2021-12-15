package authentications

import (
	"errors"
	"net/http"

	"github.com/ydataai/authentication-service/internal/services"
	"github.com/ydataai/go-core/pkg/common/logging"
)

// AuthenticationCookie defines a authentication cookie struct.
type AuthenticationCookie struct {
	oidcService *services.OIDCService
	logger      logging.Logger
}

// NewAuthenticationCookie defines a new AuthenticationCookie struct.
func NewAuthenticationCookie(logger logging.Logger,
	oidcService *services.OIDCService) *AuthenticationCookie {

	return &AuthenticationCookie{
		oidcService: oidcService,
		logger:      logger,
	}
}

// AuthenticationRequest is an interface that provides authentication from the cookie.
func (ac *AuthenticationCookie) AuthenticationRequest(r *http.Request) (map[string]interface{}, error) {
	// Try to get session from cookie
	token, err := r.Cookie("access_token")
	if err != nil || token.Value == "" {
		return nil, errors.New("'access_token' cookie not found")
	}

	ac.logger.Infof("'access_token' cookie found: %s", token.Value)

	// if we have a token, we'll validate it.
	claims, err := ac.oidcService.ValidateJWT(token.Value)
	if err != nil {
		ac.logger.Warningf("error validating the token written in the cookie. Error: %v", err.Error())
		ac.logger.Warningf("will follow the OIDC flow because it is a cookie.")
		return nil, err
	}

	return claims, nil
}
