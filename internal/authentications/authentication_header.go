package authentications

import (
	"errors"
	"net/http"
	"strings"

	"github.com/ydataai/authentication-service/internal/configurations"
	"github.com/ydataai/authentication-service/internal/services"
	"github.com/ydataai/go-core/pkg/common/logging"
)

// AuthenticationHeader defines a authentication header struct.
type AuthenticationHeader struct {
	oidcService    services.OIDCService
	restCtrlConfig configurations.RESTControllerConfiguration
	logger         logging.Logger
}

// NewAuthenticationHeader defines a new AuthenticationHeader struct.
func NewAuthenticationHeader(logger logging.Logger,
	oidcService services.OIDCService,
	restCtrlConfig configurations.RESTControllerConfiguration) CredentialsHandler {

	return &AuthenticationHeader{
		oidcService:    oidcService,
		restCtrlConfig: restCtrlConfig,
		logger:         logger,
	}
}

// Extract is an interface that provides authentication from the header.
func (ah *AuthenticationHeader) Extract(r *http.Request) (map[string]interface{}, error) {
	// Try to get session from header
	token := getBearerToken(r.Header.Get(ah.restCtrlConfig.AuthHeader))
	if token == "" {
		ah.logger.Infof("%s header not found", ah.restCtrlConfig.AuthHeader)
		return nil, errors.New(ah.restCtrlConfig.AuthHeader + " header not found")
	}

	ah.logger.Infof("%s header found: %s", ah.restCtrlConfig.AuthHeader, token)

	// if we have a token, we'll validate it.
	claims, err := ah.oidcService.ValidateJWT(token)
	if err != nil {
		ah.logger.Warnf(err.Error())
		return claims, err
	}

	return claims, nil
}

func getBearerToken(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "Bearer ") {
		return strings.TrimPrefix(value, "Bearer ")
	}
	return value
}
