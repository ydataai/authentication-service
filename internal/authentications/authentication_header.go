package authentications

import (
	"errors"
	"net/http"
	"strings"

	"github.com/ydataai/authentication-service/internal/configurations"
	"github.com/ydataai/go-core/pkg/common/logging"
)

// HeaderCredentialsHandler defines a authentication header struct.
type HeaderCredentialsHandler struct {
	restCtrlConfig configurations.RESTControllerConfiguration
	logger         logging.Logger
}

// NewHeaderCredentialsHandler defines a new HeaderCredentialsHandler struct.
func NewHeaderCredentialsHandler(logger logging.Logger,
	restCtrlConfig configurations.RESTControllerConfiguration) CredentialsHandler {

	return &HeaderCredentialsHandler{
		restCtrlConfig: restCtrlConfig,
		logger:         logger,
	}
}

// Extract is an interface that provides authentication from the header.
func (ah *HeaderCredentialsHandler) Extract(r *http.Request) (string, error) {
	// Try to get session from header
	token := getBearerToken(r.Header.Get(ah.restCtrlConfig.AuthHeader))
	if token == "" {
		ah.logger.Infof("%s header not found", ah.restCtrlConfig.AuthHeader)
		return "", errors.New(ah.restCtrlConfig.AuthHeader + " header not found")
	}

	ah.logger.Infof("%s header found: %s", ah.restCtrlConfig.AuthHeader, token)
	return token, nil
}

func getBearerToken(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "Bearer ") {
		return strings.TrimPrefix(value, "Bearer ")
	}
	return value
}
