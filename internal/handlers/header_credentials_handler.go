package handlers

import (
	"errors"
	"net/http"
	"strings"

	"github.com/ydataai/authentication-service/internal/configurations"
	"github.com/ydataai/go-core/pkg/common/logging"
)

// HeaderCredentialsHandler defines a HeaderCredentialsHandler struct.
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

// Extract is an interface that extracts credential information from the header.
func (ah *HeaderCredentialsHandler) Extract(r *http.Request) (string, error) {
	// Try to get session from header
	token := getBearerToken(r.Header.Get(ah.restCtrlConfig.AuthHeader))
	if token == "" {
		return "", errors.New(notFound + ah.restCtrlConfig.AuthHeader + " header")
	}

	ah.logger.Infof(found + ah.restCtrlConfig.AuthHeader + " header")
	ah.logger.Debug(token)
	return token, nil
}

func getBearerToken(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "Bearer ") {
		return strings.TrimPrefix(value, "Bearer ")
	}
	return value
}
