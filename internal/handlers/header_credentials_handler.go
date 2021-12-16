package handlers

import (
	"net/http"
	"strings"

	"github.com/ydataai/authentication-service/internal/configurations"
	authErrors "github.com/ydataai/authentication-service/internal/errors"
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
	token, err := getBearerToken(r.Header.Get(ah.restCtrlConfig.AuthHeader))
	if err != nil {
		ah.logger.Debugf("%s %s header", notFoundMsg, ah.restCtrlConfig.AuthHeader)
		return "", err
	}

	ah.logger.Infof("%s %s header", foundMsg, ah.restCtrlConfig.AuthHeader)
	return token, nil
}

func getBearerToken(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", authErrors.ErrNotFound
	}
	if strings.HasPrefix(value, "Bearer ") {
		return strings.TrimPrefix(value, "Bearer "), nil
	}
	return value, nil
}
