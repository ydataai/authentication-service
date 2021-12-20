package handlers

import (
	"net/http"
	"strings"

	authErrors "github.com/ydataai/authentication-service/internal/errors"
	"github.com/ydataai/go-core/pkg/common/logging"
)

// HeaderCredentialsHandler defines a HeaderCredentialsHandler struct.
type HeaderCredentialsHandler struct {
	logger logging.Logger
}

// NewHeaderCredentialsHandler defines a new HeaderCredentialsHandler struct.
func NewHeaderCredentialsHandler(logger logging.Logger) CredentialsHandler {
	return &HeaderCredentialsHandler{
		logger: logger,
	}
}

// Extract is an interface that extracts credential information from the header.
func (ah *HeaderCredentialsHandler) Extract(r *http.Request) (string, error) {
	token := r.Header.Get("Authorization")
	// make sure the authorization header is of type Bearer.
	if strings.HasPrefix(token, "Bearer") {
		token = strings.TrimSpace(
			strings.TrimPrefix(token, "Bearer"),
		)
	}

	if token == "" {
		ah.logger.Infof("%s authorization header", notFoundMsg)
		return "", authErrors.ErrTokenNotFound
	}

	// token found in authorization header of type Bearer.
	ah.logger.Infof("%s authorization header", foundMsg)
	return token, nil
}
