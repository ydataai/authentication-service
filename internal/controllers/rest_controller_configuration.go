package controllers

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

// RESTControllerConfiguration defines a struct with required environment variables for rest controller
type RESTControllerConfiguration struct {
	OIDCCallbackURL    string        `envconfig:"OIDC_CALLBACK_URL" default:"/auth/oidc/callback"`
	AuthServiceURL     string        `envconfig:"AUTHSERVICE_URL" default:"/auth"`
	HTTPRequestTimeout time.Duration `envconfig:"HTTP_REQUEST_TIMEOUT" default:"30s"`
}

// LoadFromEnvVars reads all env vars
func (rc *RESTControllerConfiguration) LoadFromEnvVars() error {
	return envconfig.Process("", rc)
}
