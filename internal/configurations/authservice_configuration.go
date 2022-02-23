package configurations

import (
	"github.com/kelseyhightower/envconfig"
)

// AuthServiceConfiguration defines a struct with required environment variables.
type AuthServiceConfiguration struct {
	AccessTokenCookieName string `envconfig:"ACCESS_TOKEN_COOKIE_NAME" default:"access_token"`
}

// LoadFromEnvVars from the Authentication Service.
func (c *AuthServiceConfiguration) LoadFromEnvVars() error {
	return envconfig.Process("", c)
}
