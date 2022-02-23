package configurations

import (
	"github.com/kelseyhightower/envconfig"
)

// CookieCredentialsHandlerConfiguration defines a struct with required environment variables.
type CookieCredentialsHandlerConfiguration struct {
	AccessTokenCookieName string `envconfig:"ACCESS_TOKEN_COOKIE_NAME" default:"access_token"`
}

// LoadFromEnvVars from the Cookie Credentials Handler.
func (c *CookieCredentialsHandlerConfiguration) LoadFromEnvVars() error {
	return envconfig.Process("", c)
}
