package configurations

import (
	"github.com/kelseyhightower/envconfig"
)

// CookieCredentialsHandlerConfiguration defines a struct with required environment variables.
type CookieCredentialsHandlerConfiguration struct {
	AccessTokenCookie string `envconfig:"ACCESS_TOKEN_COOKIE" default:"access_token"`
}

// LoadFromEnvVars from the Cookie Credentials Handler.
func (c *CookieCredentialsHandlerConfiguration) LoadFromEnvVars() error {
	return envconfig.Process("", c)
}
