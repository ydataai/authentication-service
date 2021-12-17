package configurations

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

// OIDCServiceConfiguration defines a struct with required environment variables.
type OIDCServiceConfiguration struct {
	UserIDPrefix   string        `envconfig:"USER_ID_PREFIX" default:""`
	UserIDClaim    string        `envconfig:"USER_ID_CLAIM" default:"email"`
	UserNameClaim  string        `envconfig:"USER_NAME_CLAIM" default:"name"`
	UserJWTExpires time.Duration `envconfig:"USER_JWT_EXPIRES_AT" default:"24h"`
	HMACSecret     []byte        `envconfig:"HMAC_SECRET" required:"true"`
}

// LoadFromEnvVars from the OIDC Service.
func (osc *OIDCServiceConfiguration) LoadFromEnvVars() error {
	return envconfig.Process("", osc)
}
