package configurations

import (
	"github.com/kelseyhightower/envconfig"
)

// OIDCServiceConfiguration defines a struct with required environment variables.
type OIDCServiceConfiguration struct {
	UserNameClaim  string `envconfig:"USER_NAME_CLAIM" default:"name"`
	UserEmailClaim string `envconfig:"USER_EMAIL_CLAIM" default:"email"`
	HMACSecret     []byte `envconfig:"HMAC_SECRET" required:"true"`
}

// LoadFromEnvVars from the OIDC Service.
func (osc *OIDCServiceConfiguration) LoadFromEnvVars() error {
	return envconfig.Process("", osc)
}
