package configurations

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

// OIDCServiceConfiguration defines a struct with required environment variables.
type OIDCServiceConfiguration struct {
	UserNameClaim  string        `envconfig:"USER_NAME_CLAIM" default:"name"`
	UserEmailClaim string        `envconfig:"USER_EMAIL_CLAIM" default:"email"`
	UserJWTExpires time.Duration `envconfig:"USER_JWT_EXPIRES_AT" default:"24h"`
	TopicUserInfo  string        `envconfig:"TOPIC_USER_INFO" default:"topic-user-info"`
	HMACSecret     []byte        `envconfig:"HMAC_SECRET" required:"true"`
}

// LoadFromEnvVars from the OIDC Service.
func (osc *OIDCServiceConfiguration) LoadFromEnvVars() error {
	return envconfig.Process("", osc)
}
