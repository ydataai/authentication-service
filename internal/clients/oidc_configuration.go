package clients

import (
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/ydataai/authentication-service/internal/handlers"
)

// OIDCConfiguration defines a struct with required environment variables for a OpenID Connect
type OIDCConfiguration struct {
	ClientID           string        `envconfig:"CLIENT_ID" required:"true"`
	ClientSecret       string        `envconfig:"CLIENT_SECRET" required:"true"`
	OIDProviderURL     string        `envconfig:"OIDC_PROVIDER_URL" required:"true"`
	OIDCRedirectURL    string        `envconfig:"OIDC_REDIRECT_URL" required:"true"`
	OIDCScopes         []string      `envconfig:"OIDC_SCOPES" default:"openid,profile,email" split_words:"true"`
	HTTPRequestTimeout time.Duration `envconfig:"HTTP_REQUEST_TIMEOUT" default:"30s"`
}

// LoadFromEnvVars from the OIDC
func (oc *OIDCConfiguration) LoadFromEnvVars() error {
	if err := envconfig.Process("", oc); err != nil {
		return err
	}

	// "openid" is a required scope for OpenID Connect flows
	if !handlers.ArrayContainsString(oc.OIDCScopes, "openid") {
		oc.OIDCScopes = append(oc.OIDCScopes, "openid")
	}

	return nil
}
