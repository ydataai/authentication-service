package clients

import (
	"github.com/kelseyhightower/envconfig"
)

// OIDCConfiguration defines a struct with required environment variables for a OpenID Connect
type OIDCConfiguration struct {
	ClientID        string   `envconfig:"CLIENT_ID" required:"true"`
	ClientSecret    string   `envconfig:"CLIENT_SECRET" required:"true"`
	OIDProviderURL  string   `envconfig:"OIDC_PROVIDER_URL" required:"true"`
	OIDCCallbackURI string   `envconfig:"OIDC_CALLBACK_URI" default:"/auth/oidc/callback"`
	OIDCScopes      []string `envconfig:"OIDC_SCOPES" default:"openid,profile,email,groups" split_words:"true"`
}

// LoadFromEnvVars from the OIDC
func (oc *OIDCConfiguration) LoadFromEnvVars() error {
	return envconfig.Process("", oc)
}
