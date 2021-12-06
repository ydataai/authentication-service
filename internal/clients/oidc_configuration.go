package clients

import (
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/ydataai/authentication-service/internal/handlers"
)

// OIDCConfiguration defines a struct with required environment variables for a OpenID Connect
type OIDCConfiguration struct {
	ClientID        string        `envconfig:"CLIENT_ID" required:"true"`
	ClientSecret    string        `envconfig:"CLIENT_SECRET" required:"true"`
	OIDProviderURL  string        `envconfig:"OIDC_PROVIDER_URL" required:"true"`
	OIDCRedirectURL string        `envconfig:"OIDC_REDIRECT_URL" required:"true"`
	OIDCScopes      []string      `envconfig:"OIDC_SCOPES" default:"openid,profile,email" split_words:"true"`
	JWTExpires      time.Duration `envconfig:"JWT_EXPIRES_AT" default:"24h"`
	Issuer          string        `envconfig:"SESSION_ISSUER" default:"http://authorization-service:5555/"`
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
