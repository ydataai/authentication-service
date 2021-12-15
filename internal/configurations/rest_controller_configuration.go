package configurations

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

// RESTControllerConfiguration defines a struct with required environment variables for rest controller.
type RESTControllerConfiguration struct {
	OIDCCallbackURL    string        `envconfig:"OIDC_CALLBACK_URL" default:"/auth/oidc/callback"`
	AuthServiceURL     string        `envconfig:"AUTHSERVICE_URL" default:"/"`
	LogoutURL          string        `envconfig:"LOGOUT_URL" default:"/logout"`
	HTTPRequestTimeout time.Duration `envconfig:"HTTP_REQUEST_TIMEOUT" default:"30s"`
	AuthHeader         string        `envconfig:"AUTH_HEADER" default:"Authorization"`
	UserIDHeader       string        `envconfig:"USER_ID_HEADER" default:"userid"`
	UserIDPrefix       string        `envconfig:"USER_ID_PREFIX" default:""`
	CookieMaxAge       int           `envconfig:"COOKIE_MAX_AGE" default:"86400"`
}

// LoadFromEnvVars reads all env vars.
func (rc *RESTControllerConfiguration) LoadFromEnvVars() error {
	return envconfig.Process("", rc)
}
