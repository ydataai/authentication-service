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
	UserInfoURL        string        `envconfig:"USER_INFO_URL" default:"/userinfo"`
	UserJWTExpires     time.Duration `envconfig:"USER_JWT_EXPIRES_AT" default:"24"`
	HTTPRequestTimeout time.Duration `envconfig:"HTTP_REQUEST_TIMEOUT" default:"30s"`
	UserIDHeader       string        `envconfig:"USER_ID_HEADER" default:"userid"`
	CookieMaxAge       int           `envconfig:"COOKIE_MAX_AGE" default:"86400"`
	AccessTokenCookie  string        `envconfig:"ACCESS_TOKEN_COOKIE" default:"access_token"`
	SkipURLs           []string      `envconfig:"SKIP_URLS" default:"/dex" split_words:"true"`
}

// LoadFromEnvVars reads all env vars.
func (rc *RESTControllerConfiguration) LoadFromEnvVars() error {
	return envconfig.Process("", rc)
}
