package controllers

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

// RESTControllerConfiguration defines a struct with required environment variables for rest controller
type RESTControllerConfiguration struct {
	UserID             string        `envconfig:"USER_ID" required:"true"`
	UserIDPrefix       string        `envconfig:"USER_ID_PREFIX" default:""`
	OIDCCallbackURL    string        `envconfig:"OIDC_CALLBACK_URL" default:"/auth/oidc/callback"`
	AuthServiceURL     string        `envconfig:"AUTHSERVICE_URL" default:"/auth"`
	LogoutURL          string        `envconfig:"LOGOUT_URL" default:"/logout"`
	AfterLoginURL      string        `envconfig:"AFTER_LOGIN_URL" default:"/"`
	AfterLogoutURL     string        `envconfig:"AFTER_LOGOUT_URL" default:"/login"`
	HTTPRequestTimeout time.Duration `envconfig:"HTTP_REQUEST_TIMEOUT" default:"30s"`
}

// LoadFromEnvVars reads all env vars
func (rc *RESTControllerConfiguration) LoadFromEnvVars() error {
	return envconfig.Process("", rc)
}
