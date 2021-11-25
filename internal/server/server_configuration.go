package server

import (
	"net/url"

	"github.com/kelseyhightower/envconfig"
)

// ServerConfiguration defines a struct with required environment variables for a server
type ServerConfiguration struct {
	Hostname           string   `envconfig:"HOSTNAME"`
	Port               int      `envconfig:"PORT" default:"8080"`
	ReadinessProbePort int      `envconfig:"READINESS_PROBE_PORT" default:"8081"`
	LogoutURI          *url.URL `envconfig:"LOGOUT_URI" default:"/logout"`
	AfterLoginURL      *url.URL `envconfig:"AFTER_LOGIN_URL" default:"/"`
	AfterLogoutURL     *url.URL `envconfig:"AFTER_LOGOUT_URL" default:"/login"`
}

// LoadFromEnvVars from the Logger
func (sc *ServerConfiguration) LoadFromEnvVars() error {
	return envconfig.Process("", sc)
}
