package configurations

import (
	"github.com/kelseyhightower/envconfig"
)

// SessionStorageConfiguration defines a struct with required environment variables for the session.
type SessionStorageConfiguration struct {
	// TODO: including TTL for session storage
	MaxTTL int `envconfig:"SESSION_MAX_TLL" default:"600"`
}

// LoadFromEnvVars reads all env vars.
func (sc *SessionStorageConfiguration) LoadFromEnvVars() error {
	return envconfig.Process("", sc)
}
