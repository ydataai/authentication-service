package services

import (
	"github.com/kelseyhightower/envconfig"
)

// SessionConfiguration defines a struct with required environment variables for the session
type SessionConfiguration struct {
	MaxAge int `envconfig:"SESSION_MAX_AGE" default:"604800"`
}

// LoadFromEnvVars reads all env vars
func (sc *SessionConfiguration) LoadFromEnvVars() error {
	return envconfig.Process("", sc)
}
