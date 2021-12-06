package services

import (
	"time"

	"github.com/kelseyhightower/envconfig"
)

// SessionConfiguration defines a struct with required environment variables for the session
type SessionConfiguration struct {
	MaxAge     int           `envconfig:"SESSION_MAX_AGE" default:"604800"`
	JWTExpires time.Duration `envconfig:"SESSION_JWT_EXPIRES_AT" default:"24h"`
	Issuer     string        `envconfig:"SESSION_ISSUER" default:"http://authorization-service:5555/"`
}

// LoadFromEnvVars reads all env vars
func (sc *SessionConfiguration) LoadFromEnvVars() error {
	return envconfig.Process("", sc)
}
