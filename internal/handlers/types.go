package handlers

import (
	"net/http"
)

// CredentialsHandler defines an interface for authentications.
type CredentialsHandler interface {
	Extract(r *http.Request) (string, error)
}
