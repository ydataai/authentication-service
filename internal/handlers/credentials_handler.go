package handlers

import (
	"net/http"
)

const (
	found    = "[✔️] token found in "
	notFound = "[✖️] token not found in "
)

// CredentialsHandler defines an interface for authentications.
type CredentialsHandler interface {
	Extract(r *http.Request) (string, error)
}
