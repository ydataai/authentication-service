package handlers

import (
	"net/http"
)

const (
	foundMsg    = "[✔️] token found in"
	notFoundMsg = "[✖️] token not found in"
)

// CredentialsHandler defines an interface for authentications.
type CredentialsHandler interface {
	Extract(r *http.Request) (string, error)
}
