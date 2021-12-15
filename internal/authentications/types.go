package authentications

import (
	"net/http"
)

// CredentialsHandler defines an interface for authentications.
type CredentialsHandler interface {
	Extract(r *http.Request) (map[string]interface{}, error)
}