package authentications

import (
	"net/http"
)

// CredentialsHandler gathers all authentications to validate.
type CredentialsHandler struct {
	List []Request
}

// Request defines an interface for authentications.
type Request interface {
	AuthenticationRequest(r *http.Request) (map[string]interface{}, error)
}
