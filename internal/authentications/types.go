package authentications

import (
	"net/http"
)

// CredentialsHandler gathers all authenticators to validate.
type CredentialsHandler struct {
	List []Request
}

type Request interface {
	AuthenticationRequest(r *http.Request) (map[string]interface{}, error)
}
