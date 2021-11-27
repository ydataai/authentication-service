package services

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"time"

	"github.com/ydataai/go-core/pkg/common/logging"
)

// RESTService defines http service structure
type RESTService struct {
	logger logging.Logger
}

// NewRESTService initializes http service
func NewRESTService(logger logging.Logger) *RESTService {
	return &RESTService{
		logger: logger,
	}
}

// RandomString creates a random string and does a base64 encoding
func (rs RESTService) RandomString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SetSessionCookie sets a cookie for the session
func (rs RESTService) SetSessionCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, c)
}
