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

func (rs RESTService) RandString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (rs RESTService) SetCallbackCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		MaxAge:   int(time.Hour.Seconds()),
		Secure:   r.TLS != nil,
		HttpOnly: true,
	}
	http.SetCookie(w, c)
}
