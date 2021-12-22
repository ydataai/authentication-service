package handlers

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	authErrors "github.com/ydataai/authentication-service/internal/errors"
	"github.com/ydataai/go-core/pkg/common/logging"
)

func TestCookieExtract(t *testing.T) {
	loggerConfig := logging.LoggerConfiguration{}
	loggerConfig.Level = "warn"
	logger := logging.NewLogger(loggerConfig)
	cc := NewCookieCredentialsHandler(logger)

	mockRequestWithCookie := func(key, value string) *http.Request {
		return &http.Request{Header: http.Header{
			"Cookie": []string{fmt.Sprintf("%s=%s", key, value)},
		}}
	}

	testCases := []struct {
		cookieKey   string
		cookieValue string
	}{
		{
			cookieKey:   "access_token",
			cookieValue: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiQXpvcnkiLCJlbWFpbCI6ImRldmVsb3BlcnNAeWRhdGEuYWkiLCJleHAiOjI4Mzk5NDU0NjcsImlhdCI6MTYzOTk0NTE2N30.BxSAExKYane2X2XMNS-i5INMAzM9RFTQM-xGFeMytYo",
		},
		{
			cookieKey:   "access_token",
			cookieValue: "",
		},
		{
			cookieKey:   "token",
			cookieValue: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiQXpvcnkiLCJlbWFpbCI6ImRldmVsb3BlcnNAeWRhdGEuYWkiLCJleHAiOjI4Mzk5NDU0NjcsImlhdCI6MTYzOTk0NTE2N30.BxSAExKYane2X2XMNS-i5INMAzM9RFTQM-xGFeMytYo",
		},
		{
			cookieKey:   "token",
			cookieValue: "",
		},
		{
			cookieKey:   "",
			cookieValue: "token",
		},
		{
			cookieKey:   "",
			cookieValue: "",
		},
	}

	for _, tt := range testCases {
		r := mockRequestWithCookie(tt.cookieKey, tt.cookieValue)
		token, err := cc.Extract(r)

		if authErrors.IsTokenNotFound(err) {
			logger.Warnf("[OK] ✖️ %v", err)
			assert.ErrorIs(t, err, authErrors.ErrTokenNotFound)
		} else {
			logger.Warnf("[OK] %s cookie", foundMsg)
			assert.Equal(t, tt.cookieValue, token)
		}
	}
}
