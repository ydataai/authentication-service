package handlers

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	authErrors "github.com/ydataai/authentication-service/internal/errors"
	"github.com/ydataai/go-core/pkg/common/logging"
)

func TestHeaderExtract(t *testing.T) {
	loggerConfig := logging.LoggerConfiguration{}
	loggerConfig.Level = "warn"
	logger := logging.NewLogger(loggerConfig)

	cc := NewHeaderCredentialsHandler(logger)

	mockRequestWithAuthorization := func(authType, token string) *http.Request {
		h := &http.Request{Header: http.Header{}}
		if authType != "" {
			h.Header.Set("Authorization", fmt.Sprintf("%s %s", authType, token))
		}
		return h
	}

	testCases := []struct {
		authType string
		token    string
		expected string
	}{
		{
			authType: "Bearer",
			token:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiQXpvcnkiLCJlbWFpbCI6ImRldmVsb3BlcnNAeWRhdGEuYWkiLCJleHAiOjI4Mzk5NDU0NjcsImlhdCI6MTYzOTk0NTE2N30.BxSAExKYane2X2XMNS-i5INMAzM9RFTQM-xGFeMytYo",
			expected: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiQXpvcnkiLCJlbWFpbCI6ImRldmVsb3BlcnNAeWRhdGEuYWkiLCJleHAiOjI4Mzk5NDU0NjcsImlhdCI6MTYzOTk0NTE2N30.BxSAExKYane2X2XMNS-i5INMAzM9RFTQM-xGFeMytYo",
		},
		{
			authType: "Bearer",
			token:    ".eyJuYW1lIjoiQXpvcnkiLCJlbWFpbCI6ImRldmVsb3BlcnNAeWRhdGEuYWkiLCJleHAiOjI4Mzk5NDU0NjcsImlhdCI6MTYzOTk0NTE2N30.BxSAExKYane2X2XMNS-i5INMAzM9RFTQM-xGFeMytYo",
			expected: ".eyJuYW1lIjoiQXpvcnkiLCJlbWFpbCI6ImRldmVsb3BlcnNAeWRhdGEuYWkiLCJleHAiOjI4Mzk5NDU0NjcsImlhdCI6MTYzOTk0NTE2N30.BxSAExKYane2X2XMNS-i5INMAzM9RFTQM-xGFeMytYo",
		},
		{
			authType: "Bearer",
			token:    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			expected: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		},
		{
			authType: "Bearer",
			token:    "    ",
			expected: "",
		},
		{
			authType: "Bearer",
			token:    "     .",
			expected: ".",
		},
		{
			authType: "Bearer",
			token:    "     .      ",
			expected: ".",
		},
		{
			authType: "Basic",
			token:    "d3NhbGxlczoxMjEzMTMx",
			expected: "Basic d3NhbGxlczoxMjEzMTMx",
		},
		{
			authType: "Basic",
			token:    "",
			expected: "Basic ",
		},
		{
			authType: "Basic",
			token:    "     .      ",
			expected: "Basic      .      ",
		},
		{
			authType: "",
			token:    "d3NhbGxlczoxMjEzMTMx",
			expected: "",
		},
		{
			authType: "",
			token:    "",
			expected: "",
		},
	}

	for _, tt := range testCases {
		r := mockRequestWithAuthorization(tt.authType, tt.token)
		token, err := cc.Extract(r)

		if authErrors.IsTokenNotFound(err) {
			logger.Warnf("No Header or Token == '': %v", err)
			assert.ErrorIs(t, err, authErrors.ErrTokenNotFound)
		} else {
			logger.Warnf("%v Authorization header", foundMsg)
			assert.Equal(t, tt.expected, token)
		}
	}
}
