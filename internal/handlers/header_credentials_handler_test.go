package handlers

import (
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

	mockRequestWithAuthorization := func(token string) *http.Request {
		return &http.Request{Header: http.Header{
			"Authorization": []string{token},
		}}
	}

	testCases := []struct {
		token    string
		expected string
	}{
		{
			token:    "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiQXpvcnkiLCJlbWFpbCI6ImRldmVsb3BlcnNAeWRhdGEuYWkiLCJleHAiOjI4Mzk5NDU0NjcsImlhdCI6MTYzOTk0NTE2N30.BxSAExKYane2X2XMNS-i5INMAzM9RFTQM-xGFeMytYo",
			expected: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiQXpvcnkiLCJlbWFpbCI6ImRldmVsb3BlcnNAeWRhdGEuYWkiLCJleHAiOjI4Mzk5NDU0NjcsImlhdCI6MTYzOTk0NTE2N30.BxSAExKYane2X2XMNS-i5INMAzM9RFTQM-xGFeMytYo",
		},
		{
			token:    "Bearer .eyJuYW1lIjoiQXpvcnkiLCJlbWFpbCI6ImRldmVsb3BlcnNAeWRhdGEuYWkiLCJleHAiOjI4Mzk5NDU0NjcsImlhdCI6MTYzOTk0NTE2N30.BxSAExKYane2X2XMNS-i5INMAzM9RFTQM-xGFeMytYo",
			expected: ".eyJuYW1lIjoiQXpvcnkiLCJlbWFpbCI6ImRldmVsb3BlcnNAeWRhdGEuYWkiLCJleHAiOjI4Mzk5NDU0NjcsImlhdCI6MTYzOTk0NTE2N30.BxSAExKYane2X2XMNS-i5INMAzM9RFTQM-xGFeMytYo",
		},
		{
			token:    "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			expected: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		},
		{
			token:    "Bearer    ",
			expected: "",
		},
		{
			token:    "Bearer     .",
			expected: ".",
		},
		{
			token:    "Bearer     .      ",
			expected: ".",
		},
		{
			token:    "Basic d3NhbGxlczoxMjEzMTMx",
			expected: "Basic d3NhbGxlczoxMjEzMTMx",
		},
		{
			token:    "Basic ",
			expected: "Basic ",
		},
		{
			token:    "Basic      .      ",
			expected: "Basic      .      ",
		},
		{
			token:    "d3NhbGxlczoxMjEzMTMx",
			expected: "d3NhbGxlczoxMjEzMTMx",
		},
		{
			token:    "",
			expected: "",
		},
	}

	for _, tt := range testCases {
		r := mockRequestWithAuthorization(tt.token)
		token, err := cc.Extract(r)

		if err != nil {
			logger.Warnf("[OK] ✖️ No Header or Token == '': %v", err)
			assert.ErrorIs(t, err, authErrors.ErrorTokenNotFound)
		} else {
			logger.Warnf("[OK] %v Authorization header", foundMsg)
			assert.Equal(t, tt.expected, token)
		}
	}
}
