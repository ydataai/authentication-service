package models

import "time"

// SuccessResponse defines a struct with the JSON success response.
type SuccessResponse struct {
	AccessToken string    `json:"access_token,omitempty"`
	ExpiresAt   time.Time `json:"expires_at,omitempty"`
}

// ErrorResponse defines a struct with the JSON error response.
type ErrorResponse struct {
	Message   string    `json:"message,omitempty"`
	Timestamp time.Time `json:"timestamp,omitempty"`
}
