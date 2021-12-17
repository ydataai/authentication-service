package models

import "time"

// ErrorResponse defines a struct with the JSON error response.
type ErrorResponse struct {
	Message   string    `json:"message,omitempty"`
	Timestamp time.Time `json:"timestamp,omitempty"`
}
