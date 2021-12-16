package models

// SuccessResponse defines a struct with the JSON success response.
type SuccessResponse struct {
	AccessToken string `json:"access_token,omitempty"`
}

// ErrorResponse defines a struct with the JSON error response.
type ErrorResponse struct {
	Message string `json:"message,omitempty"`
}
