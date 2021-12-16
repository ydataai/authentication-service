package models

// SuccessResponse defines a struct with the JSON success response.
type SuccessResponse struct {
	AccessToken string `json:"access_token,omitempty"`
}

// ErrorResponse defines a struct with the JSON error response.
type ErrorResponse struct {
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
}
