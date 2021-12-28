package errors

import "errors"

var (
	// ErrorTokenNotFound creates a new ErrorTokenNotFound error.
	ErrorTokenNotFound = errors.New("token not found")
	// ErrorTokenExpired creates a new ErrorTokenExpired error.
	ErrorTokenExpired = errors.New("token expired")
	// ErrorTokenInactive creates a new ErrorTokenInactive error.
	ErrorTokenInactive = errors.New("token not active yet")
	// ErrorTokenSignatureInvalid creates a new ErrorTokenSignatureInvalid error.
	ErrorTokenSignatureInvalid = errors.New("signature invalid")
	// ErrorTokenContainsInvalidSegments creates a new ErrorTokenContainsInvalidSegments error.
	ErrorTokenContainsInvalidSegments = errors.New("token contains an invalid number of segments")
	// ErrorTokenMalformed creates a new ErrorTokenMalformed error.
	ErrorTokenMalformed = errors.New("token malformed")
)

// IsTokenNotFound returns true if the specified error is an ErrorTokenNotFound.
func IsTokenNotFound(err error) bool {
	return err == ErrorTokenNotFound
}

// IsTokenExpired returns true if the specified error is an ErrorTokenExpired.
func IsTokenExpired(err error) bool {
	return err == ErrorTokenExpired
}

// IsTokenSignatureInvalid returns true if the specified error is an ErrorTokenSignatureInvalid.
func IsTokenSignatureInvalid(err error) bool {
	return err == ErrorTokenSignatureInvalid
}
