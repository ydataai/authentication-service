package errors

import "errors"

var (
	// ErrTokenNotFound creates a new NotFound error.
	ErrTokenNotFound = errors.New("token not found")
	// ErrTokenExpired creates a new ErrTokenExpired error.
	ErrTokenExpired = errors.New("token expired")
	// ErrTokenInactiveYet creates a new ErrTokenInactiveYet error.
	ErrTokenInactiveYet = errors.New("token not active yet")
	// ErrTokenSignatureInvalid creates a new ErrTokenSignatureInvalid error.
	ErrTokenSignatureInvalid = errors.New("signature invalid")
	// ErrTokenContainsInvalidSegments creates a new ErrTokenContainsInvalidSegments error.
	ErrTokenContainsInvalidSegments = errors.New("token contains an invalid number of segments")
	// ErrorTokenMalformed creates a new ErrorTokenMalformed error.
	ErrorTokenMalformed = errors.New("token malformed")
)

// IsTokenNotFound returns true if the specified error is an ErrTokenNotFound.
func IsTokenNotFound(err error) bool {
	return err == ErrTokenNotFound
}

// IsTokenExpired returns true if the specified error is an ErrTokenExpired.
func IsTokenExpired(err error) bool {
	return err == ErrTokenExpired
}

// IsTokenInactiveYet returns true if the specified error is an ErrTokenInactiveYet.
func IsTokenInactiveYet(err error) bool {
	return err == ErrTokenInactiveYet
}

// IsErrTokenSignatureInvalid returns true if the specified error is an ErrTokenSignatureInvalid.
func IsErrTokenSignatureInvalid(err error) bool {
	return err == ErrTokenSignatureInvalid
}

// IsErrTokenContainsInvalidSegments returns true if the specified error is an ErrTokenContainsInvalidSegments.
func IsErrTokenContainsInvalidSegments(err error) bool {
	return err == ErrTokenContainsInvalidSegments
}

// IsErrorTokenMalformed returns true if the specified error is an ErrorTokenMalformed.
func IsErrorTokenMalformed(err error) bool {
	return err == ErrorTokenMalformed
}
