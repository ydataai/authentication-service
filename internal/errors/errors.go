package errors

import "errors"

var (
	// ErrTokenNotFound creates a new NotFound error.
	ErrTokenNotFound = errors.New("token not found")
	// ErrTokenExpired creates a new ErrTokenExpired error.
	ErrTokenExpired = errors.New("token expired")
	// ErrTokenInactiveYet creates a new ErrTokenInactiveYet error.
	ErrTokenInactiveYet = errors.New("token not active yet")
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
