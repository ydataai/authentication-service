package errors

import "errors"

var (
	// ErrNotFound creates a new NotFound error.
	ErrNotFound = errors.New("token not found")
	// ErrTokenExpired creates a new ErrTokenExpired error.
	ErrTokenExpired = errors.New("token expired")
	// ErrTokenInactiveYet creates a new ErrTokenInactiveYet error.
	ErrTokenInactiveYet = errors.New("token not active yet")
)

// IsNotFound returns true if the specified error is an ErrNotFound.
func IsNotFound(err error) bool {
	return err == ErrNotFound
}

// IsTokenExpired returns true if the specified error is an ErrTokenExpired.
func IsTokenExpired(err error) bool {
	return err == ErrTokenExpired
}

// IsTokenInactiveYet returns true if the specified error is an ErrTokenInactiveYet.
func IsTokenInactiveYet(err error) bool {
	return err == ErrTokenInactiveYet
}
