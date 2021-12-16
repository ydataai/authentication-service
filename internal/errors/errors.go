package errors

import "errors"

// ErrNotFound creates a new NotFound error.
var ErrNotFound = errors.New("not found")

// IsNotFound returns true if the specified error is an ErrNotFound.
func IsNotFound(err error) bool {
	return err == ErrNotFound
}
