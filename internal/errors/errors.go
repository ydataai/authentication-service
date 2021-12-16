package errors

import "errors"

var ErrNotFound = errors.New("token not found")

// IsNotFound returns true if the specified error is an ErrNotFound.
func IsNotFound(err error) bool {
	return err == ErrNotFound
}
