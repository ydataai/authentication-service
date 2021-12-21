package models

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// Session is a struct to temporarily saving state and nonce.
type Session struct {
	// State is there to protect the end user from cross site request forgery(CSRF) attacks.
	// It is introduced from OAuth 2.0 protocol RFC6749 (https://www.rfc-editor.org/rfc/rfc6749#section-10.12).
	// Protocol states that:
	// Once authorization has been obtained from the end-user, the authorization server redirects
	// the end-user's user-agent back to the client with the required binding value contained in
	// the "state" parameter. The binding value enables the client to verify the validity of the
	// request by matching the binding value to the user-agent's authenticated state.
	State string

	// Nonce serves as a token validation parameter and is introduced from OIDC specification.
	// https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowSteps
	// According to Google, you should enforce protection against replay attacks by ensuring
	// it is presented only once.
	Nonce string
}

// CreateSession creates a new session.
func CreateSession() (Session, error) {
	state, err := randomString(16)
	if err != nil {
		return Session{}, fmt.Errorf("an error occurred while creating a temporary state. Error: %v", err)
	}
	nonce, err := randomString(16)
	if err != nil {
		return Session{}, fmt.Errorf("an error occurred while creating a temporary nonce. Error: %v", err)
	}

	return Session{
		State: state,
		Nonce: nonce,
	}, nil
}

// MatchNonce matches the nonce saved earlier with the nonce claim of the ID Token.
func (s Session) MatchNonce(nonce string) bool {
	return nonce == s.Nonce
}

// randomString creates a random string and does a base64 encoding.
func randomString(nByte int) (string, error) {
	b := make([]byte, nByte)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
