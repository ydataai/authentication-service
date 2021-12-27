package models

import (
	"encoding/json"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// Tokens defines the token struct.
type Tokens struct {
	IDTokenClaims *json.RawMessage
	CustomClaims  CustomClaims
}

// OAuth2Token defines the OAuth2Token struct.
type OAuth2Token struct {
	// AccessToken is the token that authorizes and authenticates the requests.
	AccessToken string `json:"access_token"`
	// TokenType is the type of token.
	// The Type method returns either this or "Bearer", the default.
	TokenType string `json:"token_type,omitempty"`
	// RefreshToken is a token that's used by the application
	// (as opposed to the user) to refresh the access token
	// if it expires.
	RefreshToken string `json:"refresh_token,omitempty"`
	// Expiry is the optional expiration time of the access token.
	//
	// If zero, TokenSource implementations will reuse the same
	// token forever and RefreshToken or equivalent
	// mechanisms for that TokenSource will not be used.
	Expiry time.Time `json:"expiry,omitempty"`
	// Raw optionally contains extra metadata from the server when updating a token.
	RawIDToken string `json:"id_token,omitempty"`
}

// CustomClaims defines the custom claims struct.
type CustomClaims struct {
	AccessToken string `json:"access_token,omitempty"`
	Name        string `json:"name,omitempty"`
	Email       string `json:"email,omitempty"`
	Profile     string `json:"profile,omitempty"`
	// The "aud" (audience) claim identifies the recipients that the JWT is intended for.
	// See more at: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
	Audience string `json:"aud,omitempty"`
	// The "sub" (subject) claim identifies the principal that is the subject of the JWT.
	// See more at: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
	Subject string `json:"sub,omitempty"`
	// RegisteredClaims are a structured version of the JWT Claims Set,
	// restricted to Registered Claim Names, as referenced at
	// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
	jwt.RegisteredClaims
}

// UserInfo defines a UserInfo struct.
type UserInfo struct {
	UID  string `json:"userid"`
	Name string `json:"name"`
}
