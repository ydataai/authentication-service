package models

import (
	"encoding/json"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/oauth2"
)

// Tokens defines the token struct.
type Tokens struct {
	OAuth2Token   *oauth2.Token
	IDTokenClaims *json.RawMessage
	CustomClaims  CustomClaims
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

// TokenInfo defines a TokenInfo struct.
type TokenInfo struct {
	UID  string `json:"userid,omitempty"`
	Name string `json:"name,omitempty"`
}
