package models

import "golang.org/x/oauth2"

// Tokens defines the token struct
type Tokens struct {
	OAuth2Token  *oauth2.Token
	CustomClaims CustomClaims
}

// CustomClaims defines the custom claims struct
type CustomClaims struct {
	Name          string `json:"name"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified" default:"false"`
	Picture       string `json:"picture"`
	Expiry        int64  `json:"exp"`
	IssuedAt      int64  `json:"iat"`
}
