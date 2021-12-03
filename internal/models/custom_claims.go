package models

// CustomClaims defines the custom claims struct
type CustomClaims struct {
	Name          string `json:"name"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified" default:"false"`
	Picture       string `json:"picture"`
	Expiry        int64  `json:"exp"`
	IssuedAt      int64  `json:"iat"`
}
