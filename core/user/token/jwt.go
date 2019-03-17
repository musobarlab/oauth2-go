package token

import (
	"crypto/rsa"
	"time"

	"github.com/dgrijalva/jwt-go"
)

// Claim data structure
type Claim struct {
	Issuer   string
	Audience string
	Subject  string
	Email    string
}

// AccessToken data structure
type AccessToken struct {
	AccessToken string
	ExpiredAt   time.Time
}

// AccessTokenResponse data structure
type AccessTokenResponse struct {
	Error       error
	AccessToken AccessToken
}

// jwtGenerator private data structure
type jwtGenerator struct {
	signKey  *rsa.PrivateKey
	tokenAge time.Duration
}

// AccessTokenGenerator interface abstraction
type AccessTokenGenerator interface {
	GenerateAccessToken(cl Claim) <-chan AccessTokenResponse
}

// NewJwtGenerator function for initializing jwtGenerator object
func NewJwtGenerator(signKey *rsa.PrivateKey, tokenAge time.Duration) AccessTokenGenerator {
	return &jwtGenerator{
		signKey:  signKey,
		tokenAge: tokenAge,
	}
}

// GenerateAccessToken function for generating access token
func (j *jwtGenerator) GenerateAccessToken(cl Claim) <-chan AccessTokenResponse {
	result := make(chan AccessTokenResponse)
	go func() {
		defer close(result)

		now := time.Now()
		age := now.Add(j.tokenAge)

		token := jwt.New(jwt.SigningMethodRS256)
		claims := make(jwt.MapClaims)
		claims["iss"] = cl.Issuer
		claims["aud"] = cl.Audience
		claims["exp"] = age.Unix()
		claims["iat"] = now.Unix()
		claims["sub"] = cl.Subject
		claims["email"] = cl.Email
		token.Claims = claims

		tokenString, err := token.SignedString(j.signKey)
		if err != nil {
			result <- AccessTokenResponse{Error: err}
			return
		}
		result <- AccessTokenResponse{Error: nil, AccessToken: AccessToken{AccessToken: tokenString, ExpiredAt: age}}
	}()

	return result
}
