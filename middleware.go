package gocloakchi

import (
	"net/http"
)

const (
	// KeyRealm is used as realm key constant
	KeyRealm = "realm"
)

// Authenticator is used to validate the JWT
type Authenticator interface {
	// DecodeAndValidateToken Decodes the token and checks if it is valid
	DecodeAndValidateToken(next http.Handler) http.Handler
	CheckToken(next http.Handler) http.Handler

	// CheckTokenCustomHeader The following 2 methods need higher permissions of the client in the realm
	CheckTokenCustomHeader(next http.Handler) http.Handler
	CheckScope(next http.Handler) http.Handler
	Protect(next http.Handler) http.Handler
	Enforcer(requestData *EnforcerConfig) func(next http.Handler) http.Handler
}
