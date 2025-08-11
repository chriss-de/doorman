package doorman

import "net/http"

type Authenticator interface {
	GetName() string
	GetType() string
	GetACLs() []string
	Evaluate(r *http.Request) (AuthenticatorInfo, error)
}

type AuthenticatorInfo interface {
	GetName() string
	GetType() string
}

type NewFunc func(epp *Doorman) error
type MiddlewareFunc func() *Doorman
type RegisterAuthenticatorFunc func(*AuthenticatorConfig) (Authenticator, error)
type HasherFunc func(string) string
