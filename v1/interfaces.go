package doorman

import "net/http"

type Authenticator interface {
	GetName() string
	GetType() string
	Evaluate(r *http.Request) (AuthenticatorInfo, error)
}

type AuthenticatorInfo interface {
	GetName() string
	GetType() string
}
