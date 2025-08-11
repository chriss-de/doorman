package doorman

import (
	"context"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
)

func MustHasACL(ctx context.Context, acl string) bool {
	result, err := HasACL(ctx, acl)
	return err == nil && result
}

func HasACL(ctx context.Context, acl string) (bool, error) {
	i, err := InfoFromContext(ctx)
	if err != nil {
		return false, err
	}
	if _, has := i.ACLs[acl]; has {
		return true, nil
	}

	return false, nil
}

func MustHasACLs(ctx context.Context, acls []string) bool {
	result, err := HasACLs(ctx, acls)
	return err == nil && result
}

func HasACLs(ctx context.Context, acls []string) (bool, error) {
	i, err := InfoFromContext(ctx)
	if err != nil {
		return false, err
	}
	for _, acl := range acls {
		if _, has := i.ACLs[acl]; !has {
			return false, nil
		}
	}

	return true, nil
}

func NeedACL(acl string, func401 func(http.ResponseWriter, *http.Request)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			if MustHasACL(r.Context(), acl) {
				next.ServeHTTP(rw, r.WithContext(r.Context()))
			} else {
				func401(rw, r)
			}
		})
	}
}

func NeedACLs(acls []string, func401 func(http.ResponseWriter, *http.Request)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			if MustHasACLs(r.Context(), acls) {
				next.ServeHTTP(rw, r.WithContext(r.Context()))
			} else {
				func401(rw, r)
			}
		})
	}
}

func GetValueFromToken(ctx context.Context, key string) (any, error) {
	dm, err := InfoFromContext(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range dm.Infos {
		if pbi, ok := p.(*BearerAuthenticatorInfo); ok {
			return pbi.GetValueFromToken(key), nil
		}
	}

	return nil, fmt.Errorf("no token in request")
}

func GetStringFromToken(ctx context.Context, key string) (string, error) {
	epp, err := InfoFromContext(ctx)
	if err != nil {
		return "", err
	}
	for _, p := range epp.Infos {
		if pbi, ok := p.(*BearerAuthenticatorInfo); ok {
			return pbi.GetStringFromToken(key), nil
		}

	}
	return "", fmt.Errorf("no token in request")
}

func GetClaimsFromToken(ctx context.Context) (jwt.MapClaims, error) {
	epp, err := InfoFromContext(ctx)
	if err != nil {
		return nil, err
	}
	for _, p := range epp.Infos {
		if pbi, ok := p.(*BearerAuthenticatorInfo); ok {
			return pbi.TokenClaims, nil
		}
	}
	return nil, fmt.Errorf("no token in request")
}
