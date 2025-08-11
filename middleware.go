package doorman

import (
	"context"
	"fmt"
	"net/http"
)

type contextKey struct {
	name string
}

var doormanCtxKey = &contextKey{"doorman"}

type Info struct {
	Infos []AuthenticatorInfo
	ACLs  map[string]struct{}
}

func Middleware(opts ...MiddlewareFunc) func(http.Handler) http.Handler {
	var doormans []*Doorman
	for _, opt := range opts {
		doormans = append(doormans, opt())
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			doormanInfo := &Info{ACLs: make(map[string]struct{})}

			for _, doorman := range doormans {
				for _, authn := range doorman.loadedAuthenticators {
					if info, err := authn.Evaluate(r); err == nil {
						if info != nil {
							doormanInfo.Infos = append(doormanInfo.Infos, info)
							for _, group := range authn.GetACLs() {
								doormanInfo.ACLs[group] = struct{}{}
							}
						}
					} else {
						logger.Error("middleware error", "error", err)
					}
				}
			}

			var debugLogArgs []any
			for _, info := range doormanInfo.Infos {
				debugLogArgs = append(debugLogArgs, "name", info.GetName())
				debugLogArgs = append(debugLogArgs, "type", info.GetType())
				debugLogArgs = append(debugLogArgs, "value", fmt.Sprintf("%+v", info))
			}
			logger.Debug("DOORMAN_DEBUG: authenticators", "infos", debugLogArgs)

			ctx := context.WithValue(r.Context(), doormanCtxKey, doormanInfo)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func WithMiddlewareUseDoorman(dm *Doorman) func() *Doorman {
	return func() *Doorman { return dm }
}

func WithMiddlewareUseGlobalDoorman() func() *Doorman {
	return func() *Doorman { return globalDoorman }
}

// InfoFromContext restores doorman info from ctx
func InfoFromContext(ctx context.Context) (i *Info, err error) {
	var ok bool

	if i, ok = ctx.Value(doormanCtxKey).(*Info); !ok {
		err = fmt.Errorf("invalid doorman info in context")
	}

	return i, err
}
