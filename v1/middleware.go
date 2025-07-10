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
}

func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doormanInfo := &Info{}

		for _, authn := range globalDoorman.loadedAuthenticators {
			if info, err := authn.Evaluate(r); err == nil {
				if info != nil {
					doormanInfo.Infos = append(doormanInfo.Infos, info)
					//for _, acl := range ep.aclList {
					//	eppInfo.ACLs[acl] = struct{}{}
					//}
				}
			} else {
				logger.Error("middleware error", "error", err)
			}
		}

		if globalDoorman.config.DebugLog {
			var debugLogArgs []any
			for _, info := range doormanInfo.Infos {
				debugLogArgs = append(debugLogArgs, "name", info.GetName())
				debugLogArgs = append(debugLogArgs, "type", info.GetType())
				debugLogArgs = append(debugLogArgs, "value", fmt.Sprintf("%+v", info))
			}
			logger.Debug("EPP_DEBUG: authenticators", "infos", debugLogArgs)
		}

		ctx := context.WithValue(r.Context(), doormanCtxKey, doormanInfo)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// InfoFromContext restores epp info from ctx
func InfoFromContext(ctx context.Context) (i *Info, err error) {
	var ok bool

	if i, ok = ctx.Value(doormanCtxKey).(*Info); !ok {
		err = fmt.Errorf("invalid doorman info in context")
	}

	return i, err
}
