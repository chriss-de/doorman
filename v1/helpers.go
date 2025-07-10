package doorman

import (
	"context"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

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
