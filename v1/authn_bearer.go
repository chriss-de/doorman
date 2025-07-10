package doorman

import (
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mitchellh/mapstructure"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
)

type bearerMetaData struct {
	JwksUri string `json:"jwks_uri"`
}

type ClaimValidation struct {
	Key      string  `mapstructure:"key"`
	Type     *string `mapstructure:"type"`
	Value    any     `mapstructure:"value"`
	Length   *int    `mapstructure:"length"`
	Contains any     `mapstructure:"contains"`
	//GreaterThan *int    `mapstructure:"gt"`
	//LessThan    *int    `mapstructure:"lt"`
}

type TokenAccessor map[string]string

type BearerAuthenticator struct {
	Name              string            `mapstructure:"name"`
	Type              string            `mapstructure:"type"`
	MetaUrl           string            `mapstructure:"meta_url"`
	JwksUrl           string            `mapstructure:"jwks_url"`
	KeysFetchInterval time.Duration     `mapstructure:"keys_fetch_interval"`
	ClaimsValidations []ClaimValidation `mapstructure:"claims_validations"`
	TokenAccessor     TokenAccessor     `mapstructure:"token_accessor"`
	httpClient        *http.Client
	bearerKeysManager *BearerKeyManager
}

type BearerAuthenticatorInfo struct {
	Authenticator *BearerAuthenticator
	TokenClaims   jwt.MapClaims
	Token         *jwt.Token
}

// NewBearerAuthenticator initialize
func NewBearerAuthenticator(name string, config map[string]interface{}) (authenticator Authenticator, err error) {
	var (
		decoder             *mapstructure.Decoder
		bearerAuthenticator *BearerAuthenticator
	)

	decoder, err = mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		DecodeHook: mapstructure.StringToTimeDurationHookFunc(),
		Result:     &bearerAuthenticator,
	})
	if err != nil {
		return nil, err
	}
	if err = decoder.Decode(config); err != nil {
		return nil, err
	}

	bearerAuthenticator.Name = name
	bearerAuthenticator.Type = "bearer"
	bearerAuthenticator.httpClient = &http.Client{}

	// sanity check
	if bearerAuthenticator.MetaUrl == "" && bearerAuthenticator.JwksUrl == "" {
		return nil, fmt.Errorf("need meta_url OR jwks_url")
	}
	if bearerAuthenticator.MetaUrl != "" && bearerAuthenticator.JwksUrl != "" {
		logger.Info("prefer meta_url over jwks_url")
	}

	// validation sanity check
	for _, cv := range bearerAuthenticator.ClaimsValidations {
		if cv.Key == "" {
			return nil, fmt.Errorf("claim validation needs a key")
		}
		if cv.Value == nil && cv.Type == nil && cv.Contains == nil && cv.Length == nil {
			return nil, fmt.Errorf("need at least one validation check")
		}
	}

	if bearerAuthenticator.MetaUrl != "" {
		if err = bearerAuthenticator.fetchMetaData(); err != nil {
			return nil, err
		}
	}

	//
	if bearerAuthenticator.KeysFetchInterval == 0 {
		bearerAuthenticator.KeysFetchInterval = 1 * time.Hour
	}

	bearerAuthenticator.bearerKeysManager, err = NewBearerKeyManager(bearerAuthenticator.Name, bearerAuthenticator.JwksUrl, bearerAuthenticator.KeysFetchInterval)
	if err != nil {
		return nil, err
	}

	return bearerAuthenticator, nil
}

// GetName returns Authenticator name
func (p *BearerAuthenticator) GetName() string {
	return p.Name
}

// GetType returns type
func (p *BearerAuthenticator) GetType() string {
	return p.Type
}

func (p *BearerAuthenticator) Evaluate(r *http.Request) (AuthenticatorInfo, error) {
	var (
		token       *jwt.Token
		tokenClaims = make(jwt.MapClaims)
		err         error
	)

	authHeaderValue := r.Header.Get("Authorization")
	if bearerValue, found := strings.CutPrefix(authHeaderValue, "Bearer "); found {
		// we dont fetch the error since it could be a token for another configuration
		// we check if the token is valid later
		token, _ = jwt.ParseWithClaims(bearerValue, &tokenClaims, p.bearerKeysManager.getSignatureKey)
		if token == nil {
			return nil, fmt.Errorf("no token")
		}
		if !token.Valid {
			return nil, fmt.Errorf("invalid bearer token")
		}
		if err = p.validateClaims(tokenClaims); err != nil {
			return nil, err
		}

		bpi := &BearerAuthenticatorInfo{Authenticator: p, TokenClaims: tokenClaims, Token: token}
		return bpi, nil

	}
	return nil, nil
}

func (p *BearerAuthenticator) validateClaims(tokenClaims jwt.MapClaims) error {
	for _, cv := range p.ClaimsValidations {
		v := getFromTokenPayload(cv.Key, tokenClaims)
		if v != nil {
			switch typedValue := v.(type) {
			case string:
				if cv.Value != nil && typedValue != cv.Value {
					return errorMessage(cv.Key, "value")
				}
				if cv.Length != nil && len(typedValue) != *cv.Length {
					return errorMessage(cv.Key, "length")
				}
				if cv.Type != nil && *cv.Type != "string" {
					return errorMessage(cv.Key, "type")
				}
				if cv.Contains != nil && strings.Contains(typedValue, fmt.Sprint(cv.Contains)) {
					return errorMessage(cv.Key, "contains")
				}
			case int, int8, int16, int32, int64, float32, float64:
				if cv.Value != nil && typedValue != cv.Value {
					return errorMessage(cv.Key, "value")
				}
				if cv.Type != nil && *cv.Type != "number" {
					return errorMessage(cv.Key, "type")
				}
			case []any:
				if cv.Length != nil && len(typedValue) != *cv.Length {
					return errorMessage(cv.Key, "length")
				}
				if cv.Type != nil && *cv.Type != "array" {
					return errorMessage(cv.Key, "type")
				}
				if cv.Contains != nil && !slices.Contains(typedValue, cv.Contains) {
					return errorMessage(cv.Key, "contains")
				}
			}
		} else {
			return errorMessage(cv.Key, "not found")
		}
	}
	return nil
}

// fetchMetaData fetches all values for IDP from metadata url
func (p *BearerAuthenticator) fetchMetaData() (err error) {
	var (
		request  *http.Request
		response *http.Response
		metaData bearerMetaData
	)

	if request, err = http.NewRequest("GET", p.MetaUrl, nil); err != nil {
		return err
	}
	if response, err = p.httpClient.Do(request); err != nil {
		return err
	}
	if response.Body != nil {
		defer func(Body io.ReadCloser) {
			_ = Body.Close()
		}(response.Body)
	}
	if response.StatusCode != 200 {
		return fmt.Errorf(response.Status)
	}
	if err = json.NewDecoder(response.Body).Decode(&metaData); err != nil {
		return err
	}

	p.JwksUrl = metaData.JwksUri

	return nil
}

func (b *BearerAuthenticatorInfo) mapKey(key string) string {
	keyResult := key

	if len(b.Authenticator.TokenAccessor) > 0 {
		if _, f := b.Authenticator.TokenAccessor[key]; f {
			keyResult = b.Authenticator.TokenAccessor[key]
		}
	}

	return keyResult
}

func (b *BearerAuthenticatorInfo) GetStringFromToken(key string) string {
	v := getFromTokenPayload(b.mapKey(key), b.TokenClaims)
	if vs, ok := v.(string); ok {
		return vs
	}
	return ""
}

func (b *BearerAuthenticatorInfo) GetValueFromToken(key string) any {
	return getFromTokenPayload(b.mapKey(key), b.TokenClaims)
}

func getFromTokenPayload(key string, t map[string]any) any {
	sKey := strings.Split(key, ".")
	for _, keyPart := range sKey {
		v, exists := t[keyPart]
		switch {
		case exists && len(sKey) == 1:
			return v
		case !exists:
			return nil
		default:
			newKey, _ := strings.CutPrefix(key, keyPart+".")
			return getFromTokenPayload(newKey, t)
		}
	}
	return nil
}

func errorMessage(key string, msg string) error {
	return fmt.Errorf("invalid claim for '%s' - %s", key, msg)
}

func (b *BearerAuthenticatorInfo) GetName() string {
	return b.Authenticator.GetName()
}

func (b *BearerAuthenticatorInfo) GetType() string {
	return b.Authenticator.GetType()
}
