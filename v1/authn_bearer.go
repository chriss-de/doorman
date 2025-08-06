package doorman

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/golang-jwt/jwt/v5"
)

type bearerMetaData struct {
	JwksUri string `json:"jwks_uri"`
}

type ValidationOperation struct {
	Operation  string `json:"operation"`
	Value      any    `json:"value"`
	IsOptional bool   `json:"optional"`
}

type ClaimValidation struct {
	Key         string                 `mapstructure:"key"`
	IsOptional  bool                   `mapstructure:"optional"`
	Validations []*ValidationOperation `mapstructure:"validations"`
	DynamicACLS []string               `mapstructure:"dynamic_acls"`
}

type TokenKeyAliases map[string]string

type BearerAuthenticator struct {
	Name              string            `mapstructure:"name"`
	Type              string            `mapstructure:"type"`
	ACLs              []string          `mapstructure:"acls"`
	MetaUrl           string            `mapstructure:"meta_url"`
	JwksUrl           string            `mapstructure:"jwks_url"`
	KeysFetchInterval time.Duration     `mapstructure:"keys_fetch_interval"`
	ClaimsValidations []ClaimValidation `mapstructure:"claims_validations"`
	TokenKeyAliases   TokenKeyAliases   `mapstructure:"token_key_aliases"`
	TokenMapACLs      []string          `mapstructure:"token_map_acls"`
	httpClient        *http.Client
	bearerKeysManager *BearerKeyManager
}

type BearerAuthenticatorInfo struct {
	Authenticator *BearerAuthenticator
	TokenClaims   jwt.MapClaims
	Token         *jwt.Token
}

// NewBearerAuthenticator initialize
func NewBearerAuthenticator(cfg *AuthenticatorConfig) (authenticator Authenticator, err error) {
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
	if err = decoder.Decode(cfg.Config); err != nil {
		return nil, err
	}

	bearerAuthenticator.Name = cfg.Name
	bearerAuthenticator.Type = "bearer"
	bearerAuthenticator.ACLs = cfg.ACLs
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
		if len(cv.Validations) == 0 {
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

func (a *BearerAuthenticator) GetName() string   { return a.Name }
func (a *BearerAuthenticator) GetType() string   { return a.Type }
func (a *BearerAuthenticator) GetACLs() []string { return a.ACLs }

func (a *BearerAuthenticator) Evaluate(r *http.Request) (AuthenticatorInfo, error) {
	var (
		token       *jwt.Token
		tokenClaims = make(jwt.MapClaims)
		err         error
	)

	authHeaderValue := r.Header.Get("Authorization")
	if bearerValue, found := strings.CutPrefix(authHeaderValue, "Bearer "); found {
		// we dont fetch the error since it could be a token for another configuration
		// we check if the token is valid later
		token, _ = jwt.ParseWithClaims(bearerValue, &tokenClaims, a.bearerKeysManager.getSignatureKey)
		if token == nil {
			return nil, fmt.Errorf("no token")
		}
		if !token.Valid {
			return nil, fmt.Errorf("invalid bearer token")
		}
		if err = a.validateClaims(tokenClaims); err != nil {
			return nil, err
		}
		if err = a.tokenMapACLs(tokenClaims); err != nil {
			return nil, err
		}

		bpi := &BearerAuthenticatorInfo{Authenticator: a, TokenClaims: tokenClaims, Token: token}
		return bpi, nil

	}
	return nil, nil
}

func (a *BearerAuthenticator) tokenMapACLs(tokenClaims jwt.MapClaims) error {
	for _, key := range a.TokenMapACLs {
		anyVal := getFromTokenPayload(a.mapKey(key), tokenClaims)
		switch val := anyVal.(type) {
		case string:
			a.ACLs = append(a.ACLs, val)
		case []string:
			a.ACLs = append(a.ACLs, val...)
		case int:
			a.ACLs = append(a.ACLs, strconv.Itoa(val))
		case []int:
			for _, i := range val {
				a.ACLs = append(a.ACLs, strconv.Itoa(i))
			}
		case map[string]any:
			for k := range val {
				a.ACLs = append(a.ACLs, k)
			}
		default:
			return fmt.Errorf("unsupported token value for ACL mapping. %T", val)
		}
	}
	return nil
}

func (a *BearerAuthenticator) validateClaims(tokenClaims jwt.MapClaims) error {
	for _, cv := range a.ClaimsValidations {
		v := getFromTokenPayload(cv.Key, tokenClaims)
		if v != nil {
			for _, validation := range cv.Validations {
				if cvo, found := claimValidationOperations[validation.Operation]; found {
					result, err := cvo(validation, v)
					if err != nil {
						return err
					}
					if !result && !validation.IsOptional {
						return fmt.Errorf("error: %s failed for %v with %s", validation.Operation, v, validation.Value)
					}
				} else {
					return fmt.Errorf("invalid validation: %s", validation.Operation)
				}
			}
			if len(cv.DynamicACLS) > 0 {
				a.ACLs = append(a.ACLs, cv.DynamicACLS...)
			}
		} else if !cv.IsOptional {
			return errorMessage(cv.Key, "not found")
		}
	}
	return nil
}

// fetchMetaData fetches all values for IDP from metadata url
func (a *BearerAuthenticator) fetchMetaData() (err error) {
	var (
		request  *http.Request
		response *http.Response
		metaData bearerMetaData
	)

	if request, err = http.NewRequest("GET", a.MetaUrl, nil); err != nil {
		return err
	}
	if response, err = a.httpClient.Do(request); err != nil {
		return err
	}
	if response.Body != nil {
		defer func(Body io.ReadCloser) {
			_ = Body.Close()
		}(response.Body)
	}
	if response.StatusCode != 200 {
		return fmt.Errorf("error: %s", response.Status)
	}
	if err = json.NewDecoder(response.Body).Decode(&metaData); err != nil {
		return err
	}

	a.JwksUrl = metaData.JwksUri

	return nil
}

func (a *BearerAuthenticator) mapKey(key string) string {
	keyResult := key

	if len(a.TokenKeyAliases) > 0 {
		if _, f := a.TokenKeyAliases[key]; f {
			keyResult = a.TokenKeyAliases[key]
		}
	}

	return keyResult
}

func (i *BearerAuthenticatorInfo) mapKey(key string) string {
	return i.Authenticator.mapKey(key)
}

func (i *BearerAuthenticatorInfo) GetStringFromToken(key string) string {
	v := getFromTokenPayload(i.mapKey(key), i.TokenClaims)
	if vs, ok := v.(string); ok {
		return vs
	}
	return ""
}

func (i *BearerAuthenticatorInfo) GetValueFromToken(key string) any {
	return getFromTokenPayload(i.mapKey(key), i.TokenClaims)
}

func getFromTokenPayload(key string, t map[string]any) any {
	sKey := strings.SplitN(key, ".", 2)
	if v, exists := t[sKey[0]]; exists {
		if len(sKey) > 1 {
			if vv, ok := v.(map[string]any); ok {
				return getFromTokenPayload(sKey[1], vv)
			}
		} else {
			return v
		}
	}
	return nil
}

func errorMessage(key string, msg string) error {
	return fmt.Errorf("invalid claim for '%s' - %s", key, msg)
}

func (i *BearerAuthenticatorInfo) GetName() string {
	return i.Authenticator.GetName()
}

func (i *BearerAuthenticatorInfo) GetType() string {
	return i.Authenticator.GetType()
}
