package doorman

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/golang-jwt/jwt/v5"
)

type bearerMetaData struct {
	JwksUri string `json:"jwks_uri"`
}

type ValidationOperation struct {
	Operation string `json:"operation"`
	Value     any    `json:"value"`
}

type ClaimValidation struct {
	Key                 string               `mapstructure:"key"`
	IsOptional          bool                 `mapstructure:"optional"`
	ValidationOperation *ValidationOperation `mapstructure:"validation"`
	DynamicACLS         []string             `mapstructure:"dynamic_acls"`
}

type TokenKeyAliases map[string]string

type ClaimsValidationGroup struct {
	ClaimsValidations []ClaimValidation `mapstructure:"claims_validations"`
	TokenKeyAliases   TokenKeyAliases   `mapstructure:"token_key_aliases"`
	TokenMapACLs      []string          `mapstructure:"token_map_acls"`
}

type BearerAuthenticator struct {
	Name              string        `mapstructure:"name"`
	Type              string        `mapstructure:"type"`
	ACLs              []string      `mapstructure:"acls"`
	MetaUrl           string        `mapstructure:"meta_url"`
	JwksUrl           string        `mapstructure:"jwks_url"`
	KeysFetchInterval time.Duration `mapstructure:"keys_fetch_interval"`
	// _
	ClaimsValidationGroups []*ClaimsValidationGroup `mapstructure:"claims_validation_groups"`
	// _
	ClaimsValidations []ClaimValidation `mapstructure:"claims_validations"`
	TokenKeyAliases   TokenKeyAliases   `mapstructure:"token_key_aliases"`
	TokenMapACLs      []string          `mapstructure:"token_map_acls"`
	// ____
	httpClient        *http.Client
	bearerKeysManager *BearerKeyManager
}

type BearerAuthenticatorInfo struct {
	Authenticator *BearerAuthenticator
	profile       *ClaimsValidationGroup
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
		DecodeHook:  mapstructure.StringToTimeDurationHookFunc(),
		ErrorUnused: true,
		Result:      &bearerAuthenticator,
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

	if len(bearerAuthenticator.ClaimsValidations) > 0 {
		p := &ClaimsValidationGroup{
			ClaimsValidations: bearerAuthenticator.ClaimsValidations,
			TokenKeyAliases:   bearerAuthenticator.TokenKeyAliases,
			TokenMapACLs:      bearerAuthenticator.TokenMapACLs,
		}
		bearerAuthenticator.ClaimsValidationGroups = slices.Insert(bearerAuthenticator.ClaimsValidationGroups, 0, p)
	}

	// validation sanity check
	if len(bearerAuthenticator.ClaimsValidationGroups) == 0 {
		return nil, fmt.Errorf("needs claims_validations")
	}
	for idx, profile := range bearerAuthenticator.ClaimsValidationGroups {
		for _, cv := range profile.ClaimsValidations {
			if cv.Key == "" {
				return nil, fmt.Errorf("claim validation needs a key in group %d", idx)
			}
			if cv.ValidationOperation == nil || cv.ValidationOperation.Operation == "" {
				return nil, fmt.Errorf("claim validation needs a validation operation in group %d", idx)
			}
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
	)

	authHeaderValue := r.Header.Get("Authorization")
	if bearerValue, found := strings.CutPrefix(authHeaderValue, "Bearer "); found {
		// we dont fetch the error since it could be a token for another configuration
		// we check if the token is valid later
		token, _ = jwt.ParseWithClaims(bearerValue, &tokenClaims, a.bearerKeysManager.getSignatureKey)
		if token == nil {
			logger.Info("no token found in bearer header")
			return nil, nil
		}
		if !token.Valid {
			logger.Info("invalid token in bearer header")
			return nil, nil
		}

		for idx, profile := range a.ClaimsValidationGroups {
			vr, err := a.validateClaimsForGroup(profile, idx, tokenClaims)
			if err != nil {
				logger.Info("group validation failed with error", "idx", idx, "err", err)
				continue
			}
			if !vr {
				logger.Debug("group validation returned false", "idx", idx)
				continue
			}
			if err = a.tokenMapACLs(profile, tokenClaims); err != nil {
				return nil, err
			}

			bpi := &BearerAuthenticatorInfo{Authenticator: a, profile: profile, TokenClaims: tokenClaims, Token: token}
			return bpi, nil
		}
	}
	return nil, nil
}

func (a *BearerAuthenticator) tokenMapACLs(profile *ClaimsValidationGroup, tokenClaims jwt.MapClaims) error {
	for _, key := range profile.TokenMapACLs {
		tokenVal := getFromTokenPayload(profile.mapKey(key), tokenClaims)
		switch anyVal := tokenVal.(type) {
		case []any:
			for _, arrVal := range anyVal {
				if err := a.tokenMapACL(arrVal); err != nil {
					return err
				}
			}
		case any:
			if err := a.tokenMapACL(anyVal); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported token value for ACL mapping. %T", anyVal)
		}
	}
	return nil
}

func (a *BearerAuthenticator) tokenMapACL(aVal any) error {
	switch val := aVal.(type) {
	case string:
		a.ACLs = append(a.ACLs, val)
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		a.ACLs = append(a.ACLs, fmt.Sprintf("%d", val))
	case float32, float64:
		a.ACLs = append(a.ACLs, fmt.Sprintf("%f", val))
	default:
		return fmt.Errorf("unsupported token content value for ACL mapping. %T", val)
	}
	return nil
}

func (a *BearerAuthenticator) validateClaimsForGroup(group *ClaimsValidationGroup, idx int, tokenClaims jwt.MapClaims) (bool, error) {
	for _, cv := range group.ClaimsValidations {
		tokenValue := getFromTokenPayload(cv.Key, tokenClaims)
		if tokenValue != nil {
			result, err := processValidationOperation(cv.ValidationOperation, tokenValue)
			if err != nil {
				return false, fmt.Errorf("validation failed for group %d and key %s: %w", idx, cv.Key, err)
			}
			if !result {
				logger.Debug("validation returned false", "group", idx, "key", cv.Key, "optional", cv.IsOptional, "operation", cv.ValidationOperation.Operation, "tokenValue", tokenValue)
				if cv.IsOptional {
					continue
				}
				return false, nil
			}

			if len(cv.DynamicACLS) > 0 {
				a.ACLs = append(a.ACLs, cv.DynamicACLS...)
			}
			return true, nil
		} else if !cv.IsOptional {
			return false, fmt.Errorf("invalid claim. key '%s' not found", cv.Key)
		}
	}
	return false, fmt.Errorf("no claim validation succeded for group %d", idx)
}

// fetchMetaData fetches all values for IDP from metadata url
func (a *BearerAuthenticator) fetchMetaData() (err error) {
	var (
		request  *http.Request
		response *http.Response
		metaData bearerMetaData
	)

	if request, err = http.NewRequest(http.MethodGet, a.MetaUrl, nil); err != nil {
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

func (a *ClaimsValidationGroup) mapKey(key string) string {
	keyResult := key

	if len(a.TokenKeyAliases) > 0 {
		if _, f := a.TokenKeyAliases[key]; f {
			keyResult = a.TokenKeyAliases[key]
		}
	}

	return keyResult
}

func (i *BearerAuthenticatorInfo) mapKey(key string) string {
	return i.profile.mapKey(key)
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

func (i *BearerAuthenticatorInfo) GetName() string {
	return i.Authenticator.GetName()
}

func (i *BearerAuthenticatorInfo) GetType() string {
	return i.Authenticator.GetType()
}
