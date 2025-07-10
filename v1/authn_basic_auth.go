package doorman

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-viper/mapstructure/v2"
)

type BasicAuthCredential struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	Hashed   string `mapstructure:"hashed"`
	hasher   func(string) string
}

type BasicAuthAuthenticatorInfo struct {
	protector *BasicAuthAuthenticator
	Username  string
}

type BasicAuthAuthenticator struct {
	Name          string                `mapstructure:"name"`
	Type          string                `mapstructure:"type"`
	Credentials   []BasicAuthCredential `mapstructure:"credentials"`
	credentialMap map[string]int
}

func NewBasicAuthAuthenticator(name string, config map[string]interface{}) (authenticator Authenticator, err error) {
	var basicAuthAuthenticator *BasicAuthAuthenticator

	if err = mapstructure.Decode(config, &basicAuthAuthenticator); err != nil {
		return nil, err
	}
	basicAuthAuthenticator.Name = name
	basicAuthAuthenticator.Type = "basic"
	basicAuthAuthenticator.credentialMap = make(map[string]int)

	for credIdx, cred := range basicAuthAuthenticator.Credentials {
		var valid bool
		if basicAuthAuthenticator.Credentials[credIdx].hasher, valid = hashers[cred.Hashed]; !valid {
			return nil, fmt.Errorf("invalid hash algorithm: %s", cred.Hashed)
		}
		basicAuthAuthenticator.credentialMap[cred.Username] = credIdx
	}

	return basicAuthAuthenticator, err
}

// GetName returns protector name
func (p *BasicAuthAuthenticator) GetName() string {
	return p.Name
}

// GetType returns type
func (p *BasicAuthAuthenticator) GetType() string {
	return p.Type
}

func (p *BasicAuthAuthenticator) Evaluate(r *http.Request) (AuthenticatorInfo, error) {
	authHeaderValue := r.Header.Get("Authorization")
	if basicValue, found := strings.CutPrefix(authHeaderValue, "Basic "); found {
		// decode from base64
		decodedBasicValue, err := base64.StdEncoding.DecodeString(basicValue)
		if err != nil {
			return nil, err
		}
		creds := strings.Split(string(decodedBasicValue), ":")
		if len(creds) != 2 {
			return nil, fmt.Errorf("invalid basic auth value")
		}

		//
		username, password := creds[0], creds[1]
		if credIdx, found := p.credentialMap[username]; found {
			cred := p.Credentials[credIdx]

			if cred.hasher != nil {
				password = cred.hasher(password)
			}

			if password == cred.Password {
				bapi := &BasicAuthAuthenticatorInfo{protector: p, Username: username}

				return bapi, nil
			}
			return nil, nil
		}
	}
	return nil, nil
}

func (b BasicAuthAuthenticatorInfo) GetName() string {
	return b.protector.GetName()
}

func (b BasicAuthAuthenticatorInfo) GetType() string {
	return b.protector.GetType()
}
