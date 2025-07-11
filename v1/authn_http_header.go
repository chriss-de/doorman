package doorman

import (
	"fmt"
	"net/http"

	"github.com/go-viper/mapstructure/v2"
)

type HttpHeader struct {
	Name   string `mapstructure:"name"`
	Value  string `mapstructure:"value"`
	Hashed string `mapstructure:"hashed"`
	hasher func(string) string
}

type HttpHeaderAuthenticatorInfo struct {
	Authenticator *HttpHeaderAuthenticator
	ApiKeyValue   string
}

type HttpHeaderAuthenticator struct {
	Name       string       `mapstructure:"name"`
	Type       string       `mapstructure:"type"`
	Groups     []string     `mapstructure:"groups"`
	Headers    []HttpHeader `mapstructure:"headers"`
	headersMap map[string]int
}

// NewHttpHeaderAuthenticator initialize
func NewHttpHeaderAuthenticator(cfg *AuthenticatorConfig) (authenticator Authenticator, err error) {
	var httpHeaderAuthenticator *HttpHeaderAuthenticator

	if err = mapstructure.Decode(cfg.Config, &httpHeaderAuthenticator); err != nil {
		return nil, err
	}
	httpHeaderAuthenticator.Name = cfg.Name
	httpHeaderAuthenticator.Type = "http_header"
	httpHeaderAuthenticator.Groups = cfg.Groups
	httpHeaderAuthenticator.headersMap = make(map[string]int)

	for idx, header := range httpHeaderAuthenticator.Headers {
		if header.Hashed != "" {
			var valid bool
			if httpHeaderAuthenticator.Headers[idx].hasher, valid = hashers[header.Hashed]; !valid {
				return nil, fmt.Errorf("invalid hash algorithm: %s", header.Hashed)
			}
		}
		httpHeaderAuthenticator.headersMap[header.Name] = idx
	}

	return httpHeaderAuthenticator, err
}

func (a *HttpHeaderAuthenticator) GetName() string     { return a.Name }
func (a *HttpHeaderAuthenticator) GetType() string     { return a.Type }
func (a *HttpHeaderAuthenticator) GetGroups() []string { return a.Groups }

func (a *HttpHeaderAuthenticator) Evaluate(r *http.Request) (AuthenticatorInfo, error) {
	for headerName, idx := range a.headersMap {
		headerValue := r.Header.Get(headerName)
		if headerValue != "" {
			httpHeader := a.Headers[idx]
			if httpHeader.hasher != nil {
				headerValue = httpHeader.hasher(headerValue)
			}
			if headerValue == httpHeader.Value {
				akpi := &HttpHeaderAuthenticatorInfo{Authenticator: a, ApiKeyValue: headerValue}
				return akpi, nil
			}
		}
	}
	return nil, nil
}

func (i *HttpHeaderAuthenticatorInfo) GetName() string {
	return i.Authenticator.GetName()
}

func (i *HttpHeaderAuthenticatorInfo) GetType() string {
	return i.Authenticator.GetType()
}
