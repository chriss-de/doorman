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
	Authenticator    *HttpHeaderAuthenticator
	ApiKeyValue      string
	PopulatedHeaders map[string]string
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
		var valid bool
		if httpHeaderAuthenticator.Headers[idx].hasher, valid = hashers[header.Hashed]; !valid {
			return nil, fmt.Errorf("invalid hash algorithm: %s", header.Hashed)
		}
		httpHeaderAuthenticator.headersMap[header.Name] = idx
	}

	return httpHeaderAuthenticator, err
}

func (p *HttpHeaderAuthenticator) GetName() string     { return p.Name }
func (p *HttpHeaderAuthenticator) GetType() string     { return p.Type }
func (p *HttpHeaderAuthenticator) GetGroups() []string { return p.Groups }

func (p *HttpHeaderAuthenticator) Evaluate(r *http.Request) (AuthenticatorInfo, error) {
	for headerName, idx := range p.headersMap {
		headerValue := r.Header.Get(headerName)
		if headerValue != "" {
			httpHeader := p.Headers[idx]
			if httpHeader.hasher != nil {
				headerValue = httpHeader.hasher(headerValue)
			}
			if headerValue == httpHeader.Value {
				akpi := &HttpHeaderAuthenticatorInfo{Authenticator: p, PopulatedHeaders: make(map[string]string), ApiKeyValue: headerValue}
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
