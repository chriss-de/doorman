package doorman

import (
	"fmt"
	"net/http"

	"github.com/go-viper/mapstructure/v2"
)

type HttpHeader struct {
	Name            string   `mapstructure:"name"`
	Value           string   `mapstructure:"value"`
	Hashed          string   `mapstructure:"hashed"`
	CapturedHeaders []string `mapstructure:"capture_headers"`
	DynamicACLS     []string `mapstructure:"dynamic_acls"`
	hasher          func(string) string
}

type HttpHeaderAuthenticatorInfo struct {
	Authenticator   *HttpHeaderAuthenticator
	CapturedHeaders map[string]string
}

type HttpHeaderAuthenticator struct {
	Name       string       `mapstructure:"name"`
	Type       string       `mapstructure:"type"`
	ACLs       []string     `mapstructure:"acls"`
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
	httpHeaderAuthenticator.ACLs = cfg.ACLs
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

func (a *HttpHeaderAuthenticator) GetName() string   { return a.Name }
func (a *HttpHeaderAuthenticator) GetType() string   { return a.Type }
func (a *HttpHeaderAuthenticator) GetACLs() []string { return a.ACLs }

func (a *HttpHeaderAuthenticator) Evaluate(r *http.Request) (AuthenticatorInfo, error) {
	for headerName, idx := range a.headersMap {
		headerValue := r.Header.Get(headerName)
		if headerValue != "" {
			httpHeader := a.Headers[idx]
			if httpHeader.hasher != nil {
				headerValue = httpHeader.hasher(headerValue)
			}
			if headerValue == httpHeader.Value {
				hhai := &HttpHeaderAuthenticatorInfo{Authenticator: a, CapturedHeaders: make(map[string]string)}
				for _, header := range httpHeader.CapturedHeaders {
					cHeaderValue := ""
					cHeaders := r.Header[header]
					if len(cHeaders) > 0 {
						cHeaderValue = cHeaders[0]
					}
					hhai.CapturedHeaders[header] = cHeaderValue
				}
				if len(httpHeader.DynamicACLS) > 0 {
					a.ACLs = append(a.ACLs, httpHeader.DynamicACLS...)
				}
				return hhai, nil
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
