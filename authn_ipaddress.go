package doorman

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/go-viper/mapstructure/v2"
)

type IPAddressAuthenticator struct {
	Name      string   `mapstructure:"name"`
	Type      string   `mapstructure:"type"`
	ACLs      []string `mapstructure:"acls"`
	Addresses []string `mapstructure:"addresses"`
	addresses []*net.IPNet
}

type IPAddressAuthenticatorInfo struct {
	Authenticator  *IPAddressAuthenticator
	ClientIP       net.IP
	MatchedAddress *net.IPNet
}

// NewIPAddressAuthenticator initialize
func NewIPAddressAuthenticator(cfg *AuthenticatorConfig) (authenticator Authenticator, err error) {
	var (
		decoder                *mapstructure.Decoder
		ipAddressAuthenticator *IPAddressAuthenticator
	)

	decoder, err = mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		ErrorUnused: true,
		Result:      &ipAddressAuthenticator,
	})
	if err != nil {
		return nil, err
	}
	if err = decoder.Decode(cfg.Config); err != nil {
		return nil, err
	}

	ipAddressAuthenticator.Name = cfg.Name
	ipAddressAuthenticator.Type = "ipaddress"
	ipAddressAuthenticator.ACLs = cfg.ACLs

	for _, addr := range ipAddressAuthenticator.Addresses {
		if _, netAddr, aErr := net.ParseCIDR(addr); aErr != nil {
			return nil, err
		} else {
			ipAddressAuthenticator.addresses = append(ipAddressAuthenticator.addresses, netAddr)
		}
	}

	return ipAddressAuthenticator, err
}

func (a *IPAddressAuthenticator) GetName() string   { return a.Name }
func (a *IPAddressAuthenticator) GetType() string   { return a.Type }
func (a *IPAddressAuthenticator) GetACLs() []string { return a.ACLs }

func (a *IPAddressAuthenticator) Evaluate(r *http.Request) (pi AuthenticatorInfo, err error) {
	remoteAddr := r.RemoteAddr
	if strings.Contains(remoteAddr, ":") {
		if remoteAddr, _, err = net.SplitHostPort(r.RemoteAddr); err != nil {
			return nil, err
		}
	}
	clientIp := net.ParseIP(remoteAddr)
	if clientIp == nil {
		return nil, fmt.Errorf("clientIp is invalid")
	}

	for _, addr := range a.addresses {
		if addr.Contains(clientIp) {
			iapi := &IPAddressAuthenticatorInfo{Authenticator: a, ClientIP: clientIp, MatchedAddress: addr}
			return iapi, nil
		}
	}

	return nil, nil
}

func (i IPAddressAuthenticatorInfo) GetName() string {
	return i.Authenticator.GetName()
}

func (i IPAddressAuthenticatorInfo) GetType() string {
	return i.Authenticator.GetType()
}
