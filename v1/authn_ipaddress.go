package doorman

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/mitchellh/mapstructure"
)

type IPAddressAuthenticator struct {
	Name      string   `mapstructure:"name"`
	Type      string   `mapstructure:"type"`
	Groups    []string `mapstructure:"groups"`
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
	var ipAddressAuthenticator *IPAddressAuthenticator

	if err = mapstructure.Decode(cfg.Config, &ipAddressAuthenticator); err != nil {
		return nil, err
	}
	ipAddressAuthenticator.Name = cfg.Name
	ipAddressAuthenticator.Type = "ipaddress"
	ipAddressAuthenticator.Groups = cfg.Groups

	for _, addr := range ipAddressAuthenticator.Addresses {
		if _, netAddr, aErr := net.ParseCIDR(addr); aErr != nil {
			return nil, err
		} else {
			ipAddressAuthenticator.addresses = append(ipAddressAuthenticator.addresses, netAddr)
		}
	}

	return ipAddressAuthenticator, err
}

func (a *IPAddressAuthenticator) GetName() string     { return a.Name }
func (a *IPAddressAuthenticator) GetType() string     { return a.Type }
func (a *IPAddressAuthenticator) GetGroups() []string { return a.Groups }

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
