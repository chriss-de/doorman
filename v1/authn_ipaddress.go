package doorman

import (
	"fmt"
	"github.com/mitchellh/mapstructure"
	"net"
	"net/http"
	"strings"
)

type IPAddressAuthenticator struct {
	Name      string   `mapstructure:"name"`
	Type      string   `mapstructure:"type"`
	Addresses []string `mapstructure:"addresses"`
	addresses []*net.IPNet
}

type IPAddressAuthenticatorInfo struct {
	Authenticator  *IPAddressAuthenticator
	ClientIP       net.IP
	MatchedAddress *net.IPNet
}

// NewIPAddressAuthenticator initialize
func NewIPAddressAuthenticator(name string, config map[string]interface{}) (authenticator Authenticator, err error) {
	var ipAddressAuthenticator *IPAddressAuthenticator

	if err = mapstructure.Decode(config, &ipAddressAuthenticator); err != nil {
		return nil, err
	}
	ipAddressAuthenticator.Name = name
	ipAddressAuthenticator.Type = "ipaddress"

	for _, addr := range ipAddressAuthenticator.Addresses {
		if _, netAddr, aErr := net.ParseCIDR(addr); aErr != nil {
			return nil, err
		} else {
			ipAddressAuthenticator.addresses = append(ipAddressAuthenticator.addresses, netAddr)
		}
	}

	return ipAddressAuthenticator, err
}

// GetName returns Authenticator name
func (p *IPAddressAuthenticator) GetName() string {
	return p.Name
}

// GetType returns type
func (p *IPAddressAuthenticator) GetType() string {
	return p.Type
}

func (p *IPAddressAuthenticator) Evaluate(r *http.Request) (pi AuthenticatorInfo, err error) {
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

	for _, addr := range p.addresses {
		if addr.Contains(clientIp) {
			iapi := &IPAddressAuthenticatorInfo{Authenticator: p, ClientIP: clientIp, MatchedAddress: addr}
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
