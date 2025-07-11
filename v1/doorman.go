package doorman

import (
	"fmt"
)

var (
	globalDoorman *Doorman
	logger        Logger                         = &NullLogger{}
	hashers       map[string]func(string) string = map[string]func(string) string{
		"md5":    stringHashMd5,
		"sha1":   stringHashSha1,
		"sha256": stringHashSha256,
	}
)

// NewDoorman init
func NewDoorman(opts ...func(dm *Doorman)) (dm *Doorman, err error) {
	dm = &Doorman{
		debugLog:                 false,
		registeredAuthenticators: make(map[string]func(*AuthenticatorConfig) (Authenticator, error)),
		configuredAuthenticators: make([]*AuthenticatorConfig, 0),
	}

	// register Authenticators
	dm.registeredAuthenticators["basic"] = NewBasicAuthAuthenticator
	dm.registeredAuthenticators["http_header"] = NewHttpHeaderAuthenticator
	dm.registeredAuthenticators["ipaddress"] = NewIPAddressAuthenticator
	dm.registeredAuthenticators["bearer"] = NewBearerAuthenticator

	for _, opt := range opts {
		opt(dm)
	}

	if err = dm.loadAuthenticators(); err != nil {
		return nil, err
	}

	return dm, nil
}

// NewEndpointProtector loads all supported endpoint authenticators from authenticatorsConfig
func (dm *Doorman) loadAuthenticators() (err error) {
	dm.authenticatorsIdMap = make(map[string]int)

	for _, authnConfig := range dm.configuredAuthenticators {
		var a Authenticator

		if authenticatorInitFunc, found := dm.registeredAuthenticators[authnConfig.Type]; found {
			if a, err = authenticatorInitFunc(authnConfig); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("no such authenticator")
		}

		//---------
		if a != nil {
			if _, ok := dm.authenticatorsIdMap[a.GetName()]; !ok {
				dm.loadedAuthenticators = append(dm.loadedAuthenticators, a)
				dm.authenticatorsIdMap[a.GetName()] = len(dm.loadedAuthenticators) - 1
			} else {
				return fmt.Errorf("duplicated name in authenticatorsConfigs. '%s'", a.GetName())
			}
		}
	}
	return nil
}

func WithAuthenticatorConfigs(configs []*AuthenticatorConfig) func(dm *Doorman) {
	return func(dm *Doorman) {
		dm.configuredAuthenticators = configs
	}
}

func RegisterNewAuthenticator(name string, initFunc func(*AuthenticatorConfig) (Authenticator, error)) func(dm *Doorman) {
	return func(dm *Doorman) {
		dm.registeredAuthenticators[name] = initFunc
	}
}

func AsGlobalDefault() func(dm *Doorman) {
	return func(dm *Doorman) {
		globalDoorman = dm
	}
}

func WithDebugLog() func(dm *Doorman) {
	return func(dm *Doorman) {
		dm.debugLog = true
	}
}
