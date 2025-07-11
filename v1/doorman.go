package doorman

import (
	"fmt"
)

var (
	globalDoorman *Doorman
	logger        Logger                = &NullLogger{}
	hashers       map[string]HasherFunc = map[string]HasherFunc{
		"plain":  stringHashPlain,
		"md5":    stringHashMd5,
		"sha1":   stringHashSha1,
		"sha256": stringHashSha256,
	}
)

// NewDoorman init
func NewDoorman(opts ...NewFunc) (dm *Doorman, err error) {
	dm = &Doorman{
		registeredAuthenticators: make(map[string]RegisterAuthenticatorFunc),
		configuredAuthenticators: make([]*AuthenticatorConfig, 0),
	}

	// register Authenticators
	dm.registeredAuthenticators["basic"] = NewBasicAuthAuthenticator
	dm.registeredAuthenticators["http_header"] = NewHttpHeaderAuthenticator
	dm.registeredAuthenticators["ipaddress"] = NewIPAddressAuthenticator
	dm.registeredAuthenticators["bearer"] = NewBearerAuthenticator

	for _, opt := range opts {
		if err = opt(dm); err != nil {
			return nil, err
		}
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

func WithAuthenticatorConfigs(configs []*AuthenticatorConfig) func(dm *Doorman) error {
	return func(dm *Doorman) error {
		dm.configuredAuthenticators = configs
		return nil
	}
}

func RegisterNewAuthenticator(name string, initFunc func(*AuthenticatorConfig) (Authenticator, error)) func(dm *Doorman) error {
	return func(dm *Doorman) error {
		dm.registeredAuthenticators[name] = initFunc
		return nil
	}
}

func AsGlobalDefault(force bool) func(dm *Doorman) error {
	return func(dm *Doorman) error {
		if globalDoorman != nil && !force {
			return fmt.Errorf("global doorman already set")
		}
		globalDoorman = dm
		return nil
	}
}
