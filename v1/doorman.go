package doorman

import (
	"fmt"
)

var (
	globalDoorman *Doorman
	hashers       map[string]func(string) string
	logger        Logger = &NullLogger{}
)

// NewDoorman init
func NewDoorman(cfg *DoormanConfig, opts ...func(dm *Doorman)) (dm *Doorman, err error) {
	dm = &Doorman{
		config:         cfg,
		authenticators: make(map[string]func(string, map[string]any) (Authenticator, error)),
	}

	// register Authenticators
	dm.authenticators["basic"] = NewBasicAuthAuthenticator
	dm.authenticators["http_header"] = NewHttpHeaderAuthenticator
	dm.authenticators["ipaddress"] = NewIPAddressAuthenticator
	dm.authenticators["bearer"] = NewBearerAuthenticator

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
	dm.authnIdMap = make(map[string]int)

	for _, authnConfig := range dm.config.Authenticators {
		var a Authenticator

		if authenticatorInitFunc, found := dm.authenticators[authnConfig.Type]; found {
			if a, err = authenticatorInitFunc(authnConfig.Name, authnConfig.Config); err != nil {
				return err
			}
		} else {
			return fmt.Errorf("no such authenticator")
		}

		//---------
		if a != nil {
			if _, ok := dm.authnIdMap[a.GetName()]; !ok {
				dm.loadedAuthenticators = append(dm.loadedAuthenticators, a)
				dm.authnIdMap[a.GetName()] = len(dm.loadedAuthenticators) - 1
			} else {
				return fmt.Errorf("duplicated name in authnConfig authenticatorsConfig. '%s'", a.GetName())
			}
		}
	}
	return nil
}

func WithAuthenticator(name string, initFunc func(string, map[string]any) (Authenticator, error)) func(dm *Doorman) {
	return func(dm *Doorman) {
		dm.authenticators[name] = initFunc
	}
}

func AsGlobalDefault() func(dm *Doorman) {
	return func(dm *Doorman) {
		globalDoorman = dm
	}
}
