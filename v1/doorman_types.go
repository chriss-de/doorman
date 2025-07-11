package doorman

type AuthenticatorConfig struct {
	Name   string         `mapstructure:"name"`
	Type   string         `mapstructure:"type"`
	Groups []string       `mapstructure:"groups"`
	Config map[string]any `mapstructure:",remain"`
}

type Doorman struct {
	debugLog                 bool
	configuredAuthenticators []*AuthenticatorConfig
	loadedAuthenticators     []Authenticator
	registeredAuthenticators map[string]func(*AuthenticatorConfig) (Authenticator, error)
	authenticatorsIdMap      map[string]int
}
