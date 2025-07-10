package doorman

type authenticatorsConfig struct {
	Name   string         `mapstructure:"name"`
	Type   string         `mapstructure:"type"`
	Config map[string]any `mapstructure:",remain"`
}

type DoormanConfig struct {
	DebugLog       bool `mapstructure:"debug_log"`
	Authenticators []authenticatorsConfig
}

type Doorman struct {
	config               *DoormanConfig
	loadedAuthenticators []Authenticator
	authenticators       map[string]func(string, map[string]any) (Authenticator, error)

	authnIdMap map[string]int
}
