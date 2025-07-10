package doorman

type Logger interface {
	Error(msg string, args ...any)
	Info(msg string, args ...any)
	Debug(msg string, args ...any)
}

type NullLogger struct{}

func (NullLogger) Error(msg string, args ...any) {}
func (NullLogger) Info(msg string, args ...any)  {}
func (NullLogger) Debug(msg string, args ...any) {}

func WithLogger(l Logger) func(epp *Doorman) {
	return func(epp *Doorman) {
		logger = l
	}
}
