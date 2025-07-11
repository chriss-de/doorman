package doorman

import "errors"

type Logger interface {
	Error(msg string, args ...any)
	Info(msg string, args ...any)
	Debug(msg string, args ...any)
}

type NullLogger struct{}

func (NullLogger) Error(msg string, args ...any) {}
func (NullLogger) Info(msg string, args ...any)  {}
func (NullLogger) Debug(msg string, args ...any) {}

func WithLogger(l Logger) func(epp *Doorman) error {
	return func(epp *Doorman) error {
		if l == nil {
			return errors.New("logger cannot be nil")
		}
		logger = l
		return nil
	}
}
