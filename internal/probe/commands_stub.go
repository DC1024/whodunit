//go:build !windows

package probe

type commandsUnsupported struct{}

func NewCommands() Commands { return commandsUnsupported{} }

func (commandsUnsupported) Available() bool { return false }

func (commandsUnsupported) Output(name string, args ...string) (string, error) {
	return "", ErrUnsupported
}
