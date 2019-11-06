package commands

import (
	"io"
	"strings"
)

var (
	// Registry - table of registered command handlers
	Registry map[string]Command
)

func init() {
	Registry = make(map[string]Command)
}

// Command - a table entry for registering a command
type Command struct {
	Run      func(io.Writer, []string) error // required
	Complete func() []string
}

// RegisterCommand - Add a command
func RegisterCommand(name string, run func(io.Writer, []string) error, complete func() []string) {
	Registry[name] = Command{Run: run, Complete: complete}
}

// LookupCommand - Find a command by prefix
func LookupCommand(prefix string) (name string, c Command, ok bool) {
	prefix = strings.ToLower(prefix)
	if c, ok = Registry[prefix]; ok {
		return prefix, c, ok
	}
	for full, candidate := range Registry {
		if strings.HasPrefix(full, prefix) {
			if c.Run != nil {
				return "", Command{}, false
			}
			c = candidate
			name = full
		}
	}
	return name, c, c.Run != nil
}
