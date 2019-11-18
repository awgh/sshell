package commands

import (
	"bytes"
	"errors"
	"io"
	"regexp"
	"strings"

	"github.com/mattn/go-shellwords"
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

// AutoCompleteCallback - Callback for AutoCompletioon of Commands
func AutoCompleteCallback(line string, pos int, key rune) (newLine string, newPos int, ok bool) {
	if key != '\t' || pos != len(line) {
		return
	}
	lastWord := regexp.MustCompile(`.+\W(\w+)$`)
	// Auto-complete for the command itself.
	if !strings.Contains(line, " ") {
		var name string
		name, _, ok = LookupCommand(line)
		if !ok {
			return
		}
		return name, len(name), true
	}
	_, c, ok := LookupCommand(line[:strings.IndexByte(line, ' ')])
	if !ok || c.Complete == nil {
		return
	}
	if strings.HasSuffix(line, " ") {
		return line, pos, true
	}
	m := lastWord.FindStringSubmatch(line)
	if m == nil {
		return line, len(line), true
	}
	soFar := m[1]
	var match []string
	for _, cand := range c.Complete() {
		if len(soFar) > len(cand) || !strings.EqualFold(cand[:len(soFar)], soFar) {
			continue
		}
		match = append(match, cand)
	}
	if len(match) == 0 {
		return
	}
	if len(match) > 1 {
		return line, pos, true
	}
	newLine = line[:len(line)-len(soFar)] + match[0]
	return newLine, len(newLine), true
}

// Exec - execute a command line in the interpreter
func Exec(args string) (string, error) {
	f, err := shellwords.Parse(args)
	if err != nil {
		return err.Error(), err
	}
	if len(f) == 0 {
		return "", nil
	}
	cmd, argv := f[0], f[1:]
	b := new(bytes.Buffer)
	if _, c, ok := LookupCommand(cmd); ok {
		err = c.Run(b, argv)
		return string(b.Bytes()), nil
	}
	t := "Unknown command: " + f[0] + "\n"
	return t, errors.New(t)
}
