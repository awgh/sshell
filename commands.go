package sshell

import (
	"errors"
	"fmt"
	"io"
)

var errExitApp = errors.New("exiting")

type command struct {
	run      func(io.Writer, []string) error // required
	complete func() []string
}

func cmdTest(term io.Writer, args []string) error {
	WriteTerm(term, fmt.Sprintf("Test: %+v", args))
	return nil
}

func cmdExit(term io.Writer, args []string) error {
	return errExitApp
}

// RegisterCommand - Add a command
func (s *SSHell) RegisterCommand(name string, run func(io.Writer, []string) error, complete func() []string) {
	s.Commands[name] = command{run: run, complete: complete}
}
