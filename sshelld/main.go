package main

import "github.com/awgh/sshell"

func main() {

	shell := sshell.SSHell{User: "admin", Password: "admin", Port: 2200, Prompt: "> "}
	shell.Listen()

}
