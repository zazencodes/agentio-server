// Command agentio-server runs the agentio server and administers its users.
package main

import "agentio.sh/server/internal/command"

func main() {
	command.Main(command.Program{Name: "agentio-server"})
}
