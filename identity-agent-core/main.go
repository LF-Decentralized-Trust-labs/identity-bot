package main

import (
	"identity-agent-core/run"
	"identity-agent-core/server"
)

// The core's own program: the Identity Agent for an individual, with no
// add-on. An organization runs a program of its own, which says so.
func main() {
	run.Main(run.Options{
		// What this program serves, which only the program can know: the core
		// is the same inside every app. It decides who may witness and watch
		// for this agent, since peers are of the same kind.
		Config: func(cfg *server.Config) { cfg.EntityType = "individual" },
	})
}
