// Command agent-host makes this machine the body of an AI agent.
//
//	agent-host enrol <enrolment string> [--placement computer|vm|cloud|device]
//	agent-host status
//	agent-host run [--brain claude-code|grok] [--brain-path PATH] [--brain-user USER] [--workspace DIR]
//	agent-host move <new address of the same Identity Agent>
//	agent-host call <METHOD> <path> [json body]
//	agent-host brain-user [USER]
//	agent-host mcp
//
// Every command accepts --data-dir; the default is per operating system.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"identity-agent-core/agenthost"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd := os.Args[1]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	dataDir := fs.String("data-dir", agenthost.DefaultDataDir(), "where this machine's key and state are kept")
	placement := fs.String("placement", "computer", "where this machine is: computer, vm, cloud or device")
	wait := fs.Duration("wait", 15*time.Minute, "how long to wait for the owner to approve")
	brainName := fs.String("brain", "", "the brain to run, instead of the one the AI agent was created with: claude-code or grok")
	brainPath := fs.String("brain-path", "", "the full path of the brain's program")
	brainUser := fs.String("brain-user", "", "the operating-system user the brain runs as")
	workspace := fs.String("workspace", "", "the brain's working directory")
	// Flags may come before or after the arguments, as people type them.
	var args []string
	rest := os.Args[2:]
	for {
		_ = fs.Parse(rest)
		if fs.NArg() == 0 {
			break
		}
		args = append(args, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	h := &agenthost.Host{DataDir: *dataDir, Out: os.Stdout}

	switch cmd {
	case "enrol", "enroll":
		if len(args) != 1 {
			usage()
		}
		if _, err := h.Enrol(args[0], *placement, *wait); err != nil {
			fail(err)
		}
	case "status":
		st, err := h.Status()
		if err != nil {
			fail(err)
		}
		fmt.Printf("state: %v\nAI agent: %v %v\ngrade: %v\nwords: %v\ncredential: %v\nbrain: %v\n",
			st["state"], st["agent_name"], st["agent"], st["grade"], st["words"], st["credential_said"], st["brain"])
	case "run":
		var runner agenthost.Runner = agenthost.SameUser{}
		if *brainUser != "" {
			runner = agenthost.AsUser{User: *brainUser}
		}
		var brain agenthost.Brain
		if *brainName != "" || *brainPath != "" {
			path := *brainPath
			if path == "" && *brainUser != "" {
				fail(fmt.Errorf("--brain-user needs --brain-path: the brain's program, installed for that user"))
			}
			b, err := agenthost.BrainFor(*brainName, runner)
			if err != nil {
				fail(err)
			}
			switch v := b.(type) {
			case agenthost.ClaudeCode:
				v.Path = path
				b = v
			case agenthost.GrokCLI:
				v.Path = path
				b = v
			}
			brain = b
		} else if *brainUser != "" {
			fail(fmt.Errorf("--brain-user needs --brain and --brain-path: the brain's program, installed for that user"))
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := h.Run(ctx, agenthost.RunOptions{Brain: brain, Runner: runner, Workspace: *workspace}); err != nil {
			fail(err)
		}
	case "move":
		if len(args) != 1 {
			usage()
		}
		st, err := h.Move(args[0])
		if err != nil {
			fail(err)
		}
		fmt.Printf("This machine now reaches %s at %s.\n", st.IdentityAgent, st.IdentityAgentURL)
	case "call":
		if len(args) < 2 {
			usage()
		}
		var body []byte
		if len(args) > 2 {
			body = []byte(args[2])
		}
		code, out, err := h.Call(args[0], args[1], body)
		if err != nil {
			fail(err)
		}
		fmt.Printf("%d\n%s\n", code, out)
	case "mcp":
		if err := agenthost.ServeMCP(os.Stdin, os.Stdout); err != nil {
			fail(err)
		}
	case "brain-user":
		user := "agentbrain"
		if len(args) == 1 {
			user = args[0]
		}
		brainUserSetup(user)
	default:
		usage()
	}
}

// brainUserSetup prints the one-time setup that lets the brain run as its own
// operating-system user. It needs an administrator, so it is printed for a
// person to run rather than run here.
func brainUserSetup(user string) {
	me := os.Getenv("USER")
	self, _ := os.Executable()
	self, _ = filepath.EvalSymlinks(self)
	switch runtime.GOOS {
	case "darwin":
		fmt.Printf(`The brain can run as its own user, so even a brain talked into misusing a tool cannot reach your files.
One-time setup, as an administrator (each sudo asks for your password):

  1. Create the user (you will be asked to choose its password; nobody needs to log in as it):
       sudo sysadminctl -addUser %[1]s -fullName "Agent Host brain" -password -

  2. Install the brain for that user, and sign it in:
       Claude Code:  sudo -u %[1]s -H sh -c 'curl -fsSL https://claude.ai/install.sh | bash'
                     sudo -u %[1]s -H /Users/%[1]s/.local/bin/claude      (then type /login)
       Grok CLI:     install it for %[1]s the same way, then: sudo -u %[1]s -H <its path> login

  3. Let %[2]s start that program as %[1]s, and nothing else:
       echo '%[2]s ALL=(%[1]s) NOPASSWD: /Users/%[1]s/.local/bin/claude' | sudo tee /etc/sudoers.d/agent-host
       sudo chmod 440 /etc/sudoers.d/agent-host

  4. Make sure %[1]s can run this program, then run the host:
       %[3]s run --brain claude-code --brain-path /Users/%[1]s/.local/bin/claude --brain-user %[1]s \
         --workspace /Users/%[1]s/workspace
`, user, me, self)
	case "linux":
		fmt.Printf(`The brain can run as its own user, so even a brain talked into misusing a tool cannot reach your files.
One-time setup, as an administrator:

  1. sudo useradd --create-home --shell /usr/sbin/nologin %[1]s
  2. Install the brain for that user and sign it in:
       sudo -u %[1]s -H sh -c 'curl -fsSL https://claude.ai/install.sh | bash'
       sudo -u %[1]s -H /home/%[1]s/.local/bin/claude      (then type /login)
  3. echo '%[2]s ALL=(%[1]s) NOPASSWD: /home/%[1]s/.local/bin/claude' | sudo tee /etc/sudoers.d/agent-host
     sudo chmod 440 /etc/sudoers.d/agent-host
  4. %[3]s run --brain claude-code --brain-path /home/%[1]s/.local/bin/claude --brain-user %[1]s \
       --workspace /home/%[1]s/workspace
`, user, me, self)
	default:
		fmt.Println("Running the brain as a separate Windows user is not available yet. The brain runs as your own user,\n" +
			"and the tool allow list keeps it to the host's tools.")
	}
	if _, err := exec.LookPath("sudo"); err != nil && runtime.GOOS != "windows" {
		fmt.Println("\nsudo was not found on this machine; the steps above need it.")
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:\n"+
		"  agent-host enrol <enrolment string> [--placement computer|vm|cloud|device]\n"+
		"  agent-host status\n"+
		"  agent-host run [--brain claude-code|grok] [--brain-path PATH] [--brain-user USER] [--workspace DIR]\n"+
		"  agent-host move <new address of the same Identity Agent>\n"+
		"  agent-host call <METHOD> <path> [json body]\n"+
		"  agent-host brain-user [USER]\n"+
		"  agent-host mcp      (started by the brain, never by hand)")
	os.Exit(2)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "agent-host:", err)
	os.Exit(1)
}
