// Command agent-host makes this machine the body of an AI agent.
//
//	agent-host enrol <enrolment string> [--placement computer|vm|cloud|device]
//	agent-host status
//	agent-host run [--brain claude-code|codex|grok] [--brain-path PATH] [--brain-user USER] [--workspace DIR]
//	               [--screen control|watch|off] [--display :0] [--display-allow-network]
//	agent-host move <new address of the same Identity Agent>
//	agent-host call <METHOD> <path> [json body]
//	agent-host brain-user [USER]
//	agent-host mcp
//	agent-host brain-home -- <brain> <args>
//	agent-host github-credential get
//
// Every command accepts --data-dir; the default is per operating system.
//
// --screen says what the people the Identity Agent allows may do with this
// machine's screen. control, the default, lets them watch it and take control
// of it; watch makes the machine watch-only, ignoring any click or key it is
// sent; off offers no screen at all. Whoever is in control can press any key
// combination a person at the machine could, including switching to another
// virtual terminal or ending the graphical session.
package main

import (
	"context"
	"encoding/json"
	"errors"
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
	// Started by the host, as the brain's user, around one run of a brain that
	// keeps its sign-in in a file: its arguments are the brain's, not this
	// program's.
	if cmd == "brain-home" {
		os.Exit(agenthost.ServeBrainHome(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	// Run by git as its credential helper, during a run lent GitHub access:
	// the token comes from the brain's environment, never a file.
	if cmd == "github-credential" {
		os.Exit(agenthost.ServeGitHubCredential(os.Args[2:], os.Stdin, os.Stdout, os.Getenv))
	}
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	dataDir := fs.String("data-dir", agenthost.DefaultDataDir(), "where this machine's key and state are kept")
	placement := fs.String("placement", "computer", "where this machine is: computer, vm, cloud or device")
	wait := fs.Duration("wait", 15*time.Minute, "how long to wait for the owner to approve")
	brainName := fs.String("brain", "", "the brain to run, instead of the one the AI agent was created with: claude-code, codex or grok")
	brainPath := fs.String("brain-path", "", "the full path of the brain's program")
	brainUser := fs.String("brain-user", "", "the operating-system user the brain runs as")
	workspace := fs.String("workspace", "", "the brain's working directory")
	screenMode := fs.String("screen", "control", "what people allowed to may do with this machine's screen: "+
		"control (watch it, and take control when the Identity Agent lets them, with any key combination), "+
		"watch (only watch it: this machine is watch-only and ignores every click and key) or off")
	display := fs.String("display", "", "the X display to show, when it is not $DISPLAY")
	displayAllowNetwork := fs.Bool("display-allow-network", false, "show an X display on another machine (host:N), "+
		"whose pictures and keys cross the network unencrypted")
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
		// Its AI agent's name and brain come only over the sealed transport,
		// which a live body has.
		if st["state"] == "active" {
			if code, raw, err := h.Call("GET", "/api/agent-host/binding", nil); err == nil && code == 200 {
				_ = json.Unmarshal(raw, &st)
			}
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
			case agenthost.Codex:
				v.Path = path
				b = v
			}
			brain = b
		} else if *brainUser != "" {
			fail(fmt.Errorf("--brain-user needs --brain and --brain-path: the brain's program, installed for that user"))
		}
		mode, err := agenthost.ParseScreenMode(*screenMode)
		if err != nil {
			fail(err)
		}
		var scr agenthost.Screen
		if mode != agenthost.ScreenOff {
			if scr, err = agenthost.OpenScreen(*display, *displayAllowNetwork); err != nil {
				if errors.Is(err, agenthost.ErrScreenNotYet) {
					fmt.Fprintln(os.Stderr, "agent-host: "+agenthost.ErrScreenNotYet.Error())
				} else {
					fmt.Fprintf(os.Stderr, "agent-host: not offering a screen: %v\n", err)
				}
				scr = nil
			} else {
				defer scr.Close()
			}
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := h.Run(ctx, agenthost.RunOptions{Brain: brain, Runner: runner, Workspace: *workspace,
			Screen: scr, ScreenMode: mode}); err != nil {
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
		fmt.Printf(`On a machine you also use, the brain runs as its own user, so it cannot use your keys or speak as you.
One-time setup, as an administrator (each sudo asks for your password):

  1. Create the user (you will be asked to choose its password; nobody needs to log in as it):
       sudo sysadminctl -addUser %[1]s -fullName "Agent Host brain" -password -

  2. Install the brain for that user, and sign it in:
       Claude Code:  sudo -u %[1]s -H sh -c 'curl -fsSL https://claude.ai/install.sh | bash'
                     sudo -u %[1]s -H /Users/%[1]s/.local/bin/claude      (then type /login)
       Grok CLI:     install it for %[1]s the same way, and name its path in step 4 too.
                     Grok runs only this way: it has no flag to ignore the MCP servers of whoever runs it.
       Codex:        install it for %[1]s (npm install -g @openai/codex), and name its path in step 4 too.
       A brain signed in through the Identity Agent needs no sign-in here: it is lent for each run.

  3. Make its workspace. Mode 711 lets the host start the brain there without
     being able to list or read what the brain keeps in it:
       sudo -u %[1]s -H mkdir -m 711 /Users/%[1]s/workspace

  4. Let %[2]s start the brain's program as %[1]s, and nothing else. SETENV lets the host pass
     each turn's tool token and sign-in in the environment rather than on the command line.
     Codex and Grok keep their sign-in in a file, so the host starts them through this program,
     which puts a lent sign-in in place for one run and takes it away after. The rule is written
     to a file, checked by visudo, and only then installed, so a mistake cannot lock sudo:
       BRAIN="$(sudo -u %[1]s -H sh -lc 'command -v codex || command -v grok')"   # leave empty for Claude Code only
       printf '%%s\n' '%[2]s ALL=(%[1]s) NOPASSWD:SETENV: /Users/%[1]s/.local/bin/claude' > /tmp/agent-host.sudoers
       [ -n "$BRAIN" ] && printf '%%s\n' "%[2]s ALL=(%[1]s) NOPASSWD:SETENV: $BRAIN, /usr/local/bin/agent-host brain-home -- $BRAIN *" >> /tmp/agent-host.sudoers
       sudo visudo -cf /tmp/agent-host.sudoers && sudo install -m 440 /tmp/agent-host.sudoers /etc/sudoers.d/agent-host

  5. Install this program where %[1]s can run it. The brain starts it for its tools, and
     your own folders are closed to other users. Then run the host from there:
       sudo mkdir -p /usr/local/bin && sudo install -m 755 %[3]s /usr/local/bin/agent-host
       /usr/local/bin/agent-host run --brain claude-code --brain-path /Users/%[1]s/.local/bin/claude --brain-user %[1]s \
         --workspace /Users/%[1]s/workspace
`, user, me, self)
	case "linux":
		fmt.Printf(`On a machine you also use, the brain runs as its own user, so it cannot use your keys or speak as you.
One-time setup, as an administrator:

  1. sudo useradd --create-home --shell /usr/sbin/nologin %[1]s
  2. Install the brain for that user and sign it in:
       sudo -u %[1]s -H sh -c 'curl -fsSL https://claude.ai/install.sh | bash'
       sudo -u %[1]s -H /home/%[1]s/.local/bin/claude      (then type /login)
  3. sudo -u %[1]s -H mkdir -m 711 /home/%[1]s/workspace
  4. Let %[2]s start the brain's program as %[1]s, and nothing else. The rule is checked by visudo
     before it is installed, so a mistake cannot lock sudo. For Codex or Grok, which the host starts
     through this program, BRAIN names the program's full path:
       BRAIN="$(sudo -u %[1]s -H sh -lc 'command -v codex || command -v grok')"   # leave empty for Claude Code only
       printf '%%s\n' '%[2]s ALL=(%[1]s) NOPASSWD:SETENV: /home/%[1]s/.local/bin/claude' > /tmp/agent-host.sudoers
       [ -n "$BRAIN" ] && printf '%%s\n' "%[2]s ALL=(%[1]s) NOPASSWD:SETENV: $BRAIN, /usr/local/bin/agent-host brain-home -- $BRAIN *" >> /tmp/agent-host.sudoers
       sudo visudo -cf /tmp/agent-host.sudoers && sudo install -m 440 /tmp/agent-host.sudoers /etc/sudoers.d/agent-host
  5. Install this program where %[1]s can run it (the brain starts it for its tools), and run the host from there:
       sudo install -m 755 %[3]s /usr/local/bin/agent-host
       /usr/local/bin/agent-host run --brain claude-code --brain-path /home/%[1]s/.local/bin/claude --brain-user %[1]s \
         --workspace /home/%[1]s/workspace
`, user, me, self)
	default:
		fmt.Println("Running the brain as a separate Windows user is not available yet. On a machine you also use,\n" +
			"the brain runs as your own user.")
	}
	if _, err := exec.LookPath("sudo"); err != nil && runtime.GOOS != "windows" {
		fmt.Println("\nsudo was not found on this machine; the steps above need it.")
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:\n"+
		"  agent-host enrol <enrolment string> [--placement computer|vm|cloud|device]\n"+
		"  agent-host status\n"+
		"  agent-host run [--brain claude-code|codex|grok] [--brain-path PATH] [--brain-user USER] [--workspace DIR]\n"+
		"                 [--screen control|watch|off] [--display :0] [--display-allow-network]\n"+
		"                 --screen control (the default) lets people allowed to watch and take control;\n"+
		"                 --screen watch makes this machine watch-only; --screen off offers no screen\n"+
		"  agent-host move <new address of the same Identity Agent>\n"+
		"  agent-host call <METHOD> <path> [json body]\n"+
		"  agent-host brain-user [USER]\n"+
		"  agent-host mcp      (started by the brain, never by hand)\n"+
		"  agent-host brain-home -- <brain> <args>      (started by the host, never by hand)")
	os.Exit(2)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "agent-host:", err)
	os.Exit(1)
}
