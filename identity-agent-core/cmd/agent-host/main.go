// Command agent-host makes this machine the body of an AI agent.
//
//	agent-host enrol <enrolment string, or - to read it from standard input> [--placement computer|vm|cloud|device]
//	agent-host status
//	agent-host run [--brain claude-code|codex|grok|built-in] [--brain-path PATH] [--brain-user USER [--brain-dir DIR]] [--workspace DIR]
//	               [--screen control|watch|off] [--display :0] [--display-allow-network]
//	agent-host move <new address of the same Identity Agent>
//	agent-host call <METHOD> <path> [json body]
//	agent-host brain-user [USER]
//	agent-host provide --program PATH [--offers screen,toolchain,xcode]
//	agent-host mcp
//	agent-host brain-home -- <brain> <args>
//	agent-host brain-env -- <brain> <args>
//	agent-host loop
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
	"bufio"
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
	"strings"
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
	// Started by the host through sudo, as the brain's user, around every run
	// of a brain that runs as its own user: the run's variables come on stdin,
	// never through sudo, which writes what it passes on to the system log.
	if cmd == "brain-env" {
		os.Exit(agenthost.ServeBrainEnv(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	// Started by the host, as the brain's user, for a turn of agent-host's own
	// loop: the turn comes on stdin, and its answer goes to stdout.
	if cmd == "loop" {
		os.Exit(agenthost.ServeLoop(os.Stdin, os.Stdout, os.Stderr))
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
	brainName := fs.String("brain", "", "the brain to run, instead of the one the AI agent was created with: claude-code, codex, grok or built-in")
	brainPath := fs.String("brain-path", "", "the full path of the brain's program")
	brainUser := fs.String("brain-user", "", "the operating-system user the brain runs as")
	brainDir := fs.String("brain-dir", "", "with --brain-user and no --brain: the directory holding the brains' programs "+
		"(claude, codex, grok); the one the AI agent was created with is run from it")
	workspace := fs.String("workspace", "", "the brain's working directory")
	program := fs.String("program", "", "provide: the program that makes, enrols and removes machines")
	offers := fs.String("offers", "", "provide: what the machines it makes can provide, comma-separated: screen, toolchain, xcode")
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
		// "-" reads the string from standard input, so a program handing it
		// to a machine need not put a one-time secret on a command line.
		if args[0] == "-" {
			line, err := bufio.NewReader(os.Stdin).ReadString('\n')
			if line = strings.TrimSpace(line); line == "" {
				fail(fmt.Errorf("no enrolment string on standard input: %v", err))
			}
			args[0] = line
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
		if err := checkBrainFlags(*brainName, *brainPath, *brainUser, *brainDir, runtime.GOOS); err != nil {
			fail(err)
		}
		if *brainName != "" || *brainPath != "" {
			path := *brainPath
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
			BrainDir: *brainDir, Screen: scr, ScreenMode: mode}); err != nil {
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
	case "provide":
		var list []string
		if *offers != "" {
			list = strings.Split(*offers, ",")
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := h.Provide(ctx, agenthost.ProvideOptions{Program: *program, Offers: list}); err != nil {
			fail(err)
		}
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

// checkBrainFlags refuses a combination of run's brain flags that cannot work,
// before anything starts, rather than on the first turn.
func checkBrainFlags(name, path, user, dir, goos string) error {
	if goos == "windows" && (user != "" || dir != "") {
		return fmt.Errorf("running the brain as a separate Windows user is not available yet; run without --brain-user and --brain-dir")
	}
	if dir != "" {
		switch {
		case user == "":
			return fmt.Errorf("--brain-dir needs --brain-user: the brains in it run as that user, never as this one")
		case name != "" || path != "":
			return fmt.Errorf("--brain-dir runs the brain the AI agent was created with; it does not go with --brain or --brain-path")
		case !filepath.IsAbs(dir):
			return fmt.Errorf("--brain-dir must be a full path")
		}
		return nil
	}
	if user != "" && path == "" {
		return fmt.Errorf("--brain-user needs --brain-path (one brain's program) or --brain-dir (a directory of them), installed for that user")
	}
	return nil
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

  4. Let %[2]s start the brain's program as %[1]s, and nothing else. The host starts every brain
     through this program (brain-env), which takes each turn's tool token, sign-in and GitHub
     access on its input: sudo writes its command line and any variable it passes on to the
     system log, so none of them goes through sudo. Codex and Grok keep their sign-in in a file,
     so this program also puts a lent sign-in in place for one run and takes it away after
     (brain-home). sudo's input and output logging stay off for this program, whose input
     holds the sign-in. Its last line lets it start this program's own loop, for an AI agent run by
     agent-host itself. The rule is written to a file, checked by visudo, and only then installed, so a
     mistake cannot lock sudo:
       BRAINS="/Users/%[1]s/.local/bin/claude $(sudo -u %[1]s -H sh -lc 'command -v codex; command -v grok')"
       { printf '%%s\n' 'Defaults!/usr/local/bin/agent-host !log_input, !log_output'
         for b in $BRAINS; do printf '%%s\n' "%[2]s ALL=(%[1]s) NOPASSWD: /usr/local/bin/agent-host brain-env -- $b *, /usr/local/bin/agent-host brain-env -- /usr/local/bin/agent-host brain-home -- $b *"; done
         printf '%%s\n' "%[2]s ALL=(%[1]s) NOPASSWD: /usr/local/bin/agent-host brain-env -- /usr/local/bin/agent-host loop"
       } > /tmp/agent-host.sudoers
       sudo visudo -cf /tmp/agent-host.sudoers && sudo install -m 440 /tmp/agent-host.sudoers /etc/sudoers.d/agent-host

  5. Install this program where %[1]s can run it. The brain starts it for its tools, git starts
     it for the GitHub access a run is lent, and your own folders are closed to other users.
     Then run the host from there:
       sudo mkdir -p /usr/local/bin && sudo install -m 755 %[3]s /usr/local/bin/agent-host
       /usr/local/bin/agent-host run --brain claude-code --brain-path /Users/%[1]s/.local/bin/claude --brain-user %[1]s \
         --workspace /Users/%[1]s/workspace

  With more than one brain installed for %[1]s (claude, codex, grok in one directory), run the one
  each AI agent was created with instead of naming one, and list each program in step 4's rule:
       /usr/local/bin/agent-host run --brain-user %[1]s --brain-dir /Users/%[1]s/.local/bin \
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
  4. Let %[2]s start the brain's program as %[1]s, and nothing else. The host starts every brain
     through this program (brain-env), which takes each turn's tool token, sign-in and GitHub
     access on its input: sudo writes its command line and any variable it passes on to the
     system log, so none of them goes through sudo. sudo's input and output logging stay off
     for this program, whose input holds the sign-in. Its last line lets it start this program's own loop, for
     an AI agent run by agent-host itself. The rule is checked by visudo before it is installed, so a mistake
     cannot lock sudo. BRAINS lists each brain's full path:
       BRAINS="/home/%[1]s/.local/bin/claude $(sudo -u %[1]s -H sh -lc 'command -v codex; command -v grok')"
       { printf '%%s\n' 'Defaults!/usr/local/bin/agent-host !log_input, !log_output'
         for b in $BRAINS; do printf '%%s\n' "%[2]s ALL=(%[1]s) NOPASSWD: /usr/local/bin/agent-host brain-env -- $b *, /usr/local/bin/agent-host brain-env -- /usr/local/bin/agent-host brain-home -- $b *"; done
         printf '%%s\n' "%[2]s ALL=(%[1]s) NOPASSWD: /usr/local/bin/agent-host brain-env -- /usr/local/bin/agent-host loop"
       } > /tmp/agent-host.sudoers
       sudo visudo -cf /tmp/agent-host.sudoers && sudo install -m 440 /tmp/agent-host.sudoers /etc/sudoers.d/agent-host
  5. Install this program where %[1]s can run it (the brain starts it for its tools, and git for the
     GitHub access a run is lent), and run the host from there:
       sudo install -m 755 %[3]s /usr/local/bin/agent-host
       /usr/local/bin/agent-host run --brain claude-code --brain-path /home/%[1]s/.local/bin/claude --brain-user %[1]s \
         --workspace /home/%[1]s/workspace

  With more than one brain installed for %[1]s (claude, codex, grok in one directory), run the one
  each AI agent was created with instead of naming one, and list each program in step 4's rule:
       /usr/local/bin/agent-host run --brain-user %[1]s --brain-dir /home/%[1]s/.local/bin \
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
		"  agent-host enrol <enrolment string, or -> [--placement computer|vm|cloud|device]\n"+
		"  agent-host status\n"+
		"  agent-host run [--brain claude-code|codex|grok] [--brain-path PATH] [--brain-user USER [--brain-dir DIR]] [--workspace DIR]\n"+
		"                 [--screen control|watch|off] [--display :0] [--display-allow-network]\n"+
		"                 --screen control (the default) lets people allowed to watch and take control;\n"+
		"                 --screen watch makes this machine watch-only; --screen off offers no screen\n"+
		"  agent-host move <new address of the same Identity Agent>\n"+
		"  agent-host call <METHOD> <path> [json body]\n"+
		"  agent-host brain-user [USER]\n"+
		"  agent-host provide --program PATH [--offers screen,toolchain,xcode]\n"+
		"  agent-host mcp      (started by the brain, never by hand)\n"+
		"  agent-host brain-home -- <brain> <args>      (started by the host, never by hand)\n"+
		"  agent-host brain-env -- <brain> <args>       (started by the host, never by hand)")
	os.Exit(2)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "agent-host:", err)
	os.Exit(1)
}
