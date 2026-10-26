package agenthost

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"identity-agent-core/childenv"
)

// A brain's home is where a program that keeps its sign-in in a file — Codex
// and Grok — finds it. The file is written there for one run, by the user the
// brain runs as, and removed when the run ends: also when it fails, and at the
// start of the next run if a crash left it behind. The home itself stays, for
// the program's sessions, so a conversation can carry on in the next run.
//
// Those programs renew their own tokens while they run, and the one they were
// lent may stop working once they have. So the file is read back at the end
// of the run and returned to the Identity Agent with the lease.
//
// The host does not write the file itself: on a machine a person also uses,
// the brain runs as a user of its own (AsUser), whose home the host cannot
// write. The host starts this program as that user instead — `agent-host
// brain-home -- <brain> <args>` — with the file in its environment, and this
// program does the writing, runs the brain, and reports back on its standard
// output alone: never its error output, which becomes a failure notice.

// signInFile is where Codex and Grok keep their sign-in in their home.
const signInFile = "auth.json"

// envBrainHome carries a brainHome to `agent-host brain-home`.
const envBrainHome = "AGENT_HOST_BRAIN_HOME"

// brainHome is what a run's brain needs in its home.
type brainHome struct {
	// Var is the variable the program reads its home from: CODEX_HOME or
	// GROK_HOME.
	Var string `json:"var"`
	// Name is the home's directory under ~/.agent-host-brain.
	Name string `json:"name"`
	// Files are written for the run and removed after: the sign-in file.
	Files map[string]string `json:"files,omitempty"`
	// Config is the program's config.toml for the run. It holds no secret: a
	// key it needs is named by the variable that carries it.
	Config string `json:"config,omitempty"`
	// Return names the file read back after the run, which the program may
	// have refreshed.
	Return string `json:"return,omitempty"`
	// ModelBaseURL is the address of a model the brain reaches with a key of
	// the sign-in's (in envModelKey); the brain's settings for it are written
	// into Config when the run starts, with the model it uses.
	ModelBaseURL string `json:"model_base_url,omitempty"`
}

// brainHomeOutcome is what `agent-host brain-home` prints: the brain's output,
// how it exited, and the sign-in file if the brain's program changed it.
type brainHomeOutcome struct {
	Stdout []byte `json:"stdout"`
	Exit   int    `json:"exit"`
	SignIn string `json:"sign_in,omitempty"`
}

// homeOf is the brain's home: one per program, under the brain user's own
// home directory.
func homeOf(name string) (string, error) {
	if name == "" || strings.ContainsAny(name, `/\`) || name == "." || name == ".." {
		return "", fmt.Errorf("not a brain home: %q", name)
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".agent-host-brain", name), nil
}

// lockHome lets one run at a time use a brain's home on this machine. A lock
// older than any run could be is left over from a crash, and taken.
func lockHome(ctx context.Context, dir string) (func(), error) {
	p := filepath.Join(dir, "agent-host.lock")
	for {
		f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			_ = f.Close()
			return func() { _ = os.Remove(p) }, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if st, serr := os.Stat(p); serr == nil && time.Since(st.ModTime()) > 2*turnTimeout {
			_ = os.Remove(p)
			continue
		}
		select {
		case <-ctx.Done():
			return nil, errors.New("another run is using this brain's home")
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// ServeBrainHome is `agent-host brain-home -- <program> <args>`: it writes the
// run's sign-in file into the brain's home, runs the program there, reads the
// file back, removes it, and prints a brainHomeOutcome. It returns the exit
// status for this program: 0 whenever the outcome was printed.
func ServeBrainHome(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		fmt.Fprintln(stderr, "agent-host brain-home: name the brain's program to run")
		return 2
	}
	var spec brainHome
	raw := os.Getenv(envBrainHome)
	_ = os.Unsetenv(envBrainHome)
	if err := json.Unmarshal([]byte(raw), &spec); err != nil || spec.Var == "" {
		fmt.Fprintln(stderr, "agent-host brain-home: started without a home to prepare")
		return 2
	}
	home, err := homeOf(spec.Name)
	if err == nil {
		err = os.MkdirAll(home, 0o700)
	}
	if err == nil {
		err = os.Chmod(home, 0o700)
	}
	if err != nil {
		fmt.Fprintf(stderr, "agent-host brain-home: the brain's home could not be made: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), interruptSignals()...)
	defer stop()
	lctx, cancel := context.WithTimeout(ctx, turnTimeout)
	unlock, err := lockHome(lctx, home)
	cancel()
	if err != nil {
		fmt.Fprintf(stderr, "agent-host brain-home: %v\n", err)
		return 1
	}
	defer unlock()
	// Whatever happens from here, the sign-in file does not stay. Both
	// programs keep theirs in auth.json, which is removed whatever this run
	// was lent: one left by a run that crashed must not sign this one in.
	secrets := []string{filepath.Join(home, signInFile)}
	for name := range spec.Files {
		if strings.ContainsAny(name, `/\`) || name == "" {
			fmt.Fprintf(stderr, "agent-host brain-home: not a file name: %q\n", name)
			return 2
		}
		secrets = append(secrets, filepath.Join(home, name))
	}
	if spec.Return != "" && !strings.ContainsAny(spec.Return, `/\`) {
		secrets = append(secrets, filepath.Join(home, spec.Return))
	}
	removeAll := func() {
		for _, p := range secrets {
			_ = os.Remove(p)
		}
	}
	removeAll() // left by a run that crashed
	defer removeAll()
	for name, content := range spec.Files {
		if err := os.WriteFile(filepath.Join(home, name), []byte(content), 0o600); err != nil {
			fmt.Fprintf(stderr, "agent-host brain-home: the sign-in could not be put in place: %v\n", err)
			return 1
		}
	}
	if err := os.WriteFile(filepath.Join(home, "config.toml"), []byte(spec.Config), 0o600); err != nil {
		fmt.Fprintf(stderr, "agent-host brain-home: the brain's settings could not be written: %v\n", err)
		return 1
	}

	cmd := exec.Command(args[0], args[1:]...)
	env := make([]string, 0, len(os.Environ())+1)
	for _, kv := range childenv.Environ() {
		if strings.HasPrefix(kv, spec.Var+"=") || strings.HasPrefix(kv, envBrainHome+"=") {
			continue
		}
		env = append(env, kv)
	}
	cmd.Env = append(env, spec.Var+"="+home)
	var out bytes.Buffer
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, &out, stderr
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(stderr, "agent-host brain-home: the brain could not be started: %v\n", err)
		return 1
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var werr error
	select {
	case werr = <-done:
	case <-ctx.Done():
		// Asked to stop: the brain goes too, and the file with it.
		_ = cmd.Process.Kill()
		werr = <-done
	}
	res := brainHomeOutcome{Stdout: out.Bytes()}
	if werr != nil {
		res.Exit = 1
		var ee *exec.ExitError
		if errors.As(werr, &ee) && ee.ExitCode() > 0 {
			res.Exit = ee.ExitCode()
		}
	}
	if spec.Return != "" {
		if b, err := os.ReadFile(filepath.Join(home, spec.Return)); err == nil && string(b) != spec.Files[spec.Return] {
			res.SignIn = string(b)
		}
	}
	removeAll()
	if err := json.NewEncoder(stdout).Encode(res); err != nil {
		return 1
	}
	return 0
}

// runInHome runs a brain's program through `agent-host brain-home`, so its
// sign-in file is in place for the run alone. It returns what the program
// printed and the sign-in file if the program refreshed it — also when the
// run failed, since a refreshed token must not be lost with the run.
//
// What the wrapper prints carries the sign-in, so it never becomes part of an
// error: a failure says what the program wrote to its error output, or else
// its own output, as runCLI does.
func runInHome(ctx context.Context, r Runner, dir string, env []string, home brainHome, stdin string,
	name string, args ...string) (out []byte, refreshed string, err error) {
	self, err := executable()
	if err != nil {
		return nil, "", err
	}
	spec, err := json.Marshal(home)
	if err != nil {
		return nil, "", err
	}
	env = append(append([]string{}, env...), envBrainHome+"="+string(spec))
	cmd, err := r.Command(ctx, dir, env, self, append([]string{"brain-home", "--", name}, args...)...)
	if err != nil {
		return nil, "", err
	}
	stopGently(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.Stdin = strings.NewReader(stdin)
	runErr := cmd.Run()
	var res brainHomeOutcome
	if jerr := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &res); jerr != nil {
		if ctx.Err() != nil {
			return nil, "", fmt.Errorf("the brain did not finish in time")
		}
		msg := trimmed(stderr.String())
		if runErr == nil {
			runErr = errors.New("its answer was unreadable")
		}
		return nil, "", fmt.Errorf("the brain could not be run: %v: %s", runErr, msg)
	}
	if res.Exit != 0 {
		if ctx.Err() != nil {
			return nil, res.SignIn, fmt.Errorf("the brain did not finish in time")
		}
		msg := trimmed(stderr.String())
		if msg == "" {
			msg = trimmed(string(res.Stdout))
		}
		return nil, res.SignIn, fmt.Errorf("the brain stopped: exit status %d: %s", res.Exit, msg)
	}
	return res.Stdout, res.SignIn, nil
}

func trimmed(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 400 {
		s = s[:400]
	}
	return s
}
