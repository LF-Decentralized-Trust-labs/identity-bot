package agenthost

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"identity-agent-core/childenv"
)

// A brain run as its own user is started through sudo, and sudo writes to the
// system log both its command line and the value of every variable it is
// told to pass on. So nothing a run is lent crosses sudo either way. The host
// starts `agent-host brain-env -- <program> <args>` as the brain's user, with
// nothing secret in sudo's environment or on its command line, and sends the
// run's variables ahead of the brain's input on stdin: one line, then the
// input as it was. This program puts the variables in the brain's environment
// and hands the rest of the input on through a pipe of its own. The brain,
// running as the same user, can then open that pipe again by name
// (/dev/stdin), as Grok does to read its prompt; a pipe the host made belongs
// to the host's user, and the brain's user may not open it.

// brainEnvMax bounds the line of variables, which holds a sign-in at most.
const brainEnvMax = 1 << 20

// brainEnvHeader is the line `agent-host brain-env` reads first.
type brainEnvHeader struct {
	Env []string `json:"env"`
}

// brainEnvInput is what `agent-host brain-env` is given on stdin: env on one
// line, then stdin. JSON never puts a raw newline inside a string, so the
// first newline ends the line.
func brainEnvInput(env []string, stdin io.Reader) (io.Reader, error) {
	if env == nil {
		env = []string{}
	}
	h, err := json.Marshal(brainEnvHeader{Env: env})
	if err != nil {
		return nil, err
	}
	if len(h)+1 > brainEnvMax {
		return nil, errors.New("a run's variables are too large to hand to its brain")
	}
	if stdin == nil {
		stdin = strings.NewReader("")
	}
	return io.MultiReader(bytes.NewReader(append(h, '\n')), stdin), nil
}

// withoutLent is env without any variable a run could be lent — a sign-in,
// GitHub access, the git settings that point git at this program, the tool
// address and token — so sudo is never handed one, even one somebody exported
// by hand on the host. sudo would not pass it on, but nor does it need it.
func withoutLent(env []string) []string {
	names := append(append(append([]string{}, credentialVars...), githubVars...), envToolsURL, envToolsToken)
	out := make([]string, 0, len(env))
next:
	for _, kv := range env {
		for _, n := range names {
			if strings.HasPrefix(kv, n+"=") {
				continue next
			}
		}
		for _, p := range githubVarPrefixes {
			if strings.HasPrefix(kv, p) {
				continue next
			}
		}
		out = append(out, kv)
	}
	return out
}

// readBrainEnvLine reads the first line of in, up to max bytes with its
// newline. ReadSlice returns what the buffer holds when it fills before a
// newline, so the line is gathered in parts, and refused once it is longer
// than max.
func readBrainEnvLine(in *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	for {
		part, err := in.ReadSlice('\n')
		line = append(line, part...)
		if len(line) > max {
			return nil, errors.New("the run's variables are too large")
		}
		if err == nil {
			return line[:len(line)-1], nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
	}
}

// ServeBrainEnv is `agent-host brain-env -- <program> <args>`: it reads the
// run's variables from the first line of stdin, starts the program with them
// in its environment and the rest of stdin as its input, and exits as the
// program did. A signal asking it to stop is passed on to the program, so
// `agent-host brain-home` beneath it can take a sign-in file away first.
func ServeBrainEnv(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) < 2 || args[0] != "--" {
		fmt.Fprintln(stderr, "agent-host brain-env: name the brain's program to run, after --")
		return 2
	}
	args = args[1:]
	if !filepath.IsAbs(args[0]) {
		fmt.Fprintln(stderr, "agent-host brain-env: the brain's program must be named by its full path")
		return 2
	}
	// The run's variables are read into this process: nothing else running as
	// this user may read it or trace it. The program it starts is not marked
	// so; it is its own (agent-host's own loop marks itself).
	if err := notReadable(); err != nil {
		fmt.Fprintf(stderr, "agent-host brain-env: this process could not be kept from other processes: %v\n", err)
		return 1
	}
	in := bufio.NewReaderSize(stdin, 64<<10)
	line, err := readBrainEnvLine(in, brainEnvMax)
	var h brainEnvHeader
	if err == nil {
		err = json.Unmarshal(line, &h)
	}
	if err != nil {
		fmt.Fprintln(stderr, "agent-host brain-env: started without the run's variables")
		return 2
	}
	for _, kv := range h.Env {
		if i := strings.IndexByte(kv, '='); i <= 0 {
			fmt.Fprintln(stderr, "agent-host brain-env: a variable has no name")
			return 2
		}
	}

	// The program's input is a pipe made here, by the brain's user, so the
	// program may open it again by name. It must never be this program's own
	// stdin, which the host made: the brain's user may not open that one, and
	// what was read ahead past the line of variables would be lost.
	pr, pw, err := os.Pipe()
	if err != nil {
		fmt.Fprintf(stderr, "agent-host brain-env: %v\n", err)
		return 1
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = withCredentials(childenv.Environ(), h.Env)
	cmd.Stdin = pr
	cmd.Stdout, cmd.Stderr = stdout, stderr
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, interruptSignals()...)
	defer signal.Stop(sigs)
	err = cmd.Start()
	_ = pr.Close()
	if err != nil {
		_ = pw.Close()
		fmt.Fprintf(stderr, "agent-host brain-env: the brain could not be started: %v\n", err)
		return 1
	}
	// A program that stops reading ends the copy (the pipe breaks); the rest
	// of its input is dropped, as it would be had it read stdin directly.
	go func() {
		_, _ = io.Copy(pw, in)
		_ = pw.Close()
	}()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	for {
		select {
		case s := <-sigs:
			// To the program alone, as sudo passes a signal to the program
			// it started; the program ends what it started itself.
			_ = cmd.Process.Signal(s)
		case err := <-done:
			if err == nil {
				return 0
			}
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				if ee.ExitCode() > 0 {
					return ee.ExitCode()
				}
				// Ended by a signal: exit as a shell reports it.
				if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
					return 128 + int(ws.Signal())
				}
			}
			return 1
		}
	}
}
