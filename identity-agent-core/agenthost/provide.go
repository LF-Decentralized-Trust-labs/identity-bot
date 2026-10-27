package agenthost

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"identity-agent-core/agentmachine"
)

// Making machines for other AI agents.
//
// A body whose AI agent may make machines (agent.machine.provide) runs
// `agent-host provide`. It collects work from its Identity Agent, saying each
// time what the machines it makes can provide, and does it with one program
// the operator gives it, called three ways:
//
//	PROGRAM make NAME NEEDS   make the machine, with agent-host on it; NEEDS is
//	                          a comma-separated list of what it must provide,
//	                          possibly empty. Exit 0 once it is ready to enrol.
//	PROGRAM enrol NAME        the one-time enrolment string is on standard
//	                          input; start `agent-host enrol` on the machine
//	                          and print its six words as one line,
//	                          "words: w1 w2 w3 w4 w5 w6". Exit 0 once the
//	                          machine has asked; a person approves it later.
//	PROGRAM remove NAME       destroy the machine. Exit 0 when it is gone,
//	                          including when it never existed.
//
// How a machine is made — a virtual machine, a container, a cloud instance —
// is the program's business. This side only carries the work, and never makes
// a machine a body: a person still compares its six words and approves it.

// ProvideOptions configures a provider.
type ProvideOptions struct {
	// Program makes, enrols and removes machines.
	Program string
	// Offers is what the machines it makes can provide.
	Offers []string
	// MakeTimeout bounds making one machine; zero is an hour.
	MakeTimeout time.Duration
	Logger      *log.Logger
}

// machineRequest is one piece of work, as the Identity Agent gives it.
type machineRequest struct {
	ID          string   `json:"id"`
	State       string   `json:"state"`
	MachineName string   `json:"machine_name"`
	AgentName   string   `json:"agent_name"`
	Needs       []string `json:"needs"`
}

// Provide collects and does work making machines until ctx ends.
func (h *Host) Provide(ctx context.Context, opts ProvideOptions) error {
	if opts.Program == "" {
		return errors.New("a provider needs the program that makes machines (--program)")
	}
	if _, err := os.Stat(opts.Program); err != nil {
		return fmt.Errorf("the program that makes machines: %w", err)
	}
	offers, err := agentmachine.Needs(opts.Offers)
	if err != nil {
		return err
	}
	opts.Offers = offers
	if opts.MakeTimeout == 0 {
		opts.MakeTimeout = time.Hour
	}
	logf := log.Printf
	if opts.Logger != nil {
		logf = opts.Logger.Printf
	}
	logf("[agent-host] making machines that provide %v, with %s", describeNeeds(offers), opts.Program)
	p := &provider{h: h, opts: opts, logf: logf, busy: map[string]bool{}, failedAt: map[string]time.Time{}}
	backoff := time.Second
	for ctx.Err() == nil {
		jobs, err := p.collect(ctx)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			wait := backoff + time.Duration(rand.Int63n(int64(backoff/2)+1))
			logf("[agent-host] could not collect work (%v); trying again in %s", err, wait.Round(time.Second))
			select {
			case <-time.After(wait):
			case <-ctx.Done():
			}
			if backoff *= 2; backoff > time.Minute {
				backoff = time.Minute
			}
			continue
		}
		backoff = time.Second
		for _, j := range jobs {
			p.start(ctx, j)
		}
		// Work already being done comes back on every collection; without a
		// pause, a collection that returns at once would spin.
		if len(jobs) > 0 {
			select {
			case <-time.After(5 * time.Second):
			case <-ctx.Done():
			}
		}
	}
	p.wg.Wait()
	return nil
}

func describeNeeds(n []string) string {
	if len(n) == 0 {
		return "messaging only"
	}
	return strings.Join(n, ", ")
}

type provider struct {
	h    *Host
	opts ProvideOptions
	logf func(string, ...any)
	wg   sync.WaitGroup

	mu       sync.Mutex
	busy     map[string]bool
	failedAt map[string]time.Time
}

func (p *provider) collect(ctx context.Context) ([]machineRequest, error) {
	q := url.Values{"offers": {strings.Join(p.opts.Offers, ",")}, "wait": {"1"}}
	code, b, err := p.h.CallContext(ctx, "GET", "/api/agent-host/machine-requests?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("the Identity Agent answered %d: %s", code, b)
	}
	var out struct {
		Requests []machineRequest `json:"requests"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("the work is unreadable: %w", err)
	}
	return out.Requests, nil
}

// retryRemoveAfter is how long a removal that failed waits before it is tried
// again.
const retryRemoveAfter = time.Minute

// start does one request in the background, unless it is already being done.
func (p *provider) start(ctx context.Context, j machineRequest) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.busy[j.ID] || time.Since(p.failedAt[j.ID]) < retryRemoveAfter {
		return
	}
	p.busy[j.ID] = true
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		ok := true
		switch j.State {
		case agentmachine.StateWaiting:
			p.make(ctx, j)
		case agentmachine.StateMaking:
			// Being made, but not by this run of the provider: it stopped
			// part way, so what it made is destroyed and the request ends.
			p.abandon(ctx, j)
		case agentmachine.StateRemoving:
			ok = p.remove(ctx, j)
		}
		p.mu.Lock()
		delete(p.busy, j.ID)
		if !ok {
			p.failedAt[j.ID] = time.Now()
		} else {
			delete(p.failedAt, j.ID)
		}
		p.mu.Unlock()
	}()
}

// check refuses a request this provider must not pass to its program: a name
// it would not have been given, or a need it does not offer.
func (p *provider) check(j machineRequest) error {
	if !agentmachine.ValidMachineName(j.MachineName) {
		return fmt.Errorf("the machine name %q is not one this provider uses", j.MachineName)
	}
	needs, err := agentmachine.Needs(j.Needs)
	if err != nil {
		return err
	}
	if m := agentmachine.Missing(needs, p.opts.Offers); len(m) > 0 {
		return fmt.Errorf("this provider does not provide %s", strings.Join(m, ", "))
	}
	return nil
}

func (p *provider) make(ctx context.Context, j machineRequest) {
	if err := p.check(j); err != nil {
		p.report(ctx, j, agentmachine.StateFailed, err.Error(), nil)
		return
	}
	p.logf("[agent-host] making %s for %s, providing %s", j.MachineName, j.AgentName, describeNeeds(j.Needs))
	if !p.report(ctx, j, agentmachine.StateMaking, "making the machine", nil) {
		return
	}
	fail := func(why string) {
		p.logf("[agent-host] %s failed: %s; destroying what was made", j.MachineName, why)
		if _, err := p.run(ctx, "remove", j, nil); err != nil {
			why += "; destroying what was made also failed: " + err.Error()
		}
		p.report(ctx, j, agentmachine.StateFailed, why, nil)
	}
	mctx, cancel := context.WithTimeout(ctx, p.opts.MakeTimeout)
	_, err := p.run(mctx, "make", j, nil, strings.Join(j.Needs, ","))
	cancel()
	if err != nil {
		fail("making it: " + err.Error())
		return
	}
	p.report(ctx, j, agentmachine.StateMaking, "made; enrolling it", nil)
	code, b, err := p.h.CallContext(ctx, "POST", "/api/agent-host/machine-requests/"+j.ID+"/enrolment", []byte("{}"))
	if err == nil && code != http.StatusCreated {
		err = fmt.Errorf("the Identity Agent answered %d: %s", code, b)
	}
	var e struct {
		Enrolment string `json:"enrolment"`
	}
	if err == nil {
		err = json.Unmarshal(b, &e)
	}
	if err != nil || e.Enrolment == "" {
		fail(fmt.Sprintf("no enrolment string: %v", err))
		return
	}
	out, err := p.run(ctx, "enrol", j, strings.NewReader(e.Enrolment+"\n"))
	if err != nil {
		fail("enrolling it: " + err.Error())
		return
	}
	words := wordsIn(out)
	if len(words) != 6 {
		fail("the program did not print the machine's six words")
		return
	}
	if p.report(ctx, j, agentmachine.StateEnrolling, "waiting for a person to compare its six words", words) {
		p.logf("[agent-host] %s asked to become the body of %s; its words are %s", j.MachineName, j.AgentName, strings.Join(words, " "))
	}
}

func (p *provider) abandon(ctx context.Context, j machineRequest) {
	why := "the provider stopped while making it"
	if agentmachine.ValidMachineName(j.MachineName) {
		if _, err := p.run(ctx, "remove", j, nil); err != nil {
			why += "; destroying what was made failed: " + err.Error()
		}
	}
	p.logf("[agent-host] %s: %s", j.MachineName, why)
	p.report(ctx, j, agentmachine.StateFailed, why, nil)
}

func (p *provider) remove(ctx context.Context, j machineRequest) bool {
	if !agentmachine.ValidMachineName(j.MachineName) {
		p.logf("[agent-host] not removing %q: not a name this provider uses", j.MachineName)
		return false
	}
	p.logf("[agent-host] destroying %s", j.MachineName)
	if _, err := p.run(ctx, "remove", j, nil); err != nil {
		p.report(ctx, j, agentmachine.StateRemoving, "destroying it failed, trying again: "+err.Error(), nil)
		return false
	}
	return p.report(ctx, j, agentmachine.StateRemoved, "destroyed", nil)
}

// wordsIn finds the "words:" line the program prints.
func wordsIn(out string) []string {
	sc := bufio.NewScanner(strings.NewReader(out))
	var words []string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if rest, ok := strings.CutPrefix(line, "words:"); ok {
			words = strings.Fields(rest)
		}
	}
	return words
}

// report tells the Identity Agent how a request is going, trying a few times.
func (p *provider) report(ctx context.Context, j machineRequest, state, detail string, words []string) bool {
	body, _ := json.Marshal(map[string]any{"state": state, "detail": detail, "words": words})
	var last error
	for i := 0; i < 5 && ctx.Err() == nil; i++ {
		code, b, err := p.h.CallContext(ctx, "POST", "/api/agent-host/machine-requests/"+j.ID, body)
		if err == nil && code == http.StatusOK {
			return true
		}
		if err == nil {
			last = fmt.Errorf("the Identity Agent answered %d: %s", code, b)
			if code < 500 {
				break
			}
		} else {
			last = err
		}
		select {
		case <-time.After(time.Duration(i+1) * 3 * time.Second):
		case <-ctx.Done():
		}
	}
	p.logf("[agent-host] could not report %s on %s: %v", state, j.MachineName, last)
	return false
}

// run calls the program, keeping what it printed in a log beside this
// machine's state, and returns it. A failure carries the program's last line.
func (p *provider) run(ctx context.Context, verb string, j machineRequest, stdin io.Reader, extra ...string) (string, error) {
	args := append([]string{verb, j.MachineName}, extra...)
	cmd := exec.CommandContext(ctx, p.opts.Program, args...)
	cmd.Stdin = stdin
	cmd.Env = append(os.Environ(), "AGENT_MACHINE_FOR="+j.AgentName)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	dir := filepath.Join(p.h.DataDir, "machines")
	if mkErr := os.MkdirAll(dir, 0o700); mkErr == nil {
		f, ferr := os.OpenFile(filepath.Join(dir, j.MachineName+".log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if ferr == nil {
			fmt.Fprintf(f, "== %s %s at %s\n%s\n", verb, j.MachineName, time.Now().UTC().Format(time.RFC3339), out.String())
			f.Close()
		}
	}
	if err != nil {
		return out.String(), fmt.Errorf("%v: %s", err, lastLine(out.String()))
	}
	return out.String(), nil
}

func lastLine(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	l := strings.TrimSpace(lines[len(lines)-1])
	if len(l) > 300 {
		l = l[:300]
	}
	return l
}
