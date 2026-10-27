// Package agentmachine keeps what an AI agent's machine must provide, the
// machines that offer to make one, and each request to make one.
//
// Two kinds of need are kept apart. What a machine PROVIDES (a screen, a code
// toolchain, Xcode) decides where an AI agent can run and how its machine is
// built. What SERVICES it may use (a repository, a design tool) are capability
// grants, the same on any machine. This package is only the first kind.
//
// A provider is a live body whose AI agent's grant lets it make machines. It
// says what it can provide each time it collects work. A person asks a
// provider for a new machine for an AI agent; the provider makes it, gives it
// a one-time enrolment string, and reports the six words the new machine
// shows. A person still approves those words, as for any machine. Removing
// that machine asks its provider to destroy it.
package agentmachine

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// What a machine can provide.
const (
	// Screen is a virtual screen that never sleeps or locks, and a browser,
	// for computer use.
	Screen = "screen"
	// Toolchain is a code toolchain: git, compilers and package managers.
	Toolchain = "toolchain"
	// Xcode is Apple's toolchain, which runs only on a Mac.
	Xcode = "xcode"
)

// Known is every need, in the order a screen lists them.
var Known = []string{Screen, Toolchain, Xcode}

// Needs normalises a list of needs: known, each once, in Known's order. An
// unknown need is an error rather than dropped, so a request for something
// nothing understands is not silently granted less.
func Needs(in []string) ([]string, error) {
	out := []string{}
	for _, n := range in {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" {
			continue
		}
		if !slices.Contains(Known, n) {
			return nil, fmt.Errorf("%q is not something a machine can be asked to provide; known: %s", n, strings.Join(Known, ", "))
		}
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return slices.Index(Known, out[i]) < slices.Index(Known, out[j]) })
	return out, nil
}

// Missing is what of needs a provider offering offers does not.
func Missing(needs, offers []string) []string {
	var out []string
	for _, n := range needs {
		if !slices.Contains(offers, n) {
			out = append(out, n)
		}
	}
	return out
}

// Job states.
const (
	// StateWaiting: asked for, not yet picked up by its provider.
	StateWaiting = "waiting"
	// StateMaking: the provider is making the machine.
	StateMaking = "making"
	// StateEnrolling: the machine has asked to become the AI agent's body,
	// and waits for a person to compare its six words.
	StateEnrolling = "enrolling"
	// StateReady: the machine is the AI agent's live body.
	StateReady = "ready"
	// StateFailed: the provider could not make it, and destroyed what it made.
	StateFailed = "failed"
	// StateRemoving: a person removed it; its provider is to destroy it.
	StateRemoving = "removing"
	// StateRemoved: destroyed, or never made.
	StateRemoved = "removed"
)

// Job is one request for a new machine for one AI agent, made by one provider.
type Job struct {
	ID string `json:"id"`
	// AgentAssetID and AgentName are the AI agent the machine is for.
	AgentAssetID string `json:"agent_asset_id"`
	AgentName    string `json:"agent_name"`
	// Provider is the body (binding id) asked to make it, ProviderName the
	// name of that body's AI agent.
	Provider     string   `json:"provider"`
	ProviderName string   `json:"provider_name"`
	Needs        []string `json:"needs"`
	// MachineName is what the provider calls the machine it makes.
	MachineName string `json:"machine_name"`
	State       string `json:"state"`
	// Detail is the provider's last word on progress or failure, as it said it.
	Detail string `json:"detail,omitempty"`
	// Words are the six words the provider reports its new machine showing.
	Words []string `json:"words,omitempty"`
	// Body is the binding the new machine enrolled as, once its words are
	// matched to a request waiting for approval.
	Body        string    `json:"body,omitempty"`
	RequestedBy string    `json:"requested_by"`
	RequestedAt time.Time `json:"requested_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Done says the job has nothing left for its provider to do.
func (j Job) Done() bool {
	return j.State == StateRemoved || j.State == StateFailed
}

// Provider is a body that has offered to make machines.
type Provider struct {
	Body     string    `json:"body"`
	Name     string    `json:"name"`
	Offers   []string  `json:"offers"`
	Platform string    `json:"platform,omitempty"`
	LastSeen time.Time `json:"last_seen"`
}

// OnlineWithin is how recently a provider must have collected work to be
// offered: a provider long-polls, so one that has not asked for this long is
// not running.
const OnlineWithin = 2 * time.Minute

// Online says whether the provider has asked for work recently.
func (p Provider) Online(now time.Time) bool { return now.Sub(p.LastSeen) < OnlineWithin }

type storeFile struct {
	Providers []Provider `json:"providers"`
	Jobs      []Job      `json:"jobs"`
}

// Store keeps providers and jobs in one file, under one lock.
type Store struct {
	mu      sync.Mutex
	path    string
	changed chan struct{}
}

// NewStore opens the store in dataDir.
func NewStore(dataDir string) *Store {
	return &Store{path: filepath.Join(dataDir, "agent_machines.json"), changed: make(chan struct{})}
}

// Changed is closed the next time a job changes, so a provider waiting for
// work hears of it at once.
func (s *Store) Changed() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.changed
}

func (s *Store) notify() {
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *Store) load() (storeFile, error) {
	var f storeFile
	b, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(b, &f); err != nil {
		return f, fmt.Errorf("the machine store is unreadable: %w", err)
	}
	return f, nil
}

func (s *Store) save(f storeFile) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Seen records a provider asking for work, and what it offers now.
func (s *Store) Seen(p Provider) error {
	offers, err := Needs(p.Offers)
	if err != nil {
		return err
	}
	p.Offers = offers
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return err
	}
	i := slices.IndexFunc(f.Providers, func(q Provider) bool { return q.Body == p.Body })
	if i < 0 {
		f.Providers = append(f.Providers, p)
	} else {
		f.Providers[i] = p
	}
	return s.save(f)
}

// Forget removes a provider, as when its body is removed.
func (s *Store) Forget(body string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return err
	}
	f.Providers = slices.DeleteFunc(f.Providers, func(p Provider) bool { return p.Body == body })
	return s.save(f)
}

// Providers lists every provider that has offered, newest first.
func (s *Store) Providers() ([]Provider, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return nil, err
	}
	sort.SliceStable(f.Providers, func(i, j int) bool { return f.Providers[i].LastSeen.After(f.Providers[j].LastSeen) })
	return f.Providers, nil
}

var machineNameRule = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

// ValidMachineName says whether a name is one this package would give a
// machine: what a provider passes on to a command that makes it.
func ValidMachineName(name string) bool { return machineNameRule.MatchString(name) }

// machineName is "agent-" and the AI agent's name, lowercased to letters,
// digits and dashes, and four random hex digits, so two machines for one AI
// agent never share a name.
func machineName(agentName string) (string, error) {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(agentName) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case !dash && b.Len() > 0:
			b.WriteByte('-')
			dash = true
		}
	}
	slug := strings.Trim(b.String(), "-")
	if len(slug) > 24 {
		slug = strings.Trim(slug[:24], "-")
	}
	suffix, err := randomHex(2)
	if err != nil {
		return "", err
	}
	if slug == "" {
		return "agent-" + suffix, nil
	}
	return "agent-" + slug + "-" + suffix, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ErrNotOffered is a provider asked for something it does not provide.
var ErrNotOffered = errors.New("that provider does not offer everything this AI agent's machine needs")

// Ask records a request for a new machine. The provider must be one that has
// offered and still offers every need.
func (s *Store) Ask(agentAssetID, agentName, provider string, needs []string, by string, now time.Time) (Job, error) {
	needs, err := Needs(needs)
	if err != nil {
		return Job{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return Job{}, err
	}
	i := slices.IndexFunc(f.Providers, func(p Provider) bool { return p.Body == provider })
	if i < 0 {
		return Job{}, errors.New("no machine by that id offers to make machines here")
	}
	p := f.Providers[i]
	if m := Missing(needs, p.Offers); len(m) > 0 {
		return Job{}, fmt.Errorf("%w (it does not provide %s)", ErrNotOffered, strings.Join(m, ", "))
	}
	id, err := randomHex(8)
	if err != nil {
		return Job{}, err
	}
	name, err := machineName(agentName)
	if err != nil {
		return Job{}, err
	}
	j := Job{
		ID: id, AgentAssetID: agentAssetID, AgentName: agentName, Provider: provider, ProviderName: p.Name,
		Needs: needs, MachineName: name, State: StateWaiting, RequestedBy: by, RequestedAt: now.UTC(), UpdatedAt: now.UTC(),
	}
	f.Jobs = append(f.Jobs, j)
	if err := s.save(f); err != nil {
		return Job{}, err
	}
	s.notify()
	return j, nil
}

// Get returns one job.
func (s *Store) Get(id string) (Job, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return Job{}, false
	}
	i := slices.IndexFunc(f.Jobs, func(j Job) bool { return j.ID == id })
	if i < 0 {
		return Job{}, false
	}
	return f.Jobs[i], true
}

// ForAgent lists one AI agent's jobs, newest first.
func (s *Store) ForAgent(agentAssetID string) []Job {
	return s.where(func(j Job) bool { return j.AgentAssetID == agentAssetID })
}

// ForProvider lists what one provider has to do: machines to make, machines
// to destroy, and machines it was making — which a provider that is not making
// them any more, because it restarted, destroys and reports failed.
func (s *Store) ForProvider(provider string) []Job {
	return s.where(func(j Job) bool {
		return j.Provider == provider && (j.State == StateWaiting || j.State == StateMaking || j.State == StateRemoving)
	})
}

// ForBody finds the job that made a machine, by the binding it enrolled as.
func (s *Store) ForBody(body string) (Job, bool) {
	js := s.where(func(j Job) bool { return j.Body == body })
	if len(js) == 0 {
		return Job{}, false
	}
	return js[0], true
}

func (s *Store) where(keep func(Job) bool) []Job {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return nil
	}
	out := []Job{}
	for _, j := range f.Jobs {
		if keep(j) {
			out = append(out, j)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].RequestedAt.After(out[j].RequestedAt) })
	return out
}

// Which states a provider may report from which. A provider never reports a
// job ready: only a person's approval makes a machine a body.
var providerMoves = map[string][]string{
	StateWaiting:   {StateMaking, StateFailed},
	StateMaking:    {StateMaking, StateEnrolling, StateFailed},
	StateEnrolling: {StateEnrolling, StateFailed},
	StateRemoving:  {StateRemoving, StateRemoved},
}

// ErrMove is a state change the job cannot make from where it is.
var ErrMove = errors.New("the machine cannot move to that state from where it is")

// Report is a provider saying how a job is going. Only the job's own provider
// may report on it.
func (s *Store) Report(id, provider, state, detail string, words []string, now time.Time) (Job, error) {
	return s.update(id, func(j *Job) error {
		if j.Provider != provider {
			return errors.New("that machine is not one this provider was asked to make")
		}
		if !slices.Contains(providerMoves[j.State], state) {
			return fmt.Errorf("%w (%s to %s)", ErrMove, j.State, state)
		}
		j.State = state
		if len(detail) > 500 {
			detail = detail[:500]
		}
		j.Detail = detail
		if len(words) > 0 {
			if len(words) != 6 {
				return errors.New("a machine shows six words")
			}
			j.Words = words
		}
		return nil
	}, now)
}

// Bound records that the machine a job made has enrolled as a body.
func (s *Store) Bound(id, body string, now time.Time) (Job, error) {
	return s.update(id, func(j *Job) error {
		j.Body = body
		return nil
	}, now)
}

// Approved moves a job whose machine a person approved to ready.
func (s *Store) Approved(body string, now time.Time) {
	if j, ok := s.ForBody(body); ok && j.State == StateEnrolling {
		_, _ = s.update(j.ID, func(j *Job) error { j.State = StateReady; return nil }, now)
	}
}

// Remove asks a job's provider to destroy what it made. A job whose machine
// was never started is simply over. Removing a removed job is not an error.
func (s *Store) Remove(id string, now time.Time) (Job, error) {
	return s.update(id, func(j *Job) error {
		switch j.State {
		case StateWaiting:
			j.State, j.Detail = StateRemoved, "cancelled before it was made"
		case StateRemoved, StateRemoving:
		default:
			j.State, j.Detail = StateRemoving, ""
		}
		return nil
	}, now)
}

func (s *Store) update(id string, change func(*Job) error, now time.Time) (Job, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.load()
	if err != nil {
		return Job{}, err
	}
	i := slices.IndexFunc(f.Jobs, func(j Job) bool { return j.ID == id })
	if i < 0 {
		return Job{}, errors.New("no such machine request")
	}
	j := f.Jobs[i]
	if err := change(&j); err != nil {
		return Job{}, err
	}
	j.UpdatedAt = now.UTC()
	f.Jobs[i] = j
	if err := s.save(f); err != nil {
		return Job{}, err
	}
	s.notify()
	return j, nil
}
