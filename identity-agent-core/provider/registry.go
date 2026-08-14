package provider

import (
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Who runs the services an identity depends on.
//
// An Identity Agent needs other people's infrastructure to be reachable and to
// be observed: somewhere to relay inbound requests, somebody to witness key
// events, somewhere to leave a message when the relay is down. These are
// different jobs, but they are not different businesses. All of them need
// public addresses, DNS, certificates, bandwidth and somebody awake at three in
// the morning, so in practice the same operators offer several of them.
//
// One registry, therefore, with capabilities tagged per operator — rather than
// four lists that drift apart and four applications for the same operator to
// fill in.
//
// Keeping the capability distinction INSIDE the entry still matters, because
// the jobs differ in what they can do to you. A relay sees who talks to you and
// when. A witness sees signed events for one identity and is named publicly in
// its KEL. Recording them separately is what lets selection spread a person's
// dependencies across operators instead of handing one of them the whole
// picture.
//
// The registry is data rather than code. Adding an operator should not require
// shipping a release, because the point of the design is that the set grows —
// an identity that draws its services from a varied and changing set of
// operators gives any one of them a much smaller view than an identity that
// gets everything from a single provider.

//go:embed providers/*.json
var embeddedProviders embed.FS

const providersDirName = "providers"

// Capability is one job an operator can do. Kept as distinct strings rather
// than a bitmask because the registry is a document people write by hand.
type Capability string

const (
	// CapabilityRelay forwards inbound requests to an agent that has no public
	// address of its own, at an address it can hand out and expect to work
	// later.
	CapabilityRelay Capability = "relay"

	// CapabilityWitness observes an identity's key events and issues receipts,
	// which is what makes duplicity detectable.
	CapabilityWitness Capability = "witness"

	// CapabilityWatcher observes OTHER identities' key events, so that a
	// counterparty presenting a forked history can be caught.
	CapabilityWatcher Capability = "watcher"

	// CapabilityMailbox holds messages for an agent that is not reachable right
	// now — a relay that stores instead of forwarding.
	CapabilityMailbox Capability = "mailbox"

	// CapabilityTunnel is generic plumbing: a public address with no knowledge
	// of identity behind it. Fine for something immediate, wrong for anything
	// somebody has to find again later.
	CapabilityTunnel Capability = "tunnel"

	// CapabilityBackup keeps encrypted archives on somebody's behalf and hands
	// them back to whoever can open them.
	//
	// It holds ciphertext and never the key, so this is the rare provider whose
	// operator has nothing to be trusted with. What it is chosen for is
	// AVAILABILITY: a destination is only worth having if it can be reached
	// after the disaster that made it necessary, which is exactly what a
	// machine in the same building cannot promise.
	//
	// Deliberately a capability like any other, so that a person can run their
	// own, use somebody else's, or use several — the same shape as witnessing.
	CapabilityBackup Capability = "backup"
)

// Known reports whether a capability is one this agent understands. An unknown
// capability in a registry document is kept but never selected — a newer
// registry should not be rejected wholesale by an older agent.
func (c Capability) Known() bool {
	switch c {
	case CapabilityBackup, CapabilityRelay, CapabilityWitness, CapabilityWatcher,
		CapabilityMailbox, CapabilityTunnel:
		return true
	}
	return false
}

// Endpoint is where one capability of one operator is reached.
type Endpoint struct {
	Capability Capability `json:"capability"`
	URL        string     `json:"url"`
	// AID is the identity this endpoint answers as, where the capability has
	// one. A witness must have it — the witness set in a KEL names AIDs, not
	// URLs, so an entry without one cannot be designated.
	AID string `json:"aid,omitempty"`
}

// Provider is one operator and everything it offers.
type Provider struct {
	// ID is stable and is how a selection is recorded. The operator's own
	// domain is the obvious choice and the one used by the shipped entries.
	ID string `json:"id"`
	// Operator names who is actually behind this, so somebody deciding whether
	// to rely on it knows whom they are relying on.
	Operator  string     `json:"operator"`
	Endpoints []Endpoint `json:"endpoints"`
	// Jurisdiction is advisory and often empty. It is recorded because
	// spreading services across operators means little if they all answer to
	// the same authority.
	Jurisdiction string `json:"jurisdiction,omitempty"`
	// Source records where this entry came from, for showing somebody why an
	// operator is on their list. Set at load time, never read from the file.
	Source string `json:"-"`
}

// Supports reports whether this operator offers a capability.
func (p *Provider) Supports(c Capability) bool {
	return p.Endpoint(c) != nil
}

// Endpoint returns the operator's first endpoint for a capability, or nil.
func (p *Provider) Endpoint(c Capability) *Endpoint {
	for i := range p.Endpoints {
		if p.Endpoints[i].Capability == c {
			return &p.Endpoints[i]
		}
	}
	return nil
}

// EndpointsFor returns every endpoint an operator offers for a capability.
//
// More than one is normal and is not redundancy for its own sake: an operator
// commonly runs several witnesses under distinct AIDs, and a witness set drawn
// from them still names distinct observers even though one organisation is
// behind them all. Worth being able to see that, since it means the real count
// of INDEPENDENT operators is smaller than the count of endpoints.
func (p *Provider) EndpointsFor(c Capability) []Endpoint {
	var out []Endpoint
	for _, e := range p.Endpoints {
		if e.Capability == c {
			out = append(out, e)
		}
	}
	return out
}

// Capabilities lists what this operator offers, sorted, for display.
func (p *Provider) Capabilities() []Capability {
	seen := map[Capability]bool{}
	out := make([]Capability, 0, len(p.Endpoints))
	for _, e := range p.Endpoints {
		if seen[e.Capability] {
			continue
		}
		seen[e.Capability] = true
		out = append(out, e.Capability)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Document is a registry file: a set of operators, from one publisher.
type Document struct {
	Version   int        `json:"version"`
	Publisher string     `json:"publisher,omitempty"`
	Providers []Provider `json:"providers"`
	// Signature covers the document minus this field. Optional today, and its
	// absence is reported rather than treated as approval — who may sign a
	// registry is a governance question that has not been settled, and
	// inventing a trust root here would be worse than being honest about not
	// having one.
	Signature string `json:"signature,omitempty"`
}

// Registry is the loaded set of operators.
type Registry struct {
	mu        sync.RWMutex
	providers map[string]*Provider
}

// Load reads the shipped operators and any the machine's owner has added.
//
// Shipped entries are trusted exactly as far as the binary is: they arrive by
// the same route the code did. Entries from the data directory are the owner's
// own choice. Neither is fetched from the network here — a registry that
// updated itself silently would be a way to move somebody's dependencies
// without telling them.
//
// A bad file is logged and skipped, never fatal. One malformed operator entry
// must not leave an agent unable to find a witness.
func Load(dataDir string) *Registry {
	r := &Registry{providers: map[string]*Provider{}}

	entries, err := embeddedProviders.ReadDir(providersDirName)
	if err == nil {
		for _, e := range entries {
			data, rerr := embeddedProviders.ReadFile(providersDirName + "/" + e.Name())
			if rerr != nil {
				log.Printf("[provider] could not read shipped registry %s: %v", e.Name(), rerr)
				continue
			}
			r.ingest("shipped:"+e.Name(), data)
		}
	}

	if dataDir == "" {
		return r
	}
	dir := filepath.Join(dataDir, providersDirName)
	files, err := os.ReadDir(dir)
	if err != nil {
		return r // no operator-supplied registry, which is the normal case
	}
	for _, f := range files {
		if f.IsDir() || !strings.HasSuffix(f.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, f.Name())
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			log.Printf("[provider] could not read %s: %v", path, rerr)
			continue
		}
		r.ingest(path, data)
	}
	return r
}

// ingest parses one document and merges its operators in.
//
// Later documents win on ID, so the owner's own file can replace a shipped
// entry — someone who does not want to use an operator we ship should not have
// to edit the binary to say so.
func (r *Registry) ingest(source string, data []byte) {
	var doc Document
	if err := json.Unmarshal(data, &doc); err != nil {
		log.Printf("[provider] %s is not a readable registry: %v", source, err)
		return
	}
	if doc.Signature == "" && !strings.HasPrefix(source, "shipped:") {
		// Said plainly rather than silently accepted. Until who may sign a
		// registry is settled, this is trusted because it is on the owner's
		// disk, not because anything verified it.
		log.Printf("[provider] %s carries no signature — trusted because it is local, not because it was verified", source)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for i := range doc.Providers {
		p := doc.Providers[i]
		if p.ID == "" {
			log.Printf("[provider] %s has an entry with no id — skipped", source)
			continue
		}
		var usable []Endpoint
		for _, e := range p.Endpoints {
			if e.URL == "" {
				log.Printf("[provider] %s: %s offers %q with no url — skipped", source, p.ID, e.Capability)
				continue
			}
			if !e.Capability.Known() {
				// Kept out of selection but not treated as corruption: a newer
				// registry may name capabilities this build predates.
				log.Printf("[provider] %s: %s offers unknown capability %q — kept, not selectable",
					source, p.ID, e.Capability)
			}
			usable = append(usable, e)
		}
		p.Endpoints = usable
		p.Source = source
		r.providers[p.ID] = &p
	}
}

// All returns every operator, ordered by ID so listings are stable.
func (r *Registry) All() []*Provider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]*Provider, 0, len(r.providers))
	for _, p := range r.providers {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Offering returns the operators that do a given job.
func (r *Registry) Offering(c Capability) []*Provider {
	var out []*Provider
	for _, p := range r.All() {
		if !c.Known() {
			continue
		}
		if p.Supports(c) {
			out = append(out, p)
		}
	}
	return out
}

// Get returns one operator by ID.
func (r *Registry) Get(id string) (*Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.providers[id]
	return p, ok
}

// Add installs or replaces an operator at runtime, so a registry received over
// the wire can be applied without a restart.
func (r *Registry) Add(p Provider, source string) error {
	if p.ID == "" {
		return fmt.Errorf("a provider needs an id")
	}
	p.Source = source
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers[p.ID] = &p
	return nil
}

// Count is how many operators are known.
func (r *Registry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.providers)
}

// IsOfficialService reports whether an identifier or URL belongs to a
// registered operator offering the given capability.
//
// This is what "service provider" means in this codebase: an operator listed in
// the registry, offering a named capability at a named endpoint. It is a
// declaration somebody made and shipped, not a property inferred from how a
// peer happens to behave.
//
// It matters because service providers are exempt from the rule that keeps
// individuals and organizations from witnessing or watching for one another. A
// service serves a large population, so naming one discloses almost nothing
// about its subject — which is exactly what a peer of the wrong kind would
// disclose. Basing the exemption on the registry rather than on a flag stored
// per contact means the exemption is auditable: it is a line in a file, not a
// bit somebody set.
func (r *Registry) IsOfficialService(c Capability, aidOrURL string) bool {
	if r == nil || aidOrURL == "" {
		return false
	}
	for _, p := range r.Offering(c) {
		for _, e := range p.Endpoints {
			if e.Capability != c {
				continue
			}
			if e.AID != "" && e.AID == aidOrURL {
				return true
			}
			if e.URL != "" && sameHost(e.URL, aidOrURL) {
				return true
			}
		}
	}
	return false
}

// sameHost compares two URLs by host, so a trailing path or slash does not
// decide whether an operator is recognised.
func sameHost(a, b string) bool {
	ua, err := url.Parse(a)
	if err != nil || ua.Host == "" {
		return false
	}
	ub, err := url.Parse(b)
	if err != nil || ub.Host == "" {
		return false
	}
	return strings.EqualFold(ua.Host, ub.Host)
}
