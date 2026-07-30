package provider

import (
	"fmt"
	"sort"
)

// Choosing operators so no one of them sees very much.
//
// A single operator running everything for one person sees a great deal: who
// contacts them and when, which identities they hold, when they are awake. None
// of that requires malice to be a problem — it is simply the view that comes
// with the job.
//
// Spreading the jobs across operators shrinks each view. The operator running
// somebody's relay learns their traffic; a DIFFERENT operator witnessing their
// key events learns those; neither can assemble the whole. Traffic analysis over
// a fraction of somebody's activity is much weaker than over all of it.
//
// So selection prefers an operator that is not already doing something else for
// the same identity. It is a preference and not a rule, because at the moment
// there are few operators, and refusing to select rather than reusing one would
// leave an identity with no relay at all — which is far worse than an operator
// knowing two things about it. The preference gets stronger on its own as the
// registry grows, without this code changing.
//
// Two jobs are singled out as worth separating even when the pool is small:
// witnessing and mailboxing. The witness is the stable anchor a stranded
// counterparty asks for a current address; the mailbox is the fallback used
// when the address does not answer. Putting both on one operator means one
// outage takes away both the way to reach somebody and the way to find out
// where they went.

// Selection is one chosen operator, with the reasoning kept.
//
// Why is recorded because a person should be able to see how their dependencies
// were decided, and because "we reused an operator you were already using" is a
// materially different answer from "we picked one you were not".
type Selection struct {
	Provider *Provider
	Endpoint *Endpoint
	Why      string
}

// conflictsWith names the capability pairs that should not share an operator
// even when choice is scarce.
//
// Only the pairs where sharing removes a fallback, not everything that would be
// nicer apart. A rule that fires constantly gets ignored or removed.
var conflictsWith = map[Capability][]Capability{
	CapabilityWitness: {CapabilityMailbox},
	CapabilityMailbox: {CapabilityWitness},
}

// Selector picks operators for one identity, remembering what it has already
// given away so later choices can avoid it.
type Selector struct {
	registry *Registry
	// inUse maps operator ID to the capabilities it already provides for this
	// identity.
	inUse map[string][]Capability
}

// NewSelector starts a selection for one identity.
func NewSelector(r *Registry) *Selector {
	return &Selector{registry: r, inUse: map[string][]Capability{}}
}

// Reserve records an operator already chosen — including one chosen previously
// and read back from storage, so a restart does not forget and re-concentrate.
func (s *Selector) Reserve(providerID string, c Capability) {
	s.inUse[providerID] = append(s.inUse[providerID], c)
}

// InUse reports what an operator already does for this identity.
func (s *Selector) InUse(providerID string) []Capability {
	return s.inUse[providerID]
}

// Choose picks an operator for a capability, preferring one not already in use.
//
// Returns an error rather than a poor choice when nothing offers the capability
// at all: an empty answer that looks like a decision is worse than a refusal
// that says the registry has nobody.
func (s *Selector) Choose(c Capability) (*Selection, error) {
	if !c.Known() {
		return nil, fmt.Errorf("no operator can be chosen for unknown capability %q", c)
	}
	candidates := s.registry.Offering(c)
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no operator in the registry offers %s", c)
	}

	// Rank rather than filter, so scarcity degrades the preference instead of
	// emptying the list.
	type ranked struct {
		p     *Provider
		score int
		why   string
	}
	var scored []ranked
	for _, p := range candidates {
		already := s.inUse[p.ID]
		switch {
		case len(already) == 0:
			scored = append(scored, ranked{p, 0,
				"not already used for this identity, so it learns only this one thing"})
		case conflicts(already, c):
			scored = append(scored, ranked{p, 2, fmt.Sprintf(
				"already provides %s for this identity, and sharing that with %s would put the fallback and the anchor in one place",
				already[0], c)})
		default:
			scored = append(scored, ranked{p, 1, fmt.Sprintf(
				"already provides %s for this identity, so it would learn a second thing", already[0])})
		}
	}
	sort.SliceStable(scored, func(i, j int) bool {
		if scored[i].score != scored[j].score {
			return scored[i].score < scored[j].score
		}
		return scored[i].p.ID < scored[j].p.ID
	})

	best := scored[0]
	why := best.why
	if best.score > 0 {
		// Chosen anyway, and said so. When the pool grows this stops happening
		// without anything here changing.
		why = "reused despite preference: " + why + " — the registry offers no unused operator for this job"
	}

	s.Reserve(best.p.ID, c)
	return &Selection{Provider: best.p, Endpoint: best.p.Endpoint(c), Why: why}, nil
}

// conflicts reports whether taking c would collide with something already held.
func conflicts(already []Capability, c Capability) bool {
	bad := conflictsWith[c]
	for _, held := range already {
		for _, b := range bad {
			if held == b {
				return true
			}
		}
	}
	return false
}

// Diversity reports how concentrated an identity's dependencies are: how many
// distinct operators are in use, and how many jobs the busiest one holds.
//
// Meant for showing somebody their own situation. "Three services, one
// operator" is a sentence a person can act on; a policy engine deciding it for
// them silently is not.
func (s *Selector) Diversity() (operators int, busiest int) {
	for _, caps := range s.inUse {
		operators++
		if len(caps) > busiest {
			busiest = len(caps)
		}
	}
	return operators, busiest
}
