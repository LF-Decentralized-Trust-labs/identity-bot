package recovery

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// The third gate: is the person recovering acting freely.
//
// Neither of the other two can answer this. The recovery phrase proves control
// of the identity. An authentication provider proves the person is its owner.
// Somebody held at knifepoint satisfies both perfectly, and so does somebody
// being walked through it while confused or medicated.
//
// Two things can speak to it, and they are not equal:
//
//   - TIME. A waiting period gives somebody a chance to notice and stop it. It
//     is the weaker answer to coercion, because a coercer will simply wait out
//     the window alongside their victim. It helps most where the phrase was
//     copied rather than extracted — a photographed page, a cloud note — and
//     the owner still holds a device that can raise the alarm.
//   - PEOPLE. Somebody who knows the owner can see that the request is wrong in
//     a way no timer can. This is the stronger answer, and the only one that
//     addresses being forced.
//
// Off by default, deliberately. Nobody has data on what people actually want
// here, and a protection that locks somebody out of their own identity is not
// obviously better than no protection at all. What is not deliberate is
// leaving it off forever: the default is a decision waiting on evidence, not a
// verdict.
type DuressProtection string

const (
	// DuressNone is the default: nothing stands between a correct phrase, a
	// passing authentication, and the identity.
	DuressNone DuressProtection = "none"

	// DuressWait holds a recovery for a fixed period so somebody has a chance
	// to notice it.
	DuressWait DuressProtection = "wait"

	// DuressTrustedContacts requires people the owner named to agree that this
	// recovery should proceed.
	//
	// The strongest of the three, because a person can judge whether somebody
	// is being forced and a clock cannot.
	DuressTrustedContacts DuressProtection = "trusted_contacts"

	// DuressBoth requires both, for somebody who wants the alarm raised AND a
	// human to answer it.
	DuressBoth DuressProtection = "both"
)

// trustedContactsCanApprove is false until a trusted contact has some way to
// say yes.
//
// A constant rather than a comment, so the shape below stays compiled and
// tested while the option it guards stays unreachable — and so turning it on is
// one edit rather than a reconstruction.
const trustedContactsCanApprove = false

// TrustedContact is somebody the owner named to vouch for a recovery.
//
// Identified by their own identifier and never by an email address or a phone
// number. A contact reachable only at a handle is a contact an attacker can
// take over — a SIM swap or a mailbox compromise would let them approve a
// recovery in that person's name, and the owner would see an approval that
// looked genuine.
type TrustedContact struct {
	AID   string `json:"aid"`
	Label string `json:"label,omitempty"`
	// AddedAt records when this person was named, so a contact added moments
	// before a recovery is visible as such.
	AddedAt string `json:"added_at,omitempty"`
}

// DuressPolicy is what an identity has chosen about the third gate.
type DuressPolicy struct {
	Protection DuressProtection `json:"protection"`

	// WaitHours applies when the protection includes waiting.
	WaitHours int `json:"wait_hours,omitempty"`

	// Contacts are the people who may vouch, and Approvals is how many of them
	// must.
	//
	// A threshold rather than all of them, because requiring everybody means
	// one person who has died, changed devices or fallen out with the owner can
	// lock them out permanently.
	Contacts  []TrustedContact `json:"contacts,omitempty"`
	Approvals int              `json:"approvals,omitempty"`
}

// DefaultDuressPolicy is what an identity has before anybody chooses.
func DefaultDuressPolicy() DuressPolicy {
	return DuressPolicy{Protection: DuressNone, WaitHours: 24, Approvals: 1}
}

// Validate reports whether this policy can actually be satisfied.
//
// A policy nobody can meet is worse than no policy: it does not protect the
// owner from an attacker, it protects the identity from its owner. Naming two
// contacts and requiring three approvals is a lockout with a reassuring name,
// so it is refused at the moment it is set rather than discovered during a
// recovery.
func (p DuressPolicy) Validate() error {
	switch p.Protection {
	case DuressNone:
		return nil
	case DuressWait, DuressTrustedContacts, DuressBoth:
	default:
		return fmt.Errorf("%q is not something this gate can do", p.Protection)
	}

	if p.Protection == DuressWait || p.Protection == DuressBoth {
		if p.WaitHours <= 0 {
			return fmt.Errorf("a waiting period of %d hours is not a waiting period", p.WaitHours)
		}
		if p.WaitHours > 30*24 {
			return fmt.Errorf("a waiting period of %d hours is long enough to be a lockout", p.WaitHours)
		}
	}

	if p.Protection == DuressTrustedContacts || p.Protection == DuressBoth {
		// Nothing can approve yet, so choosing this is choosing a lockout.
		//
		// Session.DuressApprovals is read when a recovery completes and is
		// written by nothing: there is no route a trusted contact can use to
		// say yes. A policy requiring them is therefore never satisfiable, and
		// this function exists precisely to refuse a policy that cannot be met
		// rather than let somebody discover it during a recovery. It was
		// green-lighting the one case it was written to catch.
		//
		// Removed when there is a route a trusted contact can approve through,
		// and not before.
		if !trustedContactsCanApprove {
			return fmt.Errorf("trusted contacts cannot approve a recovery yet, so requiring them " +
				"would mean no recovery could ever complete. Use a waiting period until that is built")
		}

		if len(p.Contacts) == 0 {
			return fmt.Errorf("trusted contacts are required and nobody is named")
		}
		if p.Approvals <= 0 {
			return fmt.Errorf("trusted contacts are required and no number of them is")
		}
		if p.Approvals > len(p.Contacts) {
			return fmt.Errorf("this asks for %d approvals from %d people, which nobody can satisfy",
				p.Approvals, len(p.Contacts))
		}
		seen := map[string]bool{}
		for _, c := range p.Contacts {
			if c.AID == "" {
				return fmt.Errorf("a trusted contact must be identified by their own identifier")
			}
			if seen[c.AID] {
				// The same person twice is a threshold of two satisfied by one
				// approval, which is not what the owner asked for.
				return fmt.Errorf("the same person is named twice, so a threshold could be met by one of them")
			}
			seen[c.AID] = true
		}
	}
	return nil
}

// Held reports whether this recovery may proceed, and says what is missing.
//
// startedAt is when the recovery began; approvals are the contacts who have
// vouched so far.
func (p DuressPolicy) Held(startedAt time.Time, approvals []string, now time.Time) error {
	if p.Protection == DuressNone {
		return nil
	}

	if p.Protection == DuressWait || p.Protection == DuressBoth {
		ready := startedAt.Add(time.Duration(p.WaitHours) * time.Hour)
		if now.Before(ready) {
			return &ErrHeldForDuress{
				Reason: fmt.Sprintf("this identity holds a recovery for %d hours so somebody has a "+
					"chance to notice it", p.WaitHours),
				Until: ready,
			}
		}
	}

	if p.Protection == DuressTrustedContacts || p.Protection == DuressBoth {
		named := map[string]bool{}
		for _, c := range p.Contacts {
			named[c.AID] = true
		}
		// Counted as a set. Somebody approving twice is one person agreeing
		// once, and counting it twice would let one contact satisfy a threshold
		// of two.
		got := map[string]bool{}
		for _, a := range approvals {
			if named[a] {
				got[a] = true
			}
		}
		if len(got) < p.Approvals {
			return &ErrHeldForDuress{
				Reason: fmt.Sprintf("this identity asks %d of the people it trusts to confirm a "+
					"recovery, and %d have", p.Approvals, len(got)),
				NeedsApprovals: p.Approvals - len(got),
			}
		}
	}
	return nil
}

// ErrHeldForDuress means the recovery is waiting on the third gate.
//
// A distinct type because it is not a refusal. The phrase was right and the
// person may well be the owner; something is being given a chance to notice.
type ErrHeldForDuress struct {
	Reason         string
	Until          time.Time
	NeedsApprovals int
}

func (e *ErrHeldForDuress) Error() string { return e.Reason }

// LoadDuressPolicy reads what this identity has chosen.
func (s *Service) LoadDuressPolicy() DuressPolicy {
	body, err := os.ReadFile(filepath.Join(s.DataDir, "duress_policy.json"))
	if err != nil {
		return DefaultDuressPolicy()
	}
	var p DuressPolicy
	if json.Unmarshal(body, &p) != nil || p.Protection == "" {
		return DefaultDuressPolicy()
	}
	return p
}

// SaveDuressPolicy records a choice, refusing one that cannot be met.
func (s *Service) SaveDuressPolicy(p DuressPolicy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	body, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.DataDir, 0700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(s.DataDir, "duress_policy.json"), body, 0600)
}

// duressPolicyFrom reads what the identity chose, out of the archive that
// carries it.
//
// The archive is the only place a recovering device can learn this. It has no
// local policy — that is what makes it a recovery — so anything read off local
// disk would be the default, which is no protection at all.
//
// An archive that predates the setting, or one written by an agent that never
// had it, yields the default. That is correct: an identity that never chose a
// duress policy does not have one.
func duressPolicyFrom(payload *RestoredPayload) DuressPolicy {
	if payload == nil || payload.Bundle == nil {
		return DefaultDuressPolicy()
	}
	raw, ok := payload.Bundle.Sections["file:duress_policy.json"]
	if !ok || len(raw) == 0 {
		raw, ok = payload.Bundle.Sections["duress_policy"]
	}
	if !ok || len(raw) == 0 {
		return DefaultDuressPolicy()
	}
	var p DuressPolicy
	if json.Unmarshal(raw, &p) != nil || p.Protection == "" {
		return DefaultDuressPolicy()
	}
	return p
}
