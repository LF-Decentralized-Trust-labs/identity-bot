package server

import (
	"fmt"
	"net/http"
	"time"

	"identity-agent-core/iacrypto"
)

// Why a machine was refused, said only to the machine that can prove it is that
// machine.
//
// THE PROBLEM THIS SOLVES. A machine whose authorisation ended is told "this
// machine is not authorised to act for this identity, or its authorisation has
// ended" — the same sentence a machine that was never authorised gets, and the
// same one a typo in an identifier gets. Somebody whose paired computer stopped
// working sees a refusal that does not distinguish "you were removed" from
// "this is the wrong agent" from "something is broken", and there is nothing
// they can do with it.
//
// WHY IT WAS WRITTEN THAT WAY, AND WHY THAT REASONING WAS RIGHT. The grant is
// consulted before the signature is checked. At that point nobody has proved
// anything: the identifier is just a string somebody sent. Saying "that machine
// was authorised until Tuesday" to an unproven caller would let anyone walk a
// list of identifiers and learn which ones an identity has ever trusted, which
// is a map of somebody's devices.
//
// WHAT CHANGES IT. A machine's identifier IS its public key — the
// non-transferable form, with no inception event and nothing published — so a
// signature can be checked against the identifier itself, with nothing stored
// and no grant needed. Telling a caller that produces one what happened to that
// machine's authorisation reveals nothing it could not already establish.
//
// WHAT THE CHECK ESTABLISHES, EXACTLY: a valid signature over this request
// inside the freshness window. Usually that is the machine itself, since the
// private half never leaves it — but a captured request replayed within the
// window satisfies it too, because the replay guard is spent only on the
// admitting path.
//
// Spending it here was considered and rejected. Anyone holding a captured
// signature could then burn it by presenting it to a refusal first, and the
// genuine request would fail as already used — trading a small disclosure for a
// repeatable denial of the admitting path. So the residual stands: somebody who
// already watched a machine sign to this agent can, for the length of the
// window, also learn that its authorisation ended. They observed that machine
// signing here already, and the message names nothing else.
//
// Anyone can of course mint an identifier and sign with it, and will be told
// their invented machine is not authorised here — which is true, and says
// nothing about anybody's real devices. The list stays closed.
//
// This runs ONLY on the refusal path. The admitting path is untouched: it still
// verifies against the key recorded in the grant, so nothing here can widen what
// is accepted. The worst a bug in this file can do is word a rejection badly.
func (s *CoreServer) whyThisMachineWasNotAdmitted(
	r *http.Request, aid, sig, stamp string, now time.Time,
) error {
	// The refusal every unproven caller gets, unchanged from before.
	vague := fmt.Errorf(
		"this machine is not authorised to act for this identity, or its authorisation has ended")

	if !s.thisRequestWasSignedBy(r, aid, sig, stamp, now) {
		return vague
	}

	// Proven. Now say what actually happened, and what to do about it.
	all, err := s.controllers().All()
	if err != nil {
		return vague
	}
	for _, g := range all {
		if g.ControllerAID != aid {
			continue
		}
		if _, why := g.Live(now); why != "" {
			return fmt.Errorf("this machine is no longer authorised to act for this identity: %s. "+
				"Ask the owner to authorise it again from the machine holding the identity", why)
		}
		break
	}

	// No record of it at all. Two different histories end here and the agent
	// cannot tell them apart, because revoking a grant DELETES it — the record
	// was the whole authorisation, so removing it is the whole revocation.
	// Restoring a backup lands here too: an archive never carries which machines
	// may act, so a restored identity starts with none.
	//
	// So this says what is true of all of them rather than guessing at one, and
	// names the single action that resolves every case.
	//
	// The phrase "not authorised" is deliberate rather than incidental: a test
	// elsewhere holds every refusal on this path to saying plainly that the
	// authorisation is gone, and wording that only implies it would pass a
	// reader and fail that.
	return fmt.Errorf("this machine is not authorised by this identity. It may have been " +
		"removed, or this identity may have been restored from a backup, which never " +
		"carries which machines may act. Authorise this machine again from the machine " +
		"holding the identity")
}

// thisRequestWasSignedBy reports whether this request really was signed by the
// machine its identifier names.
//
// Verified against the key inside the identifier rather than against a grant,
// because the whole point is to answer for machines no grant mentions. That is
// the ONLY difference from the admitting path; the string being checked comes
// from the same place, so neither can drift from the other.
func (s *CoreServer) thisRequestWasSignedBy(
	r *http.Request, aid, sig, stamp string, now time.Time,
) bool {
	pub, err := iacrypto.KeyFromMachineIdentifier(aid)
	if err != nil {
		return false
	}
	verkey, err := iacrypto.MachineVerkeyForKey(pub)
	if err != nil {
		return false
	}

	// The same string the admitting path checks, built by the same function, so
	// the two cannot come to disagree about what a controller signs. The key is
	// the only thing that differs here, and that difference is the whole point.
	signed, _, err := s.theStringThisMachineSigned(r, aid, stamp, now)
	if err != nil {
		return false
	}
	ok, err := iacrypto.VerifyMachineSignature(verkey, sig, []byte(signed))
	return err == nil && ok
}
