package anchored

import (
	"fmt"
	"sort"

	"identity-agent-core/drivers"
	"identity-agent-core/witness"
)

// MinNonceLen is the shortest nonce a freshness question may use.
const MinNonceLen = 16

// Tip is the newest event of the publisher's history the witnesses hold.
type Tip struct {
	SN   int
	SAID string
}

// TipReply is one witness's answer, with the nonce this device sent it. The
// nonce is what makes the answer fresh: a caller sends a new random one with
// every question and records it here, and never reuses one.
type TipReply struct {
	Nonce  string
	Answer witness.TipAnswer
}

// AgreedTip decides from the witnesses' signed answers where the publisher's
// history ends. An answer counts only if it is for aid, carries the nonce this
// device sent, is signed by its own witness's key, and the witness is one of
// designated. At least threshold designated witnesses must have answered (and
// at least one), every one of them must name the same tip, and the tip must be
// one (a witness that holds nothing says so, and then there is no tip).
func AgreedTip(aid string, designated []string, threshold int, replies []TipReply) (Tip, error) {
	if threshold < 1 || len(designated) == 0 {
		return Tip{}, fmt.Errorf("%w: the publisher has no witnesses to ask", ErrNotFresh)
	}
	byWitness := map[string]Tip{}
	for _, r := range replies {
		a := r.Answer
		key, isWitness := drivers.WitnessKey(a.WitnessAID)
		if len(r.Nonce) < MinNonceLen || a.AID != aid || a.Nonce != r.Nonce || !isWitness || !drivers.Designates(designated, a.WitnessAID) {
			continue
		}
		if (a.SN >= 0) == (a.SAID == "") {
			continue
		}
		if drivers.VerifyReceipt(a.WitnessAID, witness.TipStatement(a.AID, a.Nonce, a.SN, a.SAID), a.Signature) != nil {
			continue
		}
		t := Tip{SN: a.SN, SAID: a.SAID}
		if prev, ok := byWitness[key]; ok && prev != t {
			return Tip{}, fmt.Errorf("%w: a witness named two different tips", ErrWitnessesDisagree)
		}
		byWitness[key] = t
	}
	if len(byWitness) < threshold {
		return Tip{}, fmt.Errorf("%w: %d of the %d needed answered", ErrNotFresh, len(byWitness), threshold)
	}
	names := make([]string, 0, len(byWitness))
	for k := range byWitness {
		names = append(names, k)
	}
	sort.Strings(names)
	first := byWitness[names[0]]
	for _, n := range names[1:] {
		if byWitness[n] != first {
			return Tip{}, ErrWitnessesDisagree
		}
	}
	if first.SN < 0 {
		return Tip{}, fmt.Errorf("%w: the witnesses hold nothing for the publisher", ErrNotFresh)
	}
	return first, nil
}
