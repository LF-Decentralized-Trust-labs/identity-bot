package server

import (
	"crypto/ed25519"
	"fmt"

	"identity-agent-core/backup"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/secureenclave"

	keri "github.com/grapeid/keri-go"
)

// What an owner's phone commits to in an ownership change (ADR-061 section 6):
// for each key generation it will rotate into, a classical digest AND a
// post-quantum digest, so the owner's two commitments count once, for that
// owner, under the ceremony's weighted next-keys threshold.
//
// The post-quantum key of generation g sits beside the classical key of
// generation g in the same relationship, derived from the phrase alone
// (backup.DerivePairwisePostQuantumSeed), so a restore finds it with nothing
// else kept.

// ownerCommitment is what a phone commits to for one key generation.
type ownerCommitment struct {
	Classical   string // digest of the classical key of that generation
	PostQuantum string // digest of the post-quantum key of that generation
}

// ownerCommitmentAt is the commitment this device makes to [generation] of the
// relationship [relationshipIndex]. Nothing secret leaves it: both halves are
// digests, and the seeds are zeroed before it returns.
func ownerCommitmentAt(root []byte, relationshipIndex, generation int) (ownerCommitment, error) {
	if relationshipIndex <= 0 {
		return ownerCommitment{}, fmt.Errorf("this relationship has no key index, so no commitment can be derived from it")
	}
	classicalSeed, err := backup.DerivePairwiseSeed(root, relationshipIndex, generation)
	if err != nil {
		return ownerCommitment{}, fmt.Errorf("derive the classical key of generation %d: %w", generation, err)
	}
	defer zero(classicalSeed)
	key := ed25519.NewKeyFromSeed(classicalSeed)
	defer zero(key)
	classical, err := iacrypto.NextKeyDigest(iacrypto.VerkeyQB64(key.Public().(ed25519.PublicKey)))
	if err != nil {
		return ownerCommitment{}, fmt.Errorf("commit to the classical key of generation %d: %w", generation, err)
	}
	pqSeed, err := backup.DerivePairwisePostQuantumSeed(root, relationshipIndex, generation)
	if err != nil {
		return ownerCommitment{}, fmt.Errorf("derive the post-quantum key of generation %d: %w", generation, err)
	}
	defer zero(pqSeed)
	pq, err := iacrypto.PostQuantumNextKeyFromSeed(pqSeed)
	if err != nil {
		return ownerCommitment{}, fmt.Errorf("commit to the post-quantum key of generation %d: %w", generation, err)
	}
	zero(pq.Seed)
	return ownerCommitment{Classical: classical, PostQuantum: pq.Digest}, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// commitmentsOfThisDevice is the commitment to the next generation (1) and to
// the one after (2) for [rel], from this device's own root seed.
func (s *CoreServer) commitmentsOfThisDevice(rel *login.SiteRelationship) (next, afterNext ownerCommitment, err error) {
	if rel == nil {
		return next, afterNext, fmt.Errorf("no relationship")
	}
	root, err := secureenclave.LoadRootSeed(s.DataDir)
	if err != nil {
		return next, afterNext, fmt.Errorf("no root seed on this device: %w", err)
	}
	defer zero(root)
	if next, err = ownerCommitmentAt(root, rel.RelationshipIndex, 1); err != nil {
		return next, afterNext, err
	}
	afterNext, err = ownerCommitmentAt(root, rel.RelationshipIndex, 2)
	return next, afterNext, err
}

// isABlake3Digest reports whether [d] is written as a KERI digest: a code of
// one character, "E", and 43 characters of URL-safe base64. A device is
// believed about which key it holds, never about what a digest looks like.
func isABlake3Digest(d string) bool {
	if len(d) != 44 || d[0] != 'E' {
		return false
	}
	for _, c := range d[1:] {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// aRotationCommitsTo refuses (with the reason) a rotation that does not carry
// [want] in its next digests. A phone that signed a rotation without its
// post-quantum digest would have signed away the commitment it made, and one
// without its classical digest would have signed away its own next key.
func aRotationCommitsTo(ev *keri.Event, want ownerCommitment) string {
	has := map[string]bool{}
	for _, d := range ev.NextDigest {
		has[d] = true
	}
	switch {
	case !has[want.Classical]:
		return "that rotation does not commit to the next key this device derived, so signing it would hand this device's place to a key it does not hold"
	case !has[want.PostQuantum]:
		return "that rotation leaves out this device's post-quantum commitment, so signing it would drop the protection this device asked for"
	}
	return ""
}

// checkTheDigestsSent is what the organisation's side refuses of what an
// invited owner's device sent, with the reason, or "" when it will do. A
// post-quantum digest is optional (an owner whose device made none is held to
// its classical key alone), but one sent must be a digest, must not be the
// classical one again, and in a hand-over must come with its partner for the
// second rotation: half a commitment would put two shapes of owner into one
// weighted threshold.
//
// Optional here is safe only because the device decides for itself: when asked
// to sign, it derives its own classical and post-quantum next digests and
// refuses a rotation missing either (aRotationCommitsTo), so a digest stripped
// on the way in yields a ceremony its device will not sign, never a weaker
// commitment. That check is the gate; this one only keeps out malformed input.
func checkTheDigestsSent(handOver bool, nextPublicKey string, more CeremonyExtras) string {
	if more.NextPostQuantumDigest == "" {
		if more.AfterNextPostQuantumDigest != "" {
			return "a post-quantum commitment for the second rotation came without one for the first"
		}
		return ""
	}
	if !isABlake3Digest(more.NextPostQuantumDigest) {
		return "the post-quantum commitment sent is not a digest"
	}
	if classical, err := keri.NextDigest(nextPublicKey); err == nil && more.NextPostQuantumDigest == classical {
		return "the post-quantum commitment sent is the classical one again"
	}
	if handOver {
		if more.AfterNextPostQuantumDigest == "" {
			return "this ceremony hands the identity over, so the post-quantum commitment for the second rotation is needed too, and was not sent"
		}
	}
	if more.AfterNextPostQuantumDigest != "" {
		if !isABlake3Digest(more.AfterNextPostQuantumDigest) {
			return "the post-quantum commitment for the second rotation is not a digest"
		}
		if more.AfterNextPostQuantumDigest == more.NextPostQuantumDigest {
			return "the same post-quantum commitment was sent for both rotations"
		}
	}
	return ""
}
