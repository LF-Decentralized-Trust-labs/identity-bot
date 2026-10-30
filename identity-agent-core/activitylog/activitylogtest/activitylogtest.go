// Package activitylogtest signs and writes activity-log events for tests, in
// this package and in the packages that write to the log.
package activitylogtest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"identity-agent-core/activitylog"
	"identity-agent-core/permission"
)

// Signer signs events the way the log does: the event with no signer or
// signature, encoded, signed, base64url.
type Signer struct {
	AID  string
	priv ed25519.PrivateKey
}

// NewSigner is a signer with a fresh key.
func NewSigner(t *testing.T) *Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &Signer{AID: "ELogSigner", priv: priv}
}

// Keys answers for the signer's key, as an activitylog.EventKeys.
func (s *Signer) Keys(aid string) (ed25519.PublicKey, error) {
	if aid != s.AID {
		return nil, fmt.Errorf("unknown signer %s", aid)
	}
	return s.priv.Public().(ed25519.PublicKey), nil
}

// Sign is ev signed.
func (s *Signer) Sign(ev activitylog.InvocationEvent) activitylog.InvocationEvent {
	payload, _ := json.Marshal(ev)
	ev.SignerAID = s.AID
	ev.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.priv, payload))
	return ev
}

// KeepingSigner is a log signer that keeps where its chain begins, as the
// server's does in its own file outside the database. Fail makes it refuse to
// sign.
type KeepingSigner struct {
	*Signer
	Start activitylog.ChainStart
	Kept  bool
	Fail  bool
}

// NewKeepingSigner is a keeping signer with a fresh key.
func NewKeepingSigner(t *testing.T) *KeepingSigner {
	return &KeepingSigner{Signer: NewSigner(t)}
}

// SignEvent implements activitylog.EventSigner.
func (k *KeepingSigner) SignEvent(payload []byte) (string, string, error) {
	if k.Fail {
		return "", "", fmt.Errorf("the signing key is unavailable")
	}
	return k.AID, base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.priv, payload)), nil
}

// ChainStart implements activitylog.ChainKeeper.
func (k *KeepingSigner) ChainStart() (activitylog.ChainStart, bool, error) {
	return k.Start, k.Kept, nil
}

// KeepChainStart implements activitylog.ChainKeeper.
func (k *KeepingSigner) KeepChainStart(s activitylog.ChainStart) error {
	k.Start, k.Kept = s, true
	return nil
}

// WriteEvents writes one governance event for each id.
func WriteEvents(t *testing.T, l *activitylog.Log, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if l.RecordGovernanceEvent(permission.CallerContext{CallerAID: "EAgent", Reason: "test"}, id, "ok") == 0 {
			t.Fatalf("event %s not written", id)
		}
	}
}
