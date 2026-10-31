package relayproto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	keri "github.com/grapeid/keri-go"
)

// Admission: an Identity Agent is let in on a signature, never a password.
//
// The relay sends a challenge. The Identity Agent signs a statement naming the relay,
// the challenge's nonce, the time, and this TLS connection's channel binding,
// with the key its enrolment identifier's key event log currently names. The
// relay checks that log with keri-go and the signature against it.
//
// Each part of the statement closes one way of reusing it. The nonce makes it
// useless for any other challenge; the channel binding makes it useless on any
// other connection, including one a relay in the middle opens onward; the
// relay's name makes it useless at any other relay; the time bounds how long a
// statement is worth anything at all.

const (
	purposeAdmit = "relay-admission"
	purposeRenew = "relay-renewal"
)

// Challenge is what the relay sends first, and again at each renewal.
type Challenge struct {
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
	Nonce    string `json:"nonce"`
	Time     string `json:"t"`
	Renewal  bool   `json:"renewal,omitempty"`
}

// Statement is what the Identity Agent signs.
type Statement struct {
	Purpose  string `json:"purpose"`
	Protocol string `json:"protocol"`
	Service  string `json:"service"`
	Nonce    string `json:"nonce"`
	Exporter string `json:"exporter"`
	AID      string `json:"aid"`
	Time     string `json:"t"`
}

// canonical is the exact bytes a statement is signed over: CanonicalBody of
// its fields.
func (s Statement) canonical() ([]byte, error) {
	return CanonicalBody(map[string]any{
		"purpose": s.Purpose, "protocol": s.Protocol, "service": s.Service,
		"nonce": s.Nonce, "exporter": s.Exporter, "aid": s.AID, "t": s.Time,
	})
}

// CanonicalBody is the exact bytes everything in this protocol is signed over:
// an admission statement, and a control request (ADR-048 §8). It is the fields
// as a JSON object with sorted keys, no whitespace and no HTML escaping, with
// any "signature" field left out, so an implementation in any language
// produces the same bytes with an ordinary JSON writer.
//
// Every field is a string of printable ASCII, which is what makes the form
// unambiguous; anything else is refused rather than signed in some spelling
// another implementation would not reproduce.
func CanonicalBody(body map[string]any) ([]byte, error) {
	fields := make(map[string]string, len(body))
	for k, v := range body {
		if k == "signature" {
			continue
		}
		str, ok := v.(string)
		if !ok || !printableASCII(str) || !printableASCII(k) {
			return nil, fmt.Errorf("every signed field is a string of printable ASCII; %q is not", k)
		}
		fields[k] = str
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(fields); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// Admission is the Identity Agent's answer to a challenge.
type Admission struct {
	Statement Statement `json:"statement"`
	// Signature is the raw Ed25519 signature over the canonical statement,
	// base64url without padding.
	Signature string `json:"signature"`
	// KEL is the enrolment identifier's signed key event log as a CESR stream,
	// base64url. It may be left out when the relay already holds the log and
	// nothing has been added to it.
	KEL string `json:"kel,omitempty"`
}

// Admitted is the relay's answer to an admission it accepted.
type Admitted struct {
	Session   string `json:"session,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Error     string `json:"error,omitempty"`
}

// Signer signs bytes with the enrolment identifier's current key.
// keri-go's SoftwareSigner satisfies it.
type Signer interface {
	Sign(data []byte) ([]byte, error)
}

var b64 = base64.RawURLEncoding

// signatureOf reads an Ed25519 signature in unpadded base64url, in its one
// canonical string: exactly 86 characters of the base64url alphabet, with the
// 4 spare bits of the last one zero. Leniently read, a signature had 16
// strings, and the standard decoder skipped line breaks inside one.
//
// This module is kept free of the core's packages so a URL relay can import it
// alone, so it cannot use the core's decoder; the rule is the same.
func signatureOf(s string) ([]byte, error) {
	if len(s) != b64.EncodedLen(ed25519.SignatureSize) || strings.Trim(s, b64url) != "" {
		return nil, fmt.Errorf("the signature is not %d bytes in unpadded base64url", ed25519.SignatureSize)
	}
	sig, err := b64.Strict().DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("the signature is not in canonical base64url: %w", err)
	}
	return sig, nil
}

const b64url = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func randomToken(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic("relayproto: no randomness: " + err.Error())
	}
	return b64.EncodeToString(buf)
}

// NewChallenge makes a fresh challenge from the named relay.
func NewChallenge(service string, now time.Time) Challenge {
	return Challenge{Protocol: ProtocolVersion, Service: service,
		Nonce: randomToken(NonceBytes), Time: now.UTC().Format(time.RFC3339)}
}

// ChannelBinding is the RFC 9266 exporter value of a TLS connection.
func ChannelBinding(cs tls.ConnectionState) ([]byte, error) {
	if cs.Version < tls.VersionTLS13 {
		return nil, fmt.Errorf("the relay protocol needs TLS 1.3 for channel binding; this connection is %s",
			tls.VersionName(cs.Version))
	}
	return cs.ExportKeyingMaterial(ExporterLabel, nil, ExporterLength)
}

// printable refuses a statement with any field outside printable ASCII, so the
// bytes signed have one spelling and a log line cannot be forged with them.
func (s Statement) printable() error {
	for name, v := range map[string]string{"purpose": s.Purpose, "protocol": s.Protocol,
		"service": s.Service, "nonce": s.Nonce, "exporter": s.Exporter, "aid": s.AID, "t": s.Time} {
		for i := 0; i < len(v); i++ {
			if v[i] < 0x21 || v[i] > 0x7e {
				return fmt.Errorf("the statement's %s is not printable ASCII", name)
			}
		}
	}
	return nil
}

// Answer signs a statement answering a challenge on a connection whose channel
// binding is exporter.
func Answer(ch Challenge, exporter []byte, aid string, kel []byte, signer Signer, now time.Time) (Admission, error) {
	st := Statement{
		Purpose: purposeAdmit, Protocol: ProtocolVersion, Service: ch.Service,
		Nonce: ch.Nonce, Exporter: b64.EncodeToString(exporter), AID: aid,
		Time: now.UTC().Format(time.RFC3339),
	}
	if ch.Renewal {
		st.Purpose = purposeRenew
	}
	if err := st.printable(); err != nil {
		return Admission{}, err
	}
	body, err := st.canonical()
	if err != nil {
		return Admission{}, err
	}
	sig, err := signer.Sign(body)
	if err != nil {
		return Admission{}, fmt.Errorf("sign the admission statement: %w", err)
	}
	a := Admission{Statement: st, Signature: b64.EncodeToString(sig)}
	if len(kel) > 0 {
		a.KEL = b64.EncodeToString(kel)
	}
	return a, nil
}

// Verifier is the relay's side of admission.
type Verifier struct {
	// Service is the relay's own name, as its challenges carry it: the host
	// name an Identity Agent dials, which the Identity Agent checks.
	Service string
	// Enrolled returns the key event log the relay holds for an identifier
	// from an earlier admission, if any. It is required: a relay that keeps no
	// record of the logs it has admitted cannot tell a current key from one
	// rotated away, so a Verifier without it refuses everybody.
	Enrolled func(aid string) ([]byte, bool)
	// Standing, when set, is asked about every admission and renewal after the
	// log has verified, so a relay that watches key state can refuse an
	// identifier it has seen revoked.
	Standing func(aid string, keys []string) error
}

// Verified is an admission the relay accepted.
type Verified struct {
	AID string
	// Key is the key that signed, the one the log names now.
	Key string
	// KEL is the log the admission was checked against; the relay keeps it so
	// a later admission may send only what is new.
	KEL []byte
}

// Verify checks an admission against the challenge it answers and the channel
// binding of the connection it arrived on.
func (v *Verifier) Verify(a Admission, ch Challenge, exporter []byte, now time.Time) (*Verified, error) {
	return v.verify(a, ch, exporter, now, nil)
}

// verify is Verify with the log of the identifier's live session, if it has
// one, which may be newer than the relay's stored record.
func (v *Verifier) verify(a Admission, ch Challenge, exporter []byte, now time.Time, live []byte) (*Verified, error) {
	st := a.Statement
	if err := st.printable(); err != nil {
		return nil, err
	}
	want := purposeAdmit
	if ch.Renewal {
		want = purposeRenew
	}
	switch {
	case st.Purpose != want:
		return nil, fmt.Errorf("the statement is for %q, not %q", st.Purpose, want)
	case st.Protocol != ProtocolVersion:
		return nil, fmt.Errorf("the statement is for protocol %q, not %q", st.Protocol, ProtocolVersion)
	case st.Service != v.Service || ch.Service != v.Service:
		return nil, fmt.Errorf("the statement names relay %q; this is %q", st.Service, v.Service)
	case st.Nonce == "" || st.Nonce != ch.Nonce:
		return nil, fmt.Errorf("the statement does not answer this challenge")
	case st.Exporter != b64.EncodeToString(exporter):
		return nil, fmt.Errorf("the statement was made for a different connection")
	case st.AID == "":
		return nil, fmt.Errorf("the statement names no identifier")
	}
	at, err := time.Parse(time.RFC3339, st.Time)
	if err != nil {
		return nil, fmt.Errorf("the statement's time is not RFC 3339")
	}
	if d := now.Sub(at); d > ClockSkew || d < -ClockSkew {
		return nil, fmt.Errorf("the statement is not fresh")
	}

	kel, err := v.keyLog(st.AID, a.KEL, live)
	if err != nil {
		return nil, err
	}
	key, err := CurrentKey(st.AID, kel)
	if err != nil {
		return nil, err
	}
	keyQB64, err := keri.MatterQB64(keri.CodeEd25519, key)
	if err != nil {
		return nil, err
	}
	sig, err := signatureOf(a.Signature)
	if err != nil {
		return nil, err
	}
	body, err := st.canonical()
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(key, body, sig) {
		return nil, fmt.Errorf("the statement is not signed by the key the log names now")
	}
	if v.Standing != nil {
		if err := v.Standing(st.AID, []string{keyQB64}); err != nil {
			return nil, err
		}
	}
	return &Verified{AID: st.AID, Key: keyQB64, KEL: kel}, nil
}

// keyLog settles which log an admission is checked against. A log the relay
// already holds may only be extended: a presented log that does not begin with
// it rewrites history, which is the duplicity a key event log exists to expose.
//
// The relay may know the identifier's log from two places: its stored record,
// and the live session, which renewals keep current. Whichever is longer is
// the newest it has seen, and that is the one a newcomer must extend. Checking
// only the stored record let somebody holding a key rotated away since present
// the old log, which the stale record still accepted, and displace the owner.
func (v *Verifier) keyLog(aid, presented string, live []byte) ([]byte, error) {
	if v.Enrolled == nil {
		return nil, fmt.Errorf("this relay keeps no record of the key event logs it admits, so it admits nobody")
	}
	held, _ := v.Enrolled(aid)
	if len(live) > 0 {
		switch {
		case logExtends(live, held):
			held = live
		case logExtends(held, live):
		default:
			return nil, fmt.Errorf("the relay's records of %q disagree with each other; refusing until that is resolved", aid)
		}
	}
	if presented == "" {
		if len(held) == 0 {
			return nil, fmt.Errorf("no key event log was presented and none is held for %q", aid)
		}
		return held, nil
	}
	if len(presented) > b64.EncodedLen(MaxKELBytes) {
		return nil, fmt.Errorf("the key event log is larger than %d bytes", MaxKELBytes)
	}
	kel, err := b64.DecodeString(presented)
	if err != nil {
		return nil, fmt.Errorf("the key event log is not base64url")
	}
	if !logExtends(kel, held) {
		return nil, fmt.Errorf("the key event log presented does not extend the one held for %q", aid)
	}
	return kel, nil
}

// logExtends reports whether log holds every event base holds, in the same
// order, and possibly more after them. Events are compared as keri-go reads
// them, by sequence number, type and SAID, never as bytes: the same event can
// travel with more attachments than before (a witness receipt added, say) or
// be re-serialised, and a log that does so has not changed its history. A
// byte comparison read that as a rewrite and refused the owner for good.
//
// An empty base is extended by anything. A log that cannot be read extends
// nothing.
func logExtends(log, base []byte) bool {
	if len(base) == 0 {
		return true
	}
	if len(log) == 0 {
		return false
	}
	have, err := logEvents(log)
	if err != nil {
		return false
	}
	want, err := logEvents(base)
	if err != nil || len(have) < len(want) {
		return false
	}
	for i := range want {
		if have[i] != want[i] {
			return false
		}
	}
	return true
}

type eventID struct {
	sn   uint64
	ilk  string
	said string
}

func logEvents(stream []byte) ([]eventID, error) {
	messages, err := keri.ParseKELStream(stream)
	if err != nil {
		return nil, err
	}
	out := make([]eventID, 0, len(messages))
	for _, m := range messages {
		ev, err := keri.ParseEvent(m)
		if err != nil {
			return nil, err
		}
		if ev.SAID == "" {
			return nil, fmt.Errorf("an event in the log has no SAID")
		}
		out = append(out, eventID{sn: ev.SN, ilk: ev.Ilk, said: ev.SAID})
	}
	return out, nil
}
