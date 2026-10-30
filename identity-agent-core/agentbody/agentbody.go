// Package agentbody binds an AI agent to the machine it runs on.
//
// An AI agent's identity is held by its Identity Agent: a delegated identifier
// anchored in the owner's key log, and a grant saying what it may do. Neither
// says where the AI agent runs. A body is the machine that does — a computer, a
// virtual machine, a device — and it proves itself with a key of its own, K,
// held in that machine's secure hardware where it has any.
//
// Binding a body is a short ceremony:
//
//  1. The owner asks the Identity Agent for an enrolment string. It carries
//     everything the machine needs to recognise the right Identity Agent, and a
//     one-time secret.
//  2. The machine checks the Identity Agent's key log against the string, makes
//     K, and sends a first contact signed by K over the secret.
//  3. Both sides show six words derived from K. The owner compares them and
//     approves; a stolen secret used by another machine shows other words.
//  4. The Identity Agent issues a credential saying K is the body of this AI
//     agent, at a stated grade. From then on the machine signs every request
//     with K, and no shared secret exists to steal.
//
// This package is what both sides need to agree on: the enrolment string, the
// strings each signature covers, the six words, and the grades. The Identity
// Agent uses it to issue and check; the program a machine runs uses it to enrol
// and to sign. Keeping one copy is what keeps the two from disagreeing.
package agentbody

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"identity-agent-core/didcomm"
	"identity-agent-core/iacrypto"
	"identity-agent-core/permission"

	"github.com/zeebo/blake3"
)

// ── The enrolment string ─────────────────────────────────────────────────────

// EnrolmentPrefix marks a string as an AI agent body enrolment, version 1.
const EnrolmentPrefix = "iabody1."

// EnrolmentWindow is how long an enrolment string can be used: long enough to
// walk to a machine and type it, short enough that a copy left in a chat or a
// screenshot is useless soon after.
const EnrolmentWindow = 15 * time.Minute

// Enrolment is what the machine is told, out of band, before it trusts anything
// it fetches.
//
// The address alone is not enough: every internet path to an Identity Agent may
// end its encryption at a relay, and a relay could answer with another key. So
// the string also names the Identity Agent and a point in its key log. The
// machine accepts a fetched key log only if it is that identifier's, and holds
// the named event — so whoever wrote the string decided which Identity Agent
// the machine will believe.
type Enrolment struct {
	Version int `json:"v"`
	// URL is where the Identity Agent is reached.
	URL string `json:"url"`
	// IdentityAgent is the Identity Agent's identifier.
	IdentityAgent string `json:"ia"`
	// KeyStateSN and KeyStateSAID name an event in the Identity Agent's key log,
	// as it was when the string was made. Later events may follow it; a log
	// without it is a different identity's history.
	KeyStateSN   int    `json:"sn"`
	KeyStateSAID string `json:"d"`
	// Agent and AgentName name the AI agent this machine will become the body of.
	Agent     string `json:"agent"`
	AgentName string `json:"name"`
	// Secret is single-use, and only lets a machine ASK. Nothing is granted
	// until the owner compares the words and approves.
	Secret  string    `json:"secret"`
	Expires time.Time `json:"exp"`
}

// Encode renders the string handed to the machine.
func (e Enrolment) Encode() (string, error) {
	if e.Version == 0 {
		e.Version = 1
	}
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	return EnrolmentPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

// ParseEnrolment reads an enrolment string, refusing anything incomplete.
func ParseEnrolment(s string) (Enrolment, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, EnrolmentPrefix) {
		return Enrolment{}, fmt.Errorf("this is not an AI agent body enrolment string")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(s, EnrolmentPrefix))
	if err != nil {
		return Enrolment{}, fmt.Errorf("the enrolment string is damaged: %w", err)
	}
	var e Enrolment
	if err := json.Unmarshal(raw, &e); err != nil {
		return Enrolment{}, fmt.Errorf("the enrolment string is damaged: %w", err)
	}
	if e.Version != 1 {
		return Enrolment{}, fmt.Errorf("enrolment string version %d is not one this program reads", e.Version)
	}
	if e.URL == "" || e.IdentityAgent == "" || e.KeyStateSAID == "" || e.Agent == "" || e.Secret == "" {
		return Enrolment{}, fmt.Errorf("the enrolment string is missing a field it must carry")
	}
	return e, nil
}

// ── What each signature covers ───────────────────────────────────────────────

// Keys is the body's public key material: its signing key K, and the keys the
// Identity Agent seals messages to it with.
type Keys struct {
	// Host is the body's identifier, derived from K (iacrypto.MachineAIDForKey).
	// It IS the key: it cannot name a different one.
	Host string `json:"host"`
	// Verkey is K in the form signatures are checked against.
	Verkey string `json:"verkey"`
	// The body's sealing keys, base64url: X25519 and ML-KEM-768 to seal to it,
	// Ed25519 and ML-DSA-65 to sign what it seals. They live in software —
	// secure hardware does none of these — which is why K signs them.
	X25519   string `json:"x25519"`
	MLKEM768 string `json:"mlkem768"`
	Ed25519  string `json:"ed25519"`
	MLDSA65  string `json:"mldsa65"`
}

// KeysDigest is the digest that binds the sealing keys to K: K signs it inside
// the enrolment proof, so a relay cannot swap them.
func (k Keys) KeysDigest() string {
	return iacrypto.Blake3QB64Must([]byte(strings.Join([]string{
		"IA-BODY-KEYS-V1", k.Host, k.Verkey, k.X25519, k.MLKEM768, k.Ed25519, k.MLDSA65,
	}, "\n")))
}

// CheckSealingKeys refuses sealing keys of the wrong size: they are stored and
// later used to seal messages to the machine, so a malformed one is refused at
// enrolment rather than discovered then.
func (k Keys) CheckSealingKeys() error {
	for _, key := range []struct {
		name, value string
		size        int
	}{
		{"X25519 sealing key", k.X25519, iacrypto.X25519PubkeyBytes},
		{"ML-KEM-768 sealing key", k.MLKEM768, iacrypto.MLKEM768EncapBytes},
		{"Ed25519 sealing signature key", k.Ed25519, iacrypto.Ed25519PubkeyBytes},
		{"ML-DSA-65 sealing signature key", k.MLDSA65, iacrypto.MLDSA65VerkeyBytes},
	} {
		b, err := base64.RawURLEncoding.DecodeString(key.value)
		if err != nil || len(b) != key.size {
			return fmt.Errorf("the %s must be %d bytes, base64url", key.name, key.size)
		}
	}
	return nil
}

// DID is the body's sealing keys as the DIDComm layer takes them.
func (k Keys) DID() *didcomm.DID {
	return &didcomm.DID{AID: k.Host, Ed: k.Ed25519, Dsa: k.MLDSA65,
		X25519: k.X25519, MlKem: k.MLKEM768, Suite: didcomm.CipherSuite}
}

// KeysFrom reads a body's public keys out of its keyset.
func KeysFrom(host, verkey string, ks *didcomm.KeySet) (Keys, error) {
	ed, dsa, x, kem, err := ks.PublicMaterial()
	if err != nil {
		return Keys{}, err
	}
	enc := base64.RawURLEncoding.EncodeToString
	return Keys{Host: host, Verkey: verkey, X25519: enc(x), MLKEM768: enc(kem), Ed25519: enc(ed), MLDSA65: enc(dsa)}, nil
}

// EnrolProof is the string K signs to ask to become the body of an AI agent. It
// covers the one-time secret, a fresh nonce, the AI agent and Identity Agent it
// is meant for, and every key the body is offering, so a signature made for one
// enrolment cannot be replayed into another.
func EnrolProof(e Enrolment, nonce string, k Keys, claimedGrade, platform, placement string) []byte {
	return []byte(strings.Join([]string{
		"IA-BODY-ENROL-V1",
		e.IdentityAgent,
		e.Agent,
		e.Secret,
		nonce,
		k.Host,
		k.Verkey,
		k.KeysDigest(),
		claimedGrade,
		platform,
		placement,
	}, "\n"))
}

// MinNonce is the shortest nonce an enrolment or a signed request may carry.
const MinNonce = 16

// CheckNonce refuses a nonce shorter than MinNonce.
func CheckNonce(nonce string) error {
	if len(nonce) < MinNonce {
		return fmt.Errorf("a nonce of at least %d characters is needed", MinNonce)
	}
	return nil
}

// EnrolRequest is what a machine sends to ask to become a body: the proof that
// it holds K, and what that proof covers.
type EnrolRequest struct {
	Secret       string `json:"secret"`
	Agent        string `json:"agent"`
	Keys         Keys   `json:"keys"`
	Nonce        string `json:"nonce"`
	ClaimedGrade string `json:"claimed_grade"`
	Platform     string `json:"platform"`
	Placement    string `json:"placement"`
	// Signature is K's signature over EnrolProof.
	Signature string `json:"signature"`
}

// SealedEnrolment is how an EnrolRequest travels: as the body of a DIDComm
// message of type body-enrolment, sealed to the Identity Agent's keys from the
// machine's sealing keys, which the machine first checked are that identity's.
// A relay between them reads neither the secret nor the machine's keys.
type SealedEnrolment struct {
	// Sender is the machine's public keys, which the envelope is sealed from.
	// The same keys are inside the envelope, signed by K.
	Sender   Keys              `json:"sender"`
	Envelope *didcomm.Envelope `json:"envelope"`
}

// Request headers a body signs a request with.
const (
	HeaderHost      = permission.HeaderBodyHost
	HeaderSignature = "X-IA-Body-Sig"
	HeaderTimestamp = "X-IA-Body-Timestamp"
	// HeaderNonce makes every signed request distinct, so two identical
	// requests in one second are two requests rather than a replay — a key in
	// software signs the same input to the same signature.
	HeaderNonce = "X-IA-Body-Nonce"
	// HeaderWorkItem and HeaderReason are the request's stated purpose, which
	// the Identity Agent records. Signed, so nothing between the two can
	// rewrite what the record says the AI agent was doing.
	HeaderWorkItem = permission.HeaderWorkItem
	HeaderReason   = permission.HeaderReason
	// HeaderFor names the Identity Agent the request is meant for, by its
	// identifier — the one the enrolment named. Signed, so a request captured
	// on its way to one Identity Agent is refused by any other that has the
	// same machine enrolled.
	HeaderFor = "X-IA-Body-For"
	// HeaderSession is the caller's own session, when it has one: which of its
	// runs made the request. It decides nothing at the Identity Agent and is
	// passed to the app a call reaches, so it is signed for the same reason
	// the stated purpose is.
	HeaderSession = permission.HeaderSession
)

// RequestWindow is how far a body's timestamp may be from the Identity Agent's
// clock. A signature is also spent on first use, so the window only bounds how
// long a captured request is worth holding.
const RequestWindow = 2 * time.Minute

// SignedRequest is everything about one request that K's signature covers.
type SignedRequest struct {
	// For is the identifier of the Identity Agent the request is meant for.
	For    string
	Host   string
	Method string
	// Target is the request target exactly as sent — the escaped path and the
	// query — so a relay can change neither which route is reached nor its
	// parameters without breaking the signature.
	Target    string
	Timestamp string
	Nonce     string
	Body      []byte
	WorkItem  string
	Reason    string
	Session   string
}

// Bytes is the string K signs.
func (r SignedRequest) Bytes() []byte {
	return []byte(strings.Join([]string{
		"IA-BODY-REQ-V3",
		r.For,
		r.Host,
		strings.ToUpper(r.Method),
		r.Target,
		r.Timestamp,
		r.Nonce,
		iacrypto.Blake3QB64Must(r.Body),
		r.WorkItem,
		r.Reason,
		r.Session,
	}, "\n"))
}

// ── The six words ────────────────────────────────────────────────────────────

//go:embed bip39_english.txt
var wordlistFile []byte

var wordlist = func() []string {
	words := strings.Split(strings.TrimSpace(string(wordlistFile)), "\n")
	if len(words) != 2048 {
		panic(fmt.Sprintf("agentbody: the word list has %d words, not 2048", len(words)))
	}
	return words
}()

// Words are the six words both sides show for a body's key, so a person can
// tell that the machine asking is the one in front of them. They come from a
// digest of the body's identifier: 66 bits, so a machine that wanted to show the
// same words with its own key would have to find a key that collides with them
// within the few minutes an enrolment stays open.
func Words(host string) []string {
	sum := blake3.Sum256([]byte("IA-BODY-WORDS-V1\n" + host))
	bits := binary.BigEndian.Uint64(sum[:8])
	extra := uint64(sum[8]) // two more bits for the sixth word
	out := make([]string, 6)
	for i := 0; i < 5; i++ {
		out[i] = wordlist[(bits>>(64-11*(i+1)))&0x7ff]
	}
	out[5] = wordlist[((bits&0x1ff)<<2)|(extra>>6)]
	return out
}

// ── Grades ───────────────────────────────────────────────────────────────────

// Grades say how strongly a body's key is held, weakest first. A message carries
// its body's grade, so nobody reads a weak proof as a strong one.
const (
	GradeSoftware         = "software"
	GradeHardwareAsserted = "hardware-asserted"
	GradeHardwareAttested = "hardware-attested"
	GradeAttestedRuntime  = "attested-runtime"
)

// Grade settles what a body is recorded at from what it claims.
//
// A body cannot award itself a grade. Above "hardware (asserted)" a grade needs
// evidence the Identity Agent has checked, and nothing here checks evidence yet,
// so a higher claim is clamped to the most the body's own report can support,
// and the clamp is reported so it is recorded. "Hardware (asserted)" itself is
// the machine's word that its key is in hardware — taken, and labelled as such.
func Grade(claimed string) (grade string, clamped bool) {
	switch claimed {
	case GradeSoftware:
		return GradeSoftware, false
	case GradeHardwareAsserted:
		return GradeHardwareAsserted, false
	case GradeHardwareAttested, GradeAttestedRuntime:
		return GradeHardwareAsserted, true
	default:
		return GradeSoftware, claimed != ""
	}
}

// ── Checking a body's signature ──────────────────────────────────────────────

// Verify checks a signature made by K. The key is read out of the identifier,
// and must be the verkey offered beside it, so the identifier and the key
// cannot be mixed from two machines.
func Verify(host, verkey, signature string, message []byte) error {
	fromID, err := iacrypto.KeyFromMachineIdentifier(host)
	if err != nil {
		return fmt.Errorf("the body identifier is unreadable: %w", err)
	}
	fromVerkey, err := iacrypto.KeyFromMachineVerkey(verkey)
	if err != nil {
		return fmt.Errorf("the body key is unreadable: %w", err)
	}
	if !bytes.Equal(fromID, fromVerkey) {
		return fmt.Errorf("the body identifier and its key are not the same key")
	}
	ok, err := iacrypto.VerifyMachineSignature(verkey, signature, message)
	if err != nil || !ok {
		return fmt.Errorf("the signature is not the body key's")
	}
	return nil
}

// ── Signing as a body ────────────────────────────────────────────────────────

// Signer is a machine key: the secure-hardware signer an Identity Agent already
// uses for its own controller key (secureenclave.PlatformSigner), or a software
// key where a machine has no hardware.
type Signer interface {
	PublicKey() ([]byte, error)
	Sign(data []byte) ([]byte, error)
}

// Identity is a body's identifier and verkey, read from its key.
func Identity(s Signer) (host, verkey string, err error) {
	pub, err := s.PublicKey()
	if err != nil {
		return "", "", err
	}
	if host, err = iacrypto.MachineAIDForKey(pub); err != nil {
		return "", "", err
	}
	if verkey, err = iacrypto.MachineVerkeyForKey(pub); err != nil {
		return "", "", err
	}
	return host, verkey, nil
}

// Sign signs as the body, in the form Verify checks.
func Sign(s Signer, message []byte) (string, error) {
	pub, err := s.PublicKey()
	if err != nil {
		return "", err
	}
	sig, err := s.Sign(message)
	if err != nil {
		return "", err
	}
	return iacrypto.MachineSignatureQB64(pub, sig)
}
