// Package endpointrecord is an identifier's signed statement of the one
// address it can be reached at.
//
// A computer that has been told an organisation moved must not believe whoever
// says so: a plain reverse proxy can put any address in front of the old one
// and relay the answers. What nothing in the middle can produce is the
// organisation's own signature over the new address, so that signature is the
// proof, and it is checked against the key the organisation's verified key log
// names now, not against a key the record brings with it.
//
// A record is five strings:
//
//	type      "endpoint-record/1"
//	aid       the identifier the record speaks for
//	origin    the exact origin: scheme://host:port, one spelling (CheckOrigin),
//	          or "" to say the identifier is not reachable anywhere now
//	issued    when it was signed, YYYY-MM-DDTHH:MM:SSZ, UTC
//	signature Ed25519 over CanonicalBody of the other four, CESR qb64 (code 0B)
//
// Ordering is by issued: a record replaces one only when it was issued after
// it, and an older or equal one is refused (Newer). The signature covers the
// type, so a signature made for this form is never another form's, and the
// origin, so a record cannot be pointed somewhere its signer did not choose.
//
// Only the identifier's own key signs. A record carries no key and no
// delegation, so there is no way to sign for somebody else.
//
// The vectors in endpoint-record-vectors.json are the contract for another
// implementation, in any language.
package endpointrecord

import (
	"crypto/ed25519"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"identity-agent-core/iacrypto"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/relayproto"
)

// Type is the value of a record's type field. A change to the form is a new
// type, so a verifier can refuse what it does not read.
const Type = "endpoint-record/1"

// IssuedLayout is the one spelling of a time: UTC, whole seconds, a literal Z.
const IssuedLayout = "2006-01-02T15:04:05Z"

// MaxFuture is how far ahead of the verifier's clock a record may be issued.
// A record issued far ahead would outrank every honest record after it, so it
// is refused rather than held.
const MaxFuture = 10 * time.Minute

// Record is a signed endpoint record, exactly as it travels.
type Record struct {
	Type      string `json:"type"`
	AID       string `json:"aid"`
	Origin    string `json:"origin"`
	Issued    string `json:"issued"`
	Signature string `json:"signature"`
}

// fields are the record's fields by name, signature included.
func (r Record) fields() map[string]any {
	return map[string]any{
		"type": r.Type, "aid": r.AID, "origin": r.Origin,
		"issued": r.Issued, "signature": r.Signature,
	}
}

// Parse reads a record from a decoded JSON object, refusing anything but
// exactly the five string fields: an extra field would be carried unsigned
// beside a signed one.
func Parse(obj map[string]any) (Record, error) {
	if len(obj) != 5 {
		return Record{}, fmt.Errorf("a record has exactly the fields type, aid, origin, issued and signature")
	}
	var s [5]string
	for i, k := range []string{"type", "aid", "origin", "issued", "signature"} {
		v, ok := obj[k].(string)
		if !ok {
			return Record{}, fmt.Errorf("the record's %s is missing or not a string", k)
		}
		s[i] = v
	}
	return Record{Type: s[0], AID: s[1], Origin: s[2], Issued: s[3], Signature: s[4]}, nil
}

// SignedBytes are the bytes the signature is over: relayproto.CanonicalBody
// (ADR-049's form) of the record without its signature.
func (r Record) SignedBytes() ([]byte, error) {
	return relayproto.CanonicalBody(r.fields())
}

// Sign makes a record for aid's origin, issued at the given moment, signed by
// seed, the seed of the key aid's key log names now. It refuses what Check
// would, so a signer cannot produce a record nothing accepts.
func Sign(aid, origin string, issued time.Time, seed []byte) (Record, error) {
	if len(seed) != ed25519.SeedSize {
		return Record{}, fmt.Errorf("a signing seed is %d bytes", ed25519.SeedSize)
	}
	r := Record{Type: Type, AID: aid, Origin: origin, Issued: issued.UTC().Format(IssuedLayout)}
	if err := r.CheckShape(); err != nil {
		return Record{}, err
	}
	msg, err := r.SignedBytes()
	if err != nil {
		return Record{}, err
	}
	sig, err := iacrypto.MatterFixedQB64("0B", ed25519.Sign(ed25519.NewKeyFromSeed(seed), msg))
	if err != nil {
		return Record{}, err
	}
	r.Signature = sig
	return r, nil
}

// CheckShape refuses a record whose fields are not in their one spelling. It
// says nothing of the signature.
func (r Record) CheckShape() error {
	if r.Type != Type {
		return fmt.Errorf("the record's type is %q, not %q", r.Type, Type)
	}
	if r.AID == "" || len(r.AID) > 128 {
		return fmt.Errorf("the record names no identifier")
	}
	if r.Origin != "" {
		if err := CheckOrigin(r.Origin); err != nil {
			return err
		}
	}
	if _, err := r.IssuedAt(); err != nil {
		return err
	}
	return nil
}

// Withdrawn reports whether the record says the identifier is reachable
// nowhere. It names no address, so a caller that needs one must refuse it.
func (r Record) Withdrawn() bool { return r.Origin == "" }

// IssuedAt is when the record says it was signed.
func (r Record) IssuedAt() (time.Time, error) {
	t, err := time.Parse(IssuedLayout, r.Issued)
	if err != nil || t.Format(IssuedLayout) != r.Issued {
		return time.Time{}, fmt.Errorf("issued %q is not %s", r.Issued, IssuedLayout)
	}
	return t, nil
}

// Verify reports whether r is aid's statement: well formed, not issued more
// than MaxFuture after now, and signed by key, the key aid's verified key log
// names now. A record signed by a key the log has since rotated away from is
// refused; its signer publishes again.
//
// A record has no age limit. It stands while the key that signed it is the
// identifier's current key, which any rotation ends, and while no newer one has
// been seen (Newer); an identifier that never moves is as findable in a year as
// on the day it published (ADR-062). VerifyNoOlderThan is the same check with a
// limit, for a verifier that wants one.
func (r Record) Verify(key ed25519.PublicKey, now time.Time) error {
	return r.VerifyNoOlderThan(key, now, 0)
}

// VerifyNoOlderThan is Verify that also refuses a record issued more than
// maxAge before now. Zero means no limit, which is what Verify does; nothing in
// this repository sets one.
func (r Record) VerifyNoOlderThan(key ed25519.PublicKey, now time.Time, maxAge time.Duration) error {
	if err := r.CheckShape(); err != nil {
		return err
	}
	at, _ := r.IssuedAt()
	if at.After(now.Add(MaxFuture)) {
		return fmt.Errorf("the record is issued %s, in the future", r.Issued)
	}
	if maxAge > 0 && at.Before(now.Add(-maxAge)) {
		return fmt.Errorf("the record was issued %s, longer ago than %d days; the identifier must sign a new one", r.Issued, int(maxAge.Hours()/24))
	}
	if len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("a verifying key is %d bytes", ed25519.PublicKeySize)
	}
	sig, err := iacrypto.DecodeEd25519SignatureQB64(r.Signature)
	if err != nil {
		return fmt.Errorf("the record's signature is not a CESR Ed25519 signature: %w", err)
	}
	msg, err := r.SignedBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, msg, sig) {
		return fmt.Errorf("the record is not signed by the identifier's current key")
	}
	return nil
}

// Newer reports whether a replaces b: both speak for the same identifier and
// a was issued strictly after b. Equal is not newer, so a record cannot be
// swapped for another of the same moment.
func Newer(a, b Record) bool {
	if a.AID != b.AID {
		return false
	}
	ta, errA := a.IssuedAt()
	tb, errB := b.IssuedAt()
	return errA == nil && errB == nil && ta.After(tb)
}

// CheckOrigin refuses an origin that is not in its one spelling:
//
//   - scheme is http or https, lower case;
//   - the host is a lower-case DNS name (letters, digits, hyphens, dots; no
//     trailing dot) or an IPv4 address as four decimal numbers without a leading
//     zero, or an IPv6 address in brackets written the way netip writes it;
//   - the port is always written, 1 to 65535, with no leading zero, so https
//     on 443 is "https://host:443" and never "https://host";
//   - nothing follows the port: no path (not even "/"), query, fragment or
//     user information.
//
// One spelling, because origins are compared as text.
func CheckOrigin(o string) error {
	scheme, rest, ok := strings.Cut(o, "://")
	if !ok || (scheme != "http" && scheme != "https") {
		return fmt.Errorf("origin %q does not start with http:// or https://", o)
	}
	var host, port string
	if strings.HasPrefix(rest, "[") {
		end := strings.Index(rest, "]")
		if end < 0 || !strings.HasPrefix(rest[end+1:], ":") {
			return fmt.Errorf("origin %q: an IPv6 host is [address]:port", o)
		}
		host, port = rest[:end+1], rest[end+2:]
		ip, err := netip.ParseAddr(host[1 : len(host)-1])
		if err != nil || !ip.Is6() || ip.Is4In6() || ip.Zone() != "" || ip.String() != host[1:len(host)-1] {
			return fmt.Errorf("origin %q: the IPv6 address is not in its one spelling", o)
		}
	} else {
		i := strings.LastIndex(rest, ":")
		if i < 0 {
			return fmt.Errorf("origin %q has no port; write it, even the default", o)
		}
		host, port = rest[:i], rest[i+1:]
		if err := checkName(host); err != nil {
			return fmt.Errorf("origin %q: %w", o, err)
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return fmt.Errorf("origin %q: the port is 1 to 65535 with no leading zero, and nothing may follow it", o)
	}
	return nil
}

var numericLabel = regexp.MustCompile(`^(?i:0x[0-9a-f]*|[0-9]+)$`)

func checkName(h string) error {
	if h == "" || len(h) > 253 {
		return fmt.Errorf("the host is empty or too long")
	}
	// A host whose last label is a number, or reads as one (0x7f), is an IPv4
	// address to a resolver, and "127.1", "2130706433" and "0x7f.1" are all
	// 127.0.0.1 to one. It is accepted only as four decimal numbers without a
	// leading zero, the one spelling.
	last := h[strings.LastIndex(h, ".")+1:]
	if numericLabel.MatchString(last) {
		ip, err := netip.ParseAddr(h)
		if err != nil || !ip.Is4() || ip.String() != h {
			return fmt.Errorf("the host %q is a number that is not four decimal numbers", h)
		}
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("the host %q is not a DNS name in lower case", h)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return fmt.Errorf("the host %q is not a DNS name in lower case", h)
			}
		}
	}
	return nil
}

// OriginOf is the origin of an address as the form writes it: the scheme and
// host in lower case and the port always written, the default one included. It
// refuses an address with user information, which an origin never has, and
// ignores the path, query and fragment, which it does not include.
func OriginOf(address string) (string, error) {
	u, err := url.Parse(address)
	if err != nil {
		return "", fmt.Errorf("%q is not an address: %w", address, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if u.User != nil || u.Hostname() == "" || (scheme != "http" && scheme != "https") {
		return "", fmt.Errorf("%q is not an http or https address with a host", address)
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[scheme]
	}
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	origin := scheme + "://" + host + ":" + port
	if err := CheckOrigin(origin); err != nil {
		return "", err
	}
	return origin, nil
}
