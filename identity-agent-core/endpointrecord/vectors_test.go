package endpointrecord

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"sort"
	"strings"
	"testing"
	"time"

	"identity-agent-core/iacrypto"
	"identity-agent-core/internal/contractcheck"
)

const vectorAID = "EKYLUMmNPZeEs77Zvclf0bSN5IN-mLfLpx2ySb-HDlk4"

var vectorSeed = func() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
}()

var otherSeed = func() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(0xa0 + i)
	}
	return b
}()

var nextSeed = func() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(0x50 + i)
	}
	return b
}()

func qb64Key(seed []byte) string {
	return iacrypto.VerkeyQB64(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
}

var vectorNow = time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC)

func mustSign(t *testing.T, origin string, issued time.Time) Record {
	t.Helper()
	r, err := Sign(vectorAID, origin, issued, vectorSeed)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func asObject(r Record) map[string]any {
	return map[string]any{"type": r.Type, "aid": r.AID, "origin": r.Origin, "issued": r.Issued, "signature": r.Signature}
}

// signUnchecked signs whatever fields it is given, which Sign would refuse, so
// a vector can carry a record that is validly signed and still not accepted.
func signUnchecked(t *testing.T, r Record, seed []byte) Record {
	t.Helper()
	msg, err := r.SignedBytes()
	if err != nil {
		t.Fatal(err)
	}
	r.Signature, err = iacrypto.MatterFixedQB64("0B", ed25519.Sign(ed25519.NewKeyFromSeed(seed), msg))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func buildVectors(t *testing.T) VectorSet {
	set := VectorSet{
		About: "Signed endpoint records (package endpointrecord). A record names the one origin an " +
			"identifier is reached at, and is signed by the key the identifier's verified key log " +
			"names now. canonical is the bytes the Ed25519 signature is over: the record's fields " +
			"other than signature as a JSON object, keys sorted, no whitespace (ADR-049's form). The " +
			"signature is CESR qb64, code 0B. valid says whether the record verifies against key at " +
			"now, the verifier's clock: a record issued more than 10 minutes after now, or more than " +
			"90 days before it, does not verify. next_public_key is the key the identifier's log names after a " +
			"rotation. requests are the strings a controller signs for a request, the second form and the third, " +
			"which names the origin: lines joined by a line feed. origins are in their one spelling or not; ordering says " +
			"whether record A replaces record B. addresses are what a client is pointed at and the origin it signs for (empty when it has none).",
		SeedHex:        hex.EncodeToString(vectorSeed),
		PublicKey:      qb64Key(vectorSeed),
		OtherPublicKey: qb64Key(otherSeed),
		NextSeedHex:    hex.EncodeToString(nextSeed),
		NextPublicKey:  qb64Key(nextSeed),
		Now:            vectorNow.Format(IssuedLayout),
	}
	issued := vectorNow.Add(-time.Hour)
	add := func(name string, r Record, obj map[string]any, key string, valid bool, why string) {
		whole := obj == nil
		if whole {
			obj = asObject(r)
		}
		v := RecordVector{Name: name, Record: obj, Key: key, Valid: valid, Why: why}
		// Only a record that is the five strings has bytes it is signed over.
		if msg, err := r.SignedBytes(); err == nil && whole {
			v.Canonical = string(msg)
		}
		set.Records = append(set.Records, v)
	}

	good := mustSign(t, "https://org.example.com:443", issued)
	add("an origin on the default port", good, nil, "public_key", true, "")
	add("an origin on another port", mustSign(t, "https://org.example.com:8443", issued), nil, "public_key", true, "")
	add("a plain http origin", mustSign(t, "http://192.0.2.7:8080", issued), nil, "public_key", true, "")
	add("an IPv6 origin", mustSign(t, "https://[2001:db8::1]:443", issued), nil, "public_key", true, "")
	add("a withdrawal, which names no address", mustSign(t, "", issued), nil, "public_key", true, "")
	add("issued a few minutes ahead of the verifier", mustSign(t, "https://org.example.com:443", vectorNow.Add(5*time.Minute)), nil, "public_key", true, "")

	add("issued just inside the maximum age", mustSign(t, "https://org.example.com:443", vectorNow.Add(-MaxAge+time.Minute)), nil, "public_key", true, "")
	// A rotation: the verified key log names the next key from now on, so what
	// the replaced key signed, however genuine it was, is refused.
	rotated, err := Sign(vectorAID, "https://org.example.com:443", issued, nextSeed)
	if err != nil {
		t.Fatal(err)
	}
	add("signed by the key a rotation put in force", rotated, nil, "next_public_key", true, "")
	add("signed by the key a rotation replaced, checked against the key in force now", good, nil, "next_public_key", false, "signature")
	add("signed by the key in force after a rotation, checked against the key before it", rotated, nil, "public_key", false, "signature")
	add("signed by a key the identifier's log does not name", good, nil, "other_public_key", false, "signature")
	bad := good
	bad.Origin = "https://evil.example.com:443"
	add("the origin changed after signing", bad, nil, "public_key", false, "signature")
	bad = good
	bad.Issued = vectorNow.Add(-time.Minute).Format(IssuedLayout)
	add("the issue time changed after signing", bad, nil, "public_key", false, "signature")
	bad = good
	bad.AID = "EOtherIdentifierOtherIdentifierOtherIdentif"
	add("the identifier changed after signing", bad, nil, "public_key", false, "signature")
	add("issued further ahead of the verifier than allowed",
		mustSign(t, "https://org.example.com:443", vectorNow.Add(11*time.Minute)), nil, "public_key", false, "future")

	add("issued longer ago than the maximum age", mustSign(t, "https://org.example.com:443", vectorNow.Add(-MaxAge-time.Minute)), nil, "public_key", false, "expired")

	notDefault := Record{Type: Type, AID: vectorAID, Origin: "https://org.example.com", Issued: good.Issued}
	add("an origin without its port, validly signed", signUnchecked(t, notDefault, vectorSeed), nil, "public_key", false, "origin")
	upper := Record{Type: Type, AID: vectorAID, Origin: "https://Org.Example.com:443", Issued: good.Issued}
	add("an origin in upper case, validly signed", signUnchecked(t, upper, vectorSeed), nil, "public_key", false, "origin")
	path := Record{Type: Type, AID: vectorAID, Origin: "https://org.example.com:443/", Issued: good.Issued}
	add("an origin with a path, validly signed", signUnchecked(t, path, vectorSeed), nil, "public_key", false, "origin")
	other := Record{Type: "endpoint-record/2", AID: vectorAID, Origin: good.Origin, Issued: good.Issued}
	add("another type, validly signed", signUnchecked(t, other, vectorSeed), nil, "public_key", false, "type")
	subsec := Record{Type: Type, AID: vectorAID, Origin: good.Origin, Issued: "2026-11-04T11:00:00.5Z"}
	add("an issue time with a fraction, validly signed", signUnchecked(t, subsec, vectorSeed), nil, "public_key", false, "issued")
	offset := Record{Type: Type, AID: vectorAID, Origin: good.Origin, Issued: "2026-11-04T11:00:00+00:00"}
	add("an issue time with an offset, validly signed", signUnchecked(t, offset, vectorSeed), nil, "public_key", false, "issued")

	extra := asObject(good)
	extra["note"] = "carried beside the signed fields"
	add("a field the form does not have", good, extra, "public_key", false, "fields")
	missing := asObject(good)
	delete(missing, "issued")
	add("a record with no issue time", good, missing, "public_key", false, "fields")
	number := asObject(good)
	number["issued"] = 1762257600
	add("an issue time that is a number", good, number, "public_key", false, "fields")

	// The same signature in a second spelling: a lead bit of the qb64 set. A
	// lenient decoder reads it as the same bytes (ADR-060).
	spelled := asObject(good)
	spelled["signature"] = "0C" + good.Signature[2:]
	add("the signature with a lead bit set", good, spelled, "public_key", false, "signature")
	bare := asObject(good)
	bare["signature"] = good.Signature[2:]
	add("the signature without its code", good, bare, "public_key", false, "signature")
	unsigned := asObject(good)
	unsigned["signature"] = ""
	add("an empty signature", good, unsigned, "public_key", false, "signature")

	for _, o := range []string{
		"https://org.example.com:443", "http://org.example.com:80", "https://a.b.c-d.example:65535",
		"https://127.0.0.1:1", "https://192.0.2.255:8443", "https://host1.example.com:443", "https://3com.example:443", "https://example.1a:443", "https://[::1]:443", "https://[2001:db8::1]:8443", "https://xn--bcher-kva.example:443",
	} {
		set.Origins = append(set.Origins, OriginVector{Origin: o, OK: true})
	}
	for _, o := range []string{
		"", "org.example.com:443", "https://org.example.com", "https://org.example.com:", "https://org.example.com:0",
		"https://org.example.com:65536", "https://org.example.com:0443", "https://org.example.com:+443",
		"https://org.example.com:443/", "https://org.example.com:443/path", "https://org.example.com:443?x=1",
		"https://org.example.com:443#x", "https://user@org.example.com:443", "https://user:pw@org.example.com:443",
		"HTTPS://org.example.com:443", "ftp://org.example.com:443", "https://Org.example.com:443",
		"https://org.example.com.:443", "https://-org.example.com:443", "https://org..example.com:443",
		"https://org example.com:443", "https://org.example.com:443 ", "https://bücher.example:443",
		"https://org_example.com:443", "https://[::1]", "https://[::1]:0", "https://[0:0:0:0:0:0:0:1]:443",
		"https://[::FFFF:1.2.3.4]:443", "https://[::ffff:1.2.3.4]:443", "https://[fe80::1%25eth0]:443",
		"https://::1:443", "//org.example.com:443", "https://:443",
		"http://127.1:80", "http://0177.0.0.1:80", "http://2130706433:80", "http://0x7f.1:80", "http://0x7f.0x0.0x0.0x1:80",
		"http://1.2.3:80", "http://1.2.3.4.5:80", "http://256.1.1.1:80", "http://01.2.3.4:80", "http://127.0.0.1.:80",
	} {
		set.Origins = append(set.Origins, OriginVector{Origin: o, OK: false})
	}

	t1, t2 := "2026-11-04T10:00:00Z", "2026-11-04T10:00:01Z"
	for in, out := range map[string]string{
		"https://Org.Example.com":          "https://org.example.com:443",
		"http://org.example.com/a/b?c=d#e": "http://org.example.com:80",
		"https://org.example.com:8443/":    "https://org.example.com:8443",
		"https://[2001:DB8::1]:9":          "https://[2001:db8::1]:9",
		"HTTP://192.0.2.7":                 "http://192.0.2.7:80",
		"https://org.example.com:0443":     "",
		"https://user@org.example.com":     "",
		"ftp://org.example.com:21":         "",
		"org.example.com":                  "",
		"https://":                         "",
		"http://127.1":                     "",
		"https://bücher.example":           "",
	} {
		set.Addresses = append(set.Addresses, AddressVector{Address: in, Origin: out})
	}
	sort.Slice(set.Addresses, func(i, j int) bool { return set.Addresses[i].Address < set.Addresses[j].Address })

	set.Ordering = []OrderVector{
		{"issued later replaces", vectorAID, t2, vectorAID, t1, true},
		{"issued earlier is refused", vectorAID, t1, vectorAID, t2, false},
		{"the same moment does not replace", vectorAID, t1, vectorAID, t1, false},
		{"another identifier's record never replaces", "EOtherIdentifierOtherIdentifierOtherIdentif", t2, vectorAID, t1, false},
		{"an issue time not in its spelling replaces nothing", vectorAID, "2026-11-04T10:00:02", vectorAID, t1, false},
	}

	body := iacrypto.Blake3QB64Must([]byte(`{"to":"EAGENT"}`))
	request := func(name, origin, level, at string, score int) RequestVector {
		v := RequestVector{Name: name, Controller: "BD93CNX1zCvGM7WdKzou2S50eSIMbwit4gi-vNhYCrk7", IdentityAgent: "EORGANISATION",
			Origin: origin, Method: "POST", Path: "/api/conversations", Timestamp: "2026-10-20T11:59:00Z",
			Level: level, MeasuredAt: at, Score: score, BodyDigest: body}
		form, named := "IA-CONTROLLER-REQ-V2", []string{v.Controller, v.IdentityAgent}
		if origin != "" {
			form, named = "IA-CONTROLLER-REQ-V3", append(named, origin)
		}
		v.Signed = strings.Join(append(append([]string{form}, named...),
			v.Method, v.Path, v.Timestamp, level, at, strconv.Itoa(score), body), "\n")
		return v
	}
	set.Requests = []RequestVector{
		request("the third form names the origin", "https://agent.example.com:443", "", "", 0),
		request("the third form with an authentication vouched for", "https://agent.example.com:443", "software", "2026-10-20T11:58:30Z", 40),
		request("the third form at an address on a port", "http://192.0.2.7:8080", "", "", 0),
		request("the second form names none", "", "", "", 0),
		request("the second form with an authentication vouched for", "", "software", "2026-10-20T11:58:30Z", 40),
	}
	return set
}

func TestThePublishedEndpointRecordVectorsHold(t *testing.T) {
	if contractcheck.Writing(t) {
		raw, err := json.MarshalIndent(buildVectors(t), "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile("endpoint-record-vectors.json", append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	set, err := Vectors()
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Records) < 27 || len(set.Origins) < 30 || len(set.Ordering) < 4 || len(set.Addresses) < 10 || len(set.Requests) < 5 {
		t.Fatal("the vector file is missing cases")
	}

	// What the file says is what the code makes: rebuilt, never copied.
	want := buildVectors(t)
	a, _ := json.Marshal(want)
	b, _ := json.Marshal(set)
	if string(a) != string(b) {
		t.Fatal("the vector file is not what the code produces; regenerate with IA_WRITE_CONTRACTS=1 and review the diff")
	}

	now, err := time.Parse(IssuedLayout, set.Now)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{"public_key": set.PublicKey, "other_public_key": set.OtherPublicKey, "next_public_key": set.NextPublicKey}
	for _, v := range set.Records {
		raw, _ := json.Marshal(v.Record)
		var obj map[string]any
		_ = json.Unmarshal(raw, &obj)
		key, _, err := iacrypto.DecodeEd25519Key(keys[v.Key], false)
		if err != nil {
			t.Fatal(err)
		}
		var verr error
		if r, perr := Parse(obj); perr != nil {
			verr = perr
		} else {
			verr = r.Verify(key, now)
		}
		if (verr == nil) != v.Valid {
			t.Errorf("%s: valid=%v but verification said %v", v.Name, v.Valid, verr)
		}
	}
	for _, o := range set.Origins {
		if got := CheckOrigin(o.Origin) == nil; got != o.OK {
			t.Errorf("origin %q: ok=%v, code says %v", o.Origin, o.OK, got)
		}
	}
	for _, a := range set.Addresses {
		got, err := OriginOf(a.Address)
		if (err == nil) != (a.Origin != "") || got != a.Origin {
			t.Errorf("address %q: origin %q, code says %q (%v)", a.Address, a.Origin, got, err)
		}
	}
	for _, o := range set.Ordering {
		a := Record{AID: o.AAID, Issued: o.AIssue}
		b := Record{AID: o.BAID, Issued: o.BIssue}
		if got := Newer(a, b); got != o.Newer {
			t.Errorf("%s: newer=%v, code says %v", o.Name, o.Newer, got)
		}
	}
	if !strings.HasPrefix(set.PublicKey, "D") {
		t.Fatal("the public key is a qb64 verifier")
	}
}

// A record signed for one origin cannot be made to name another, and a
// signature made by anything but the identifier's key is not accepted.
func TestARecordNamesTheOriginItWasSignedFor(t *testing.T) {
	r := mustSign(t, "https://org.example.com:443", vectorNow.Add(-time.Hour))
	key := ed25519.NewKeyFromSeed(vectorSeed).Public().(ed25519.PublicKey)
	if err := r.Verify(key, vectorNow); err != nil {
		t.Fatal(err)
	}
	r.Origin = "https://org.example.com:444"
	if r.Verify(key, vectorNow) == nil {
		t.Fatal("a record verified for an origin it was not signed for")
	}
}

func TestAnIndependentImplementationAgreesWithTheEndpointRecordVectors(t *testing.T) {
	contractcheck.IndependentlyWith(t, "check_endpoint_record_vectors.py", "endpoint-record-vectors.json", "cryptography")
}

func TestAnAddressBecomesTheOriginTheFormWrites(t *testing.T) {
	for in, want := range map[string]string{
		"https://Relay.Example.com":          "https://relay.example.com:443",
		"http://relay.example.com/a/b?c=d#e": "http://relay.example.com:80",
		"https://relay.example.com:8443/":    "https://relay.example.com:8443",
		"https://[2001:DB8::1]:9":            "https://[2001:db8::1]:9",
	} {
		got, err := OriginOf(in)
		if err != nil || got != want {
			t.Errorf("OriginOf(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "relay.example.com", "ftp://x.example:21", "https://u:p@x.example", "https://"} {
		if got, err := OriginOf(in); err == nil {
			t.Errorf("OriginOf(%q) = %q, want a refusal", in, got)
		}
	}
}
