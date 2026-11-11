package login

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"identity-agent-core/internal/contractcheck"
)

// Two verifiers, one per language, apply the same rules to an assertion: how
// long it stays fresh, which binding is checked first and what it says when it
// fails, which browser-key spellings are a thumbprint, how a thumbprint is
// made, which documents are read at all, and when an assertion is spent. The
// canonical bodies and spellings are held in core-canonical-and-spellings.json;
// this file holds the decisions, so a rule changed in one language and not the
// other fails in the one that was not changed.
//
// The cases are written here, signed here, and decided here by the core's own
// code; the TypeScript package runs the same file
// (src/every-rule-is-decided-alike.test.mjs). When the core changes on purpose,
// regenerate with
//
//	IA_WRITE_CONTRACTS=1 go test ./login -run TestThePublishedVerifyDecisionsAreTheCores
//
// and review the diff: every changed decision is one the TypeScript package
// has to make too.
var verifyDecisionsPath = filepath.Join("..", "..", "packages", "login-verify", "test-vectors",
	"verify-decisions.json")

type verifyDecisionFile struct {
	Description       string             `json:"description"`
	FreshnessWindows  []windowCase       `json:"freshness_windows"`
	BrowserKeys       []thumbprintCase   `json:"browser_key_thumbprints"`
	P256Thumbprints   []p256Case         `json:"p256_thumbprints"`
	Verifications     []verificationCase `json:"verifications"`
	SpendingSequences []spendingSequence `json:"spending_sequences"`
	SpendingRule      string             `json:"spending_rule"`
}

// The window, in seconds, a maxSkewSeconds asks for.
type windowCase struct {
	Name           string `json:"name"`
	MaxSkewSeconds int    `json:"max_skew_seconds"`
	Seconds        int    `json:"seconds"`
}

type thumbprintCase struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	GoAccepts bool   `json:"go_accepts"`
}

// The RFC 7638 thumbprint of a P-256 key given as JWK coordinates, or none.
type p256Case struct {
	Name       string `json:"name"`
	X          string `json:"x"`
	Y          string `json:"y"`
	GoAccepts  bool   `json:"go_accepts"`
	Thumbprint string `json:"thumbprint,omitempty"`
}

type expectation struct {
	Nonce      string `json:"nonce"`
	Audience   string `json:"audience"`
	SiteAID    string `json:"site_aid"`
	BrowserKey string `json:"browser_key"`
	FrontEnd   string `json:"front_end"`
}

// One check of one document: what a relying party expects, the clock, the
// key, and what the core makes of it. Reason is exactly the core's text.
type verificationCase struct {
	Name           string      `json:"name"`
	AssertionJSON  string      `json:"assertion_json"`
	Now            string      `json:"now"`
	Expect         expectation `json:"expect"`
	MaxSkewSeconds int         `json:"max_skew_seconds"`
	PublicKeyHex   string      `json:"public_key_hex"`
	GoReads        bool        `json:"go_reads"`
	GoValid        bool        `json:"go_valid"`
	GoReason       string      `json:"go_reason,omitempty"`
}

// Assertions presented in turn to one relying party's store of spent
// assertions. Each step is one of the verification cases above, named.
type spendingSequence struct {
	Name  string         `json:"name"`
	Steps []spendingStep `json:"steps"`
}

type spendingStep struct {
	Case     string `json:"case"`
	Accepted bool   `json:"accepted"`
	Reason   string `json:"reason,omitempty"`
}

const (
	vdSeedHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	vdNow     = "2026-06-17T12:00:00Z"
	// RFC 7515 appendix A.3's P-256 key and its RFC 7638 thumbprint.
	vdX     = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU"
	vdY     = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
	vdThumb = "oKIywvGUpTVTyxMQ3bwIIeQUudfr_CkLMjCE19ECD-U"
)

// The rule the spending sequences are decided by. It is the TypeScript
// verifier's: the core's login package spends nothing itself (the core
// server finishes a sign-in on its first answer, accepted or not, which is a
// different rule and is tested where that server is), so the sequences'
// expectations are written here, from the core's decision on each assertion
// and this rule.
const vdSpendingRule = "An assertion the verifier accepts is spent under audience|nonce|i, and a later " +
	"presentation under the same three is refused with \"assertion already used\". An assertion refused " +
	"for any other reason spends nothing."

func verificationCases(t *testing.T) []verificationCase {
	seed, _ := hex.DecodeString(vdSeedHex)
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	otherSeed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	otherPub := ed25519.NewKeyFromSeed(otherSeed).Public().(ed25519.PublicKey)

	base := func() Assertion {
		return Assertion{
			V: "IALOGIN10JSON", T: "login-assertion", I: "EAsserter",
			RelationshipAIDOOBI: "https://r.example/oobi/EAsserter",
			Audience:            "https://app.example.com", Nonce: "nonce-1", Dt: vdNow,
			Disclosures: map[string]string{"display_name": "Alice"}, PresentedACDCs: []interface{}{},
			SiteAID: "ESite",
		}
	}
	sign := func(a Assertion, seed []byte) Assertion {
		a.D, a.Sig = "", ""
		d, err := assertionDigest(a)
		if err != nil {
			t.Fatal(err)
		}
		a.D = d
		a.Sig, err = SignString(canonicalAssertionBody(a), seed)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	expectFor := func(a Assertion) expectation {
		return expectation{Nonce: a.Nonce, Audience: a.Audience, SiteAID: a.SiteAID, BrowserKey: a.BrowserKey, FrontEnd: a.FrontEnd}
	}

	var cases []verificationCase
	add := func(name string, a Assertion, e expectation, now string, skew int, key ed25519.PublicKey) {
		j, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		cases = append(cases, verificationCase{Name: name, AssertionJSON: string(j), Now: now, Expect: e,
			MaxSkewSeconds: skew, PublicKeyHex: hex.EncodeToString(key)})
	}
	addText := func(name, text string) {
		cases = append(cases, verificationCase{Name: name, AssertionJSON: text, Now: vdNow,
			Expect: expectFor(base()), PublicKeyHex: hex.EncodeToString(pub)})
	}
	plain := func(name string, a Assertion) { add(name, a, expectFor(a), vdNow, 0, pub) }
	// An assertion whose dt is `secs` seconds before the clock (negative: after).
	at := func(name string, dt string, now string, skew int) {
		a := base()
		a.Dt = dt
		add(name, sign(a, seed), expectFor(a), now, skew, pub)
	}
	withExpect := func(name string, e expectation) {
		add(name, sign(base(), seed), e, vdNow, 0, pub)
	}
	clock := func(secs int) string {
		n, _ := time.Parse(time.RFC3339, vdNow)
		return n.Add(time.Duration(secs) * time.Second).UTC().Format(time.RFC3339)
	}

	// Accepted.
	plain("an assertion that answers its challenge", sign(base(), seed))
	{
		a := base()
		a.BrowserKey = vdThumb
		plain("a sign-in for a browser key, repeating that key", sign(a, seed))
	}

	// A sign-in for a utility app names the kind of front end, and the person's
	// assertion repeats it (ADR-072 section 2, amended).
	for _, kind := range []string{"browser", "installed_app"} {
		a := base()
		a.FrontEnd = kind
		plain("a sign-in for the "+kind+" front end, repeating that kind", sign(a, seed))
	}

	// Freshness: the window is either side of the clock, inclusive.
	at("dt 300 seconds before the clock is inside the default window", clock(-300), vdNow, 0)
	at("dt 301 seconds before the clock is outside it", clock(-301), vdNow, 0)
	at("dt 300 seconds after the clock is inside it", clock(300), vdNow, 0)
	at("dt 301 seconds after the clock is outside it", clock(301), vdNow, 0)
	at("a window of 10 seconds takes 10", clock(-10), vdNow, 10)
	at("a window of 10 seconds refuses 11", clock(-11), vdNow, 10)
	at("a window of zero is the default, so 300 is inside", clock(-300), vdNow, 0)
	at("a window of zero is the default, so 301 is outside", clock(-301), vdNow, 0)
	at("a negative window is the default, so 301 is outside", clock(-301), vdNow, -5)
	at("a negative window is the default, so 300 is inside", clock(-300), vdNow, -5)
	at("a window of an hour takes an hour", clock(-3600), vdNow, 3600)
	at("a window of an hour refuses an hour and a second", clock(-3601), vdNow, 3600)
	at("a wider window than an hour is narrowed, so an hour is inside", clock(-3600), vdNow, 100000)
	at("a wider window than an hour is narrowed, so an hour and a second is outside", clock(-3601), vdNow, 100000)
	at("a wider window than an hour is narrowed, in the future too", clock(3601), vdNow, 2147483647)
	at("a dt written in another offset is the instant it names", "2026-06-17T14:00:00+02:00", vdNow, 0)
	at("a dt in another offset that names a stale instant is refused", "2026-06-17T14:00:00Z", vdNow, 0)
	at("a dt with a fraction just inside the window", "2026-06-17T11:55:00.5Z", vdNow, 0)
	at("a dt with a fraction just outside the window", "2026-06-17T11:54:59.999Z", vdNow, 0)
	at("a dt a nanosecond outside the window is outside", "2026-06-17T12:05:00.000000001Z", vdNow, 0)
	at("a dt a nanosecond inside the window is inside", "2026-06-17T12:04:59.999999999Z", vdNow, 0)
	at("an unreadable dt is refused, not compared", "not a time", vdNow, 0)
	at("an empty dt is refused", "", vdNow, 0)
	at("a dt with a comma before the fraction is refused", "2026-06-17T12:00:00,5Z", vdNow, 0)
	at("a dt on a day that does not exist is refused", "2026-02-30T12:00:00Z", vdNow, 0)
	at("a dt in 2001 is refused", "2001-01-01T00:00:00Z", vdNow, 0)
	// Unreadable time wins over a window that would also refuse it, and a
	// wrong dt wins over every binding after it.
	{
		a := base()
		a.Dt, a.Nonce, a.Audience = clock(-9999), "other", "https://other.example"
		add("a stale dt is refused before the nonce and audience are looked at", sign(a, seed),
			expectation{Nonce: "nonce-1", Audience: "https://app.example.com", SiteAID: "ESite"}, vdNow, 0, pub)
	}

	// Binding order: nonce, audience, site, browser key, sig, signature.
	e := expectFor(base())
	withExpect("a different nonce is refused", expectation{"nonce-2", e.Audience, e.SiteAID, "", ""})
	withExpect("a different audience is refused", expectation{e.Nonce, "https://other.example", e.SiteAID, "", ""})
	withExpect("another site's challenge is refused", expectation{e.Nonce, e.Audience, "EOtherSite", "", ""})
	withExpect("an expected site that is empty is refused", expectation{e.Nonce, e.Audience, "", "", ""})
	withExpect("a nonce wins over a wrong audience", expectation{"nonce-2", "https://other.example", e.SiteAID, "", ""})
	withExpect("an audience wins over a wrong site", expectation{e.Nonce, "https://other.example", "EOtherSite", "", ""})
	withExpect("a wrong site wins over a wrong browser key", expectation{e.Nonce, e.Audience, "EOtherSite", vdThumb, ""})
	withExpect("a browser key the assertion does not repeat is refused", expectation{e.Nonce, e.Audience, e.SiteAID, vdThumb, ""})
	{
		a := base()
		a.BrowserKey = vdThumb
		add("a browser key where the challenge named none is refused", sign(a, seed), e, vdNow, 0, pub)
		other := expectation{e.Nonce, e.Audience, e.SiteAID, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", ""}
		add("a different browser key is refused", sign(a, seed), other, vdNow, 0, pub)
		a.BrowserKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		a.Sig = ""
		add("a wrong browser key wins over a missing signature", a, expectFor(base()), vdNow, 0, pub)
	}
	for _, c := range []struct{ name, key string }{
		{"a challenge's browser key with padding", vdThumb + "="},
		{"a challenge's browser key one character short", vdThumb[:42]},
		{"a challenge's browser key in the standard alphabet", "oKIywvGUpTVTyxMQ3bwIIeQUudfr/CkLMjCE19ECD+U"},
		{"a challenge's browser key with unused bits set", vdThumb[:42] + "V"},
		{"a challenge's browser key with a space", vdThumb[:20] + " " + vdThumb[21:]},
	} {
		a := base()
		a.BrowserKey = c.key
		add(c.name+" is refused though the assertion repeats it", sign(a, seed), expectFor(a), vdNow, 0, pub)
	}
	// Front end: checked after the browser key and before the signature.
	{
		a := base()
		a.FrontEnd = "browser"
		add("a front end where the challenge named none is refused", sign(a, seed), e, vdNow, 0, pub)
		add("a different front end is refused", sign(a, seed),
			expectation{Nonce: e.Nonce, Audience: e.Audience, SiteAID: e.SiteAID, FrontEnd: "installed_app"}, vdNow, 0, pub)
		add("a front end the assertion does not repeat is refused", sign(base(), seed),
			expectation{Nonce: e.Nonce, Audience: e.Audience, SiteAID: e.SiteAID, FrontEnd: "browser"}, vdNow, 0, pub)
		add("a wrong browser key wins over a wrong front end", sign(a, seed),
			expectation{Nonce: e.Nonce, Audience: e.Audience, SiteAID: e.SiteAID, BrowserKey: vdThumb, FrontEnd: "installed_app"}, vdNow, 0, pub)
		a.Sig = ""
		a.FrontEnd = "installed_app"
		add("a wrong front end wins over a missing signature", a,
			expectation{Nonce: e.Nonce, Audience: e.Audience, SiteAID: e.SiteAID, FrontEnd: "browser"}, vdNow, 0, pub)
		for _, kind := range []string{"Browser", "desktop", " browser"} {
			a := base()
			a.FrontEnd = kind
			add("a challenge's front end '"+kind+"' is refused though the assertion repeats it", sign(a, seed), expectFor(a), vdNow, 0, pub)
		}
	}
	{
		a := base()
		a.Sig = ""
		plain("an assertion with no signature is refused", a)
	}
	{
		a := sign(base(), seed)
		a.Disclosures = map[string]string{"display_name": "Mallory"}
		plain("a body changed after signing is refused", a)
	}
	add("an assertion signed by another key is refused", sign(base(), otherSeed), expectFor(base()), vdNow, 0, pub)
	add("an assertion checked under another key is refused", sign(base(), seed), expectFor(base()), vdNow, 0, otherPub)
	{
		a := sign(base(), seed)
		a.Sig += "="
		plain("a signature with padding is refused", a)
	}
	{
		a := sign(base(), seed)
		a.D = "EG_cHUI0SD-MBeGHZn2v4YklTwBkwLSQGOA459pZcwZ_"
		plain("a digest that is not the body's does not change the verdict, the signature covers it", a)
	}

	// Strict reading: a document two readers could read differently is not
	// read, so it is never verified.
	signed := sign(base(), seed)
	sj, _ := json.Marshal(signed)
	text := string(sj)
	addText("a signed assertion read as written", text)
	addText("a repeated field is not read", strings.Replace(text, `"nonce":"nonce-1"`, `"nonce":"nonce-1","nonce":"nonce-2"`, 1))
	addText("a field in another case is not read", strings.Replace(text, `"nonce":"nonce-1"`, `"nonce":"nonce-1","Nonce":"nonce-2"`, 1))
	addText("an unknown field is not read", strings.Replace(text, `"v":`, `"extra":"x","v":`, 1))
	addText("a number where a string is expected is not read", strings.Replace(text, `"nonce":"nonce-1"`, `"nonce":1`, 1))
	addText("a document that is a list is not read", "[]")
	addText("a document that is null is not read", "null")
	addText("text that is not JSON is not read", "not json")
	addText("trailing text after the document is not read", text+" x")

	for i := range cases {
		c := &cases[i]
		a, err := ReadAssertion([]byte(c.AssertionJSON))
		if err != nil {
			continue
		}
		c.GoReads = true
		now, err := time.Parse(time.RFC3339, c.Now)
		if err != nil {
			t.Fatal(err)
		}
		key, _ := hex.DecodeString(c.PublicKeyHex)
		res := verifyAssertionAt(a, c.Expect.Nonce, c.Expect.Audience, c.Expect.SiteAID, c.Expect.BrowserKey, c.Expect.FrontEnd,
			c.MaxSkewSeconds, now, func(string, string) ([]byte, error) { return key, nil })
		c.GoValid, c.GoReason = res.Valid, res.Reason
	}
	return cases
}

func thumbprintCases() []thumbprintCase {
	other := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	cases := []thumbprintCase{
		{Name: "an RFC 7638 thumbprint", Value: vdThumb},
		{Name: "all zero bytes", Value: other},
		{Name: "all one bits", Value: strings.Repeat("_", 42) + "8"},
		{Name: "empty", Value: ""},
		{Name: "one character short", Value: vdThumb[:42]},
		{Name: "one character long", Value: vdThumb + "A"},
		{Name: "padding", Value: vdThumb + "="},
		{Name: "unused bits set", Value: vdThumb[:42] + "V"},
		{Name: "the standard alphabet", Value: "oKIywvGUpTVTyxMQ3bwIIeQUudfr/CkLMjCE19ECD+U"},
		{Name: "a character outside the alphabet", Value: vdThumb[:10] + "." + vdThumb[11:]},
		{Name: "a space", Value: vdThumb[:10] + " " + vdThumb[11:]},
		{Name: "a newline at the end", Value: vdThumb + "\n"},
		{Name: "a thumbprint of the wrong length, 64 hex characters", Value: strings.Repeat("ab", 32)},
		{Name: "a non-ASCII character", Value: vdThumb[:42] + "é"},
	}
	for i := range cases {
		cases[i].GoAccepts = CheckBrowserKeyThumbprint(cases[i].Value) == nil
	}
	return cases
}

func p256Cases() []p256Case {
	cases := []p256Case{
		{Name: "RFC 7515 appendix A.3's key", X: vdX, Y: vdY},
		{Name: "a coordinate of zeroes, which is not on the curve and is not checked", X: strings.Repeat("A", 43), Y: strings.Repeat("A", 43)},
		{Name: "x one character short", X: vdX[:42], Y: vdY},
		{Name: "y one character long", X: vdX, Y: vdY + "A"},
		{Name: "x with padding", X: vdX + "=", Y: vdY},
		{Name: "y with unused bits set", X: vdX, Y: vdY[:42] + "b"},
		{Name: "x in the standard alphabet", X: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVE/", Y: vdY},
		{Name: "x empty", X: "", Y: vdY},
		{Name: "y empty", X: vdX, Y: ""},
		{Name: "x and y swapped is a different key with a different thumbprint", X: vdY, Y: vdX},
		{Name: "a quote in x cannot break out of the thumbprint input", X: vdX[:20] + `"` + vdX[21:], Y: vdY},
		{Name: "a coordinate that is hex", X: strings.Repeat("ab", 32), Y: vdY},
	}
	for i := range cases {
		if tp, err := ThumbprintP256(cases[i].X, cases[i].Y); err == nil {
			cases[i].GoAccepts, cases[i].Thumbprint = true, tp
		}
	}
	return cases
}

func windowCases() []windowCase {
	var out []windowCase
	for _, s := range []int{-2147483648, -1, 0, 1, 10, 299, 300, 301, 3599, 3600, 3601, 86400, 2147483647} {
		out = append(out, windowCase{Name: fmt.Sprintf("a window of %d", s), MaxSkewSeconds: s,
			Seconds: int(freshnessWindow(s) / time.Second)})
	}
	return out
}

func spendingSequences(cases []verificationCase) []spendingSequence {
	decided := map[string]verificationCase{}
	for _, c := range cases {
		decided[c.Name] = c
	}
	const ok = "an assertion that answers its challenge"
	seqs := [][]string{
		// The same assertion twice.
		{ok, ok},
		// A refused assertion spends nothing, so the real one still passes.
		{"a body changed after signing is refused", ok, ok},
		{"an assertion checked under another key is refused", ok},
		{"dt 301 seconds before the clock is outside it", ok},
		// A different assertion is not the same one.
		{ok, "a sign-in for a browser key, repeating that key", "dt 300 seconds after the clock is inside it"},
	}
	names := []string{
		"the same assertion presented twice",
		"a forged copy first does not spend the real assertion",
		"a copy checked under the wrong key first does not spend it",
		"a stale copy first does not spend it",
		"assertions that share an audience, a nonce and an asserter are one assertion",
	}
	var out []spendingSequence
	for i, steps := range seqs {
		seq := spendingSequence{Name: names[i]}
		spent := map[string]bool{}
		for _, name := range steps {
			c, found := decided[name]
			if !found {
				panic("no verification case " + name)
			}
			step := spendingStep{Case: name, Accepted: c.GoValid, Reason: c.GoReason}
			if c.GoValid {
				a, _ := ReadAssertion([]byte(c.AssertionJSON))
				key := a.Audience + "|" + a.Nonce + "|" + a.I
				if spent[key] {
					step.Accepted, step.Reason = false, "assertion already used"
				}
				spent[key] = true
			}
			seq.Steps = append(seq.Steps, step)
		}
		out = append(out, seq)
	}
	return out
}

func TestThePublishedVerifyDecisionsAreTheCores(t *testing.T) {
	committed, readErr := os.ReadFile(verifyDecisionsPath)
	if errors.Is(readErr, fs.ErrNotExist) {
		if _, derr := os.Stat(filepath.Join("..", "..", "packages", "login-verify")); errors.Is(derr, fs.ErrNotExist) {
			t.Skip("the TypeScript login verifier is not beside this module here")
		}
	}
	cases := verificationCases(t)
	file := verifyDecisionFile{
		Description: "Produced by the Go core: the decisions a login verifier makes, each from a document signed " +
			"here and a clock and a key fixed here. The TypeScript verifier must make every one alike, reason " +
			"for reason. Regenerated and checked by TestThePublishedVerifyDecisionsAreTheCores in " +
			"identity-agent-core/login.",
		FreshnessWindows:  windowCases(),
		BrowserKeys:       thumbprintCases(),
		P256Thumbprints:   p256Cases(),
		Verifications:     cases,
		SpendingSequences: spendingSequences(cases),
		SpendingRule:      vdSpendingRule,
	}
	out, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')

	if contractcheck.Writing(t) {
		if err := os.WriteFile(verifyDecisionsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if readErr != nil || !bytes.Equal(out, committed) {
		t.Fatalf("the login verifier's decisions are not what this core decides (read error: %v). "+
			"If the core changed on purpose, regenerate them (IA_WRITE_CONTRACTS=1) and make the same "+
			"change in packages/login-verify.", readErr)
	}
}
