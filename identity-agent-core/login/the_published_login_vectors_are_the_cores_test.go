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

	"identity-agent-core/iacrypto"
	"identity-agent-core/internal/contractcheck"
)

// The TypeScript login verifier is held to a vector file that says it was
// produced by this core: canonical bodies and digests, which key and signature
// spellings are read, and a signed assertion. Nothing would keep that claim
// true on its own, so this test recomputes every decision in the file with the
// core's own canonicaliser and decoders and requires the result to be the file,
// byte for byte. A change to how the core reads a login fails here, before the
// verifier a relying party runs quietly disagrees with it.
//
// When the core changes on purpose, regenerate the file with
// IA_WRITE_CONTRACTS=1 go test ./login -run TestThePublishedLoginVectorsAreTheCores
// and review the diff: every changed decision is one the TypeScript package
// has to make too.
var loginVectorsPath = filepath.Join("..", "..", "packages", "login-verify", "test-vectors",
	"core-canonical-and-spellings.json")

// The fields are in the order the file has them; the file is written with
// encoding/json and compared as bytes.
type loginVectorFile struct {
	CanonicalAssertions []canonicalCase `json:"canonical_assertions"`
	CanonicalChallenges []canonicalCase `json:"canonical_challenges"`
	Description         string          `json:"description"`
	NonTransferableAID  []spellingCase  `json:"non_transferable_aid"`
	SignedAssertion     signedAssertion `json:"signed_assertion"`
	VerkeyQB64          []spellingCase  `json:"verkey_qb64"`
}

// A document, and what the core makes of it: whether it reads it at all, and
// if so the canonical body it signs and, for an assertion, its digest.
type canonicalCase struct {
	Name          string `json:"name"`
	JSON          string `json:"json"`
	GoReads       bool   `json:"go_reads"`
	CanonicalBody string `json:"canonical_body,omitempty"`
	Said          string `json:"said,omitempty"`
}

// A spelling of a key or an identifier, whether the core reads it, and the
// bytes it reads.
type spellingCase struct {
	Name      string `json:"name"`
	Value     string `json:"value"`
	GoAccepts bool   `json:"go_accepts"`
	RawHex    string `json:"raw_hex,omitempty"`
}

type signatureCase struct {
	Name      string `json:"name"`
	Sig       string `json:"sig"`
	GoAccepts bool   `json:"go_accepts"`
}

// An assertion signed by the key made from seed_hex, and spellings of its
// signature. Each spelling is made from the canonical signature by the recipe
// its name gives (signatureSpellings), so a regenerated signature carries its
// spellings with it.
type signedAssertion struct {
	AssertionJSON string          `json:"assertion_json"`
	CanonicalBody string          `json:"canonical_body"`
	PublicKeyHex  string          `json:"public_key_hex"`
	Said          string          `json:"said"`
	SeedHex       string          `json:"seed_hex"`
	Signatures    []signatureCase `json:"signatures"`
	VerkeyQB64    string          `json:"verkey_qb64"`
}

func TestThePublishedLoginVectorsAreTheCores(t *testing.T) {
	committed, err := os.ReadFile(loginVectorsPath)
	if errors.Is(err, fs.ErrNotExist) {
		// The module is built on its own in places, without the packages beside
		// it. Only then is there nothing to check: where the package is present
		// and its vectors are not, they were moved or deleted, and that fails.
		if _, derr := os.Stat(filepath.Join("..", "..", "packages", "login-verify")); errors.Is(derr, fs.ErrNotExist) {
			t.Skip("the TypeScript login verifier is not beside this module here")
		}
	}
	if err != nil {
		t.Fatalf("the login verifier's vectors cannot be read: %v", err)
	}

	var file loginVectorFile
	dec := json.NewDecoder(bytes.NewReader(committed))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		t.Fatalf("the login verifier's vectors do not have the shape this test writes: %v", err)
	}
	if len(file.CanonicalAssertions) == 0 || len(file.CanonicalChallenges) == 0 || len(file.VerkeyQB64) == 0 ||
		len(file.NonTransferableAID) == 0 || len(file.SignedAssertion.Signatures) == 0 {
		t.Fatal("the login verifier's vectors are missing a section")
	}

	recomputed, err := recomputeLoginVectors(file)
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.MarshalIndent(recomputed, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')

	if contractcheck.Writing(t) {
		if err := os.WriteFile(loginVectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	if !bytes.Equal(out, committed) {
		t.Fatalf("the login verifier's vectors are not what this core decides:\n%s\n"+
			"If the core changed on purpose, regenerate them (IA_WRITE_CONTRACTS=1) and make the "+
			"same change in packages/login-verify.", describeLoginVectorDrift(file, recomputed))
	}
}

// recomputeLoginVectors keeps every input in file and replaces every decision
// with the one this core makes.
func recomputeLoginVectors(file loginVectorFile) (loginVectorFile, error) {
	out := file
	out.Description = "Produced by the Go core: canonical bodies, accept/refuse decisions for key and " +
		"signature spellings, and a signed assertion. The TypeScript verifier must agree byte for byte. " +
		"Regenerated and checked by TestThePublishedLoginVectorsAreTheCores in identity-agent-core/login."

	out.CanonicalAssertions = make([]canonicalCase, len(file.CanonicalAssertions))
	for i, c := range file.CanonicalAssertions {
		out.CanonicalAssertions[i] = canonicalCase{Name: c.Name, JSON: c.JSON}
		var a Assertion
		if json.Unmarshal([]byte(c.JSON), &a) != nil {
			continue
		}
		said, err := assertionDigest(a)
		if err != nil {
			return out, fmt.Errorf("assertion %q: %w", c.Name, err)
		}
		out.CanonicalAssertions[i].GoReads = true
		out.CanonicalAssertions[i].CanonicalBody = canonicalAssertionBody(a)
		out.CanonicalAssertions[i].Said = said
	}

	out.CanonicalChallenges = make([]canonicalCase, len(file.CanonicalChallenges))
	for i, c := range file.CanonicalChallenges {
		out.CanonicalChallenges[i] = canonicalCase{Name: c.Name, JSON: c.JSON}
		var b ChallengeBundle
		if json.Unmarshal([]byte(c.JSON), &b) != nil {
			continue
		}
		out.CanonicalChallenges[i].GoReads = true
		out.CanonicalChallenges[i].CanonicalBody = canonicalChallengeBody(b)
	}

	// A key a login names is a transferable Ed25519 key; a site that never
	// rotates is named by a non-transferable identifier. Each is read the one
	// way the core reads it.
	out.VerkeyQB64 = decideSpellings(file.VerkeyQB64, iacrypto.KeyFromVerkeyQB64)
	out.NonTransferableAID = decideSpellings(file.NonTransferableAID, iacrypto.KeyFromNonTransferableAID)

	s, err := recomputeSignedAssertion(file.SignedAssertion)
	if err != nil {
		return out, err
	}
	out.SignedAssertion = s
	return out, nil
}

func decideSpellings(cases []spellingCase, decode func(string) ([]byte, error)) []spellingCase {
	out := make([]spellingCase, len(cases))
	for i, c := range cases {
		out[i] = spellingCase{Name: c.Name, Value: c.Value}
		if raw, err := decode(c.Value); err == nil {
			out[i].GoAccepts = true
			out[i].RawHex = hex.EncodeToString(raw)
		}
	}
	return out
}

// recomputeSignedAssertion signs the assertion's canonical body with the key
// made from seed_hex, as an Identity Agent signs a login, and asks the core's
// verifier about every spelling of that signature.
func recomputeSignedAssertion(in signedAssertion) (signedAssertion, error) {
	seed, err := hex.DecodeString(in.SeedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		return in, fmt.Errorf("the signed assertion's seed is not %d bytes of hex", ed25519.SeedSize)
	}
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)

	var a Assertion
	if err := json.Unmarshal([]byte(in.AssertionJSON), &a); err != nil {
		return in, fmt.Errorf("the signed assertion is one the core does not read: %w", err)
	}
	a.Sig = ""
	if a.D, err = assertionDigest(a); err != nil {
		return in, err
	}
	body := canonicalAssertionBody(a)
	sig, err := SignString(body, seed)
	if err != nil {
		return in, err
	}
	a.Sig = sig
	signed, err := json.Marshal(a)
	if err != nil {
		return in, err
	}

	out := signedAssertion{
		AssertionJSON: string(signed),
		CanonicalBody: body,
		PublicKeyHex:  hex.EncodeToString(pub),
		Said:          a.D,
		SeedHex:       in.SeedHex,
		VerkeyQB64:    iacrypto.VerkeyQB64(pub),
	}
	for _, c := range in.Signatures {
		spelled, err := spellSignature(c.Name, sig)
		if err != nil {
			return in, err
		}
		ok, verr := VerifyString(body, spelled, pub)
		out.Signatures = append(out.Signatures, signatureCase{Name: c.Name, Sig: spelled, GoAccepts: verr == nil && ok})
	}
	return out, nil
}

const qb64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// spellSignature writes the canonical signature sig the way the named case
// spells it. The names are the file's; a case with a name not here is an
// error, so a spelling cannot be added to the file without saying how it is
// made.
func spellSignature(name, sig string) (string, error) {
	const variant = "lead bits set in the third character, variant "
	if strings.HasPrefix(name, variant) && len(name) == len(variant)+1 {
		// The third character carries the last 4 bits of the two lead bytes,
		// which are zero in the canonical spelling. Variant a sets them to 1,
		// b to 2, and so on to o at 15.
		k := int(name[len(variant)]) - 'a' + 1
		third := strings.IndexByte(qb64Alphabet, sig[2])
		if k < 1 || k > 15 || third < 0 {
			return "", fmt.Errorf("no signature spelling %q", name)
		}
		return sig[:2] + string(qb64Alphabet[k<<2|third&0b11]) + sig[3:], nil
	}
	last := byte('A')
	if sig[len(sig)-1] == 'A' {
		last = 'B'
	}
	switch name {
	case "canonical":
		return sig, nil
	case "a trailing character":
		return sig + "A", nil
	case "padding":
		return sig + "==", nil
	case "padding and junk":
		return sig + "=junk", nil
	case "the standard alphabet":
		return strings.NewReplacer("-", "+", "_", "/").Replace(sig), nil
	case "a character outside the alphabet":
		return sig[:40] + "." + sig[41:], nil
	case "an inserted newline":
		return sig[:40] + "\n" + sig[40:], nil
	case "another code":
		return "0C" + sig[2:], nil
	case "one character short":
		return sig[:len(sig)-1], nil
	case "the last character changed":
		return sig[:len(sig)-1] + string(last), nil
	}
	return "", fmt.Errorf("no signature spelling %q: say in spellSignature how it is made", name)
}

// describeLoginVectorDrift names each case whose decision differs, so a
// failure says what the core now does rather than only that the bytes moved.
func describeLoginVectorDrift(file, now loginVectorFile) string {
	var b strings.Builder
	canon := func(kind string, was, is []canonicalCase) {
		for i := range was {
			if i < len(is) && was[i] != is[i] {
				fmt.Fprintf(&b, "  %s %q: the file says reads=%v %s %s, the core reads=%v %s %s\n", kind, was[i].Name,
					was[i].GoReads, was[i].CanonicalBody, was[i].Said, is[i].GoReads, is[i].CanonicalBody, is[i].Said)
			}
		}
	}
	spell := func(kind string, was, is []spellingCase) {
		for i := range was {
			if i < len(is) && was[i] != is[i] {
				fmt.Fprintf(&b, "  %s %q: the file says accepted=%v %s, the core accepted=%v %s\n", kind, was[i].Name,
					was[i].GoAccepts, was[i].RawHex, is[i].GoAccepts, is[i].RawHex)
			}
		}
	}
	canon("assertion", file.CanonicalAssertions, now.CanonicalAssertions)
	canon("challenge", file.CanonicalChallenges, now.CanonicalChallenges)
	spell("key", file.VerkeyQB64, now.VerkeyQB64)
	spell("identifier", file.NonTransferableAID, now.NonTransferableAID)
	ws, ns := file.SignedAssertion, now.SignedAssertion
	for i := range ws.Signatures {
		if i < len(ns.Signatures) && ws.Signatures[i] != ns.Signatures[i] {
			fmt.Fprintf(&b, "  signature %q: the file says %q accepted=%v, the core %q accepted=%v\n", ws.Signatures[i].Name,
				ws.Signatures[i].Sig, ws.Signatures[i].GoAccepts, ns.Signatures[i].Sig, ns.Signatures[i].GoAccepts)
		}
	}
	ws.Signatures, ns.Signatures = nil, nil
	if fmt.Sprint(ws) != fmt.Sprint(ns) {
		fmt.Fprintf(&b, "  the signed assertion: the file has %+v, the core makes %+v\n", ws, ns)
	}
	if file.Description != now.Description {
		fmt.Fprintf(&b, "  the description: the file has %q\n", file.Description)
	}
	if b.Len() == 0 {
		return "  every decision agrees; the file differs only in how it is written"
	}
	return b.String()
}
