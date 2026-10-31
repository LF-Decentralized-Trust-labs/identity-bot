package iacrypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

// Every key and identifier has exactly one string per spelling. These make
// the other strings that decode to the same bytes, and check each is refused.

// setLeadBits writes k into the lead bits carried by the character after a
// one-character code: there are 2 of them. k = 0 is the canonical spelling.
func setLeadBits(qb64 string, k int) string {
	v := strings.IndexByte(b64Chars, qb64[1])
	v = v&0x0f | k<<4
	return qb64[:1] + string(b64Chars[v]) + qb64[2:]
}

func randomKey(t *testing.T) []byte {
	t.Helper()
	raw := make([]byte, Ed25519PubkeyBytes)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAQB64KeyWithLeadBitsSetIsRefused(t *testing.T) {
	for i := 0; i < 200; i++ {
		raw := randomKey(t)
		for _, canonical := range []string{VerkeyQB64(raw), NonTransferableAIDQB64(raw)} {
			for k := 1; k < 4; k++ {
				other := setLeadBits(canonical, k)
				if _, _, err := DecodeEd25519Key(other, false); err == nil {
					t.Fatalf("%s with lead bits %d read as the key %s names", other, k, canonical)
				}
				if canonical[0] == 'D' {
					if _, err := KeyFromVerkeyQB64(other); err == nil {
						t.Fatalf("KeyFromVerkeyQB64 read %s", other)
					}
				} else {
					if _, err := KeyFromNonTransferableAID(other); err == nil {
						t.Fatalf("KeyFromNonTransferableAID read the witness identifier %s", other)
					}
				}
				if IsIdentifierQB64(other) {
					t.Fatalf("%s was taken for an identifier", other)
				}
			}
		}
	}
}

func TestAQB64KeyOfTheWrongShapeIsRefused(t *testing.T) {
	raw := randomKey(t)
	aid := NonTransferableAIDQB64(raw)
	for name, s := range map[string]string{
		"one short":              aid[:43],
		"one long":               aid + "A",
		"four long":              aid + "AAAA",
		"padded":                 aid[:43] + "=",
		"line break inside":      aid[:20] + "\n" + aid[20:],
		"line break at the end":  aid + "\n",
		"standard alphabet":      aid[:43] + "+",
		"transferable code":      "D" + aid[1:],
		"a digest's code":        "E" + aid[1:],
		"nothing after the code": "B",
	} {
		if _, err := KeyFromNonTransferableAID(s); err == nil {
			t.Errorf("%s: %q was read as a witness identifier", name, s)
		}
	}
}

// A raw key in base64 has 2 bits over in its last character. Each spelling
// reads in exactly one string.
func TestARawKeyHasOneStringPerSpelling(t *testing.T) {
	raw := randomKey(t)
	for _, enc := range base64Spellings {
		s := enc.EncodeToString(raw)
		if got, _, err := DecodeEd25519Key(s, false); err != nil || !bytes.Equal(got, raw) {
			t.Fatalf("%s did not read back: %v", s, err)
		}
		last := strings.TrimRight(s, "=")
		i := len(last) - 1
		alphabet := b64Chars
		if enc == base64.StdEncoding || enc == base64.RawStdEncoding {
			alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
		}
		v := strings.IndexByte(alphabet, last[i])
		for spare := 1; spare < 4; spare++ {
			other := last[:i] + string(alphabet[v&^3|spare]) + s[len(last):]
			if _, _, err := DecodeEd25519Key(other, false); err == nil {
				t.Errorf("%s, with spare bits %d, read as the same key", other, spare)
			}
		}
		if _, _, err := DecodeEd25519Key(s[:10]+"\n"+s[10:], false); err == nil {
			t.Errorf("a line break inside %s was skipped", s)
		}
	}
}

// Hex is read in lowercase, the case it is written in, and only that.
func TestHexIsReadInOneCase(t *testing.T) {
	raw := randomKey(t)
	raw[0] = 0xab // at least one letter
	h := hex.EncodeToString(raw)
	if got, _, err := DecodeEd25519Key(h, true); err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("lowercase hex did not read: %v", err)
	}
	if _, _, err := DecodeEd25519Key(strings.ToUpper(h), true); err == nil {
		t.Error("uppercase hex was read as the same key")
	}
}

func TestAMachineIdentifierHasOneSpelling(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := priv.PublicKey.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	aid, err := MachineAIDQB64(pub.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := KeyFromMachineAID(aid); err != nil {
		t.Fatalf("the canonical machine identifier did not read: %v", err)
	}
	for name, s := range map[string]string{
		"one long":    aid + "A",
		"line break":  aid[:10] + "\n" + aid[10:],
		"padded":      aid[:47] + "=",
		"wrong table": "1AAJ" + aid[4:],
	} {
		if _, err := KeyFromMachineAID(s); err == nil {
			t.Errorf("%s: %q was read as a machine identifier", name, s)
		}
	}
}

// The post-quantum and agreement keys an identifier anchors were read by
// taking the last bytes of whatever decoded, so a longer string read too.
func TestAnAnchoredKeyIsReadAtExactlyItsLength(t *testing.T) {
	raw := randomKey(t)
	q, err := EncodeLargeFixed(CESRX25519Pubkey, raw, X25519PubkeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeLargeFixed(CESRX25519Pubkey, q, X25519PubkeyBytes); err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("the canonical key did not read: %v", err)
	}
	for name, s := range map[string]string{
		"four long":     q + "AAAA",
		"lead bits set": setLeadBits(q, 1),
		"line break":    q[:10] + "\n" + q[10:],
	} {
		if _, err := DecodeLargeFixed(CESRX25519Pubkey, s, X25519PubkeyBytes); err == nil {
			t.Errorf("%s: %q was read as the anchored key", name, s)
		}
	}

	kem := make([]byte, MLKEM768EncapBytes)
	rand.Read(kem)
	qk, err := EncodeLargeFixed(CESRMLKEM768Encap, kem, MLKEM768EncapBytes)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := DecodeLargeFixed(CESRMLKEM768Encap, qk, MLKEM768EncapBytes); err != nil || !bytes.Equal(got, kem) {
		t.Fatalf("the canonical encapsulation key did not read: %v", err)
	}
	// A four-character code here, so the lead byte is written out in full
	// after it, in the first character and two bits of the second.
	body := []byte(qk)
	body[4] = 'B'
	if _, err := DecodeLargeFixed(CESRMLKEM768Encap, string(body), MLKEM768EncapBytes); err == nil {
		t.Error("an encapsulation key with a non-zero lead byte was read")
	}
	if _, err := DecodeLargeFixed(CESRMLKEM768Encap, qk+"AAAA", MLKEM768EncapBytes); err == nil {
		t.Error("an encapsulation key four characters long was read")
	}
}

func TestOnlyBase64URLIsReadWhereTheFormatSaysSo(t *testing.T) {
	raw := randomKey(t)
	s := base64.RawURLEncoding.EncodeToString(raw)
	if got, err := DecodeBase64URLSized(s, len(raw)); err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("base64url did not read: %v", err)
	}
	for name, other := range map[string]string{
		"padded":     base64.URLEncoding.EncodeToString(raw),
		"standard":   base64.RawStdEncoding.EncodeToString(raw),
		"line break": s[:10] + "\n" + s[10:],
		"spare bits": s[:42] + string(b64Chars[strings.IndexByte(b64Chars, s[42])|1]),
	} {
		if other == s {
			continue // a standard spelling with no + or / is the same string
		}
		if _, err := DecodeBase64URLSized(other, len(raw)); err == nil {
			t.Errorf("%s: %q was read", name, other)
		}
	}
}

func TestACountHasOneSpelling(t *testing.T) {
	for in, want := range map[string]int{"0": 0, "1": 1, "a": 10, "ff": 255, "7fffffff": 1<<31 - 1} {
		if got, err := ParseHexCount(in); err != nil || got != want {
			t.Errorf("%q read as %d (%v), want %d", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "A", "0a", "00", "2zz", "-1", "+1", "0x1", "80000000", " 1"} {
		if n, err := ParseHexCount(bad); err == nil {
			t.Errorf("%q read as %d", bad, n)
		}
	}
}

func TestHexIsReadInLowercaseOnly(t *testing.T) {
	if got, err := DecodeHex("00ab"); err != nil || !bytes.Equal(got, []byte{0, 0xab}) {
		t.Fatalf("lowercase hex: %x %v", got, err)
	}
	for _, bad := range []string{"00AB", "00aB", "0g"} {
		if _, err := DecodeHex(bad); err == nil {
			t.Errorf("%q was read", bad)
		}
	}
}
