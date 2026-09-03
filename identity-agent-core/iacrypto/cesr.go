package iacrypto

import (
	"crypto/elliptic"
	"encoding/base64"
	"fmt"
)

const (
	CipherSuiteIAHybrid1 = "IA-HYBRID-1"

	// CESR codes for the keys an identity publishes.
	//
	// The table a primitive belongs in is not a choice — it follows from the
	// raw size modulo 3, because the encoding has to land on a 24-bit boundary.
	// Size 0 mod 3 takes the `1` table with no lead byte, 2 mod 3 takes `2`
	// with one, 1 mod 3 takes `3` with two. Every key here is 2 mod 3 except
	// the Ed25519 pair, so every one of them belongs in `2`.
	//
	// These were previously 1PXB / 1PKM / 1PDA — four-character codes in the
	// `1` table, encoded by gluing the code onto raw base64 with no lead byte.
	// That is correct only for a size divisible by three, so all three came out
	// one character short of a whole number of base64 quadruples.
	//
	// That fault is LATENT rather than active, and the distinction is worth
	// stating precisely because it is easy to overstate. A parser that does not
	// recognise a code cannot determine the value's length either, so today it
	// stops at the code and the length never matters. The damage arrives when
	// the code becomes KNOWN: a parser then reads exactly the declared size on
	// faith, so a value one character short consumes a character of whatever
	// follows it and the stream is corrupted from there. Measured against the
	// reference implementation with a known code — a correct-length value reads
	// cleanly and its neighbour is recovered, a short one fails with a shortage
	// error partway into the next value.
	//
	// So this is a bug that would activate at precisely the moment
	// interoperability starts working, which is the argument for fixing it
	// before then rather than after.

	// CESRX25519Pubkey is the ASSIGNED code for an X25519 public key. It is not
	// provisional and never should have been: `C` has been in the reference
	// implementation all along, and inventing a code for a key that already had
	// one was simply a miss.
	CESRX25519Pubkey = "C"

	// CESRMLDSA65Verkey is the code the specification's open pull request
	// PROPOSES for an ML-DSA-65 verification key. Unassigned until that merges.
	CESRMLDSA65Verkey = "2AAE"
	// CESRMLDSA65Sig is the proposed code for an ML-DSA-65 signature. Its raw
	// size is 3309, which is 0 mod 3, so it takes the `1` table.
	CESRMLDSA65Sig = "1AAT"

	// CESRMLKEM768Encap is ours, and unavoidably so: the specification has no
	// code for ML-KEM-768 and none is proposed — the pull request adding
	// post-quantum primitives covers signatures only and says a key
	// encapsulation mechanism is "left to a later version". A key counterparties
	// encrypt to has to be published somehow, so this stays provisional. What
	// has changed is that it is now correctly framed: 1184 is 2 mod 3, so it
	// takes the `2` table with one lead byte.
	CESRMLKEM768Encap    = "2PKM"
	MLDSA65VerkeyBytes   = 1952
	MLDSA65SigBytes      = 3309
	MLKEM768EncapBytes   = 1184
	X25519PubkeyBytes    = 32
	Ed25519PubkeyBytes   = 32
	Ed25519SigBytes      = 64
	CtrControllerIdxSigs = "-A"
	C2Message            = "m63-c2-hybrid-signature-golden-vector"
)

var (
	C2Ed25519Seed = func() []byte {
		out := make([]byte, 32)
		for i := range out {
			out[i] = byte((i + 0x21) % 256)
		}
		return out
	}()
	C2MLDSASeed = []byte("m63-c2-hybrid-signature-golden!!")
)

// keri Base64 index alphabet (matches keripy intToB64).
var b64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func intToB64(i int, length int) string {
	d := make([]byte, 0, length)
	for length > 0 && (len(d) < length || i > 0) {
		d = append([]byte{b64Chars[i%64]}, d...)
		i /= 64
	}
	for len(d) < length {
		d = append([]byte{'A'}, d...)
	}
	return string(d)
}

func b64ToInt(s string) int {
	n := 0
	for _, c := range s {
		n = n*64 + int(bytesIndexRune(b64Chars, c))
	}
	return n
}

func bytesIndexRune(s string, r rune) int {
	for i, c := range s {
		if c == r {
			return i
		}
	}
	return 0
}

// MatterFixedQB64 encodes fixed-size CESR material (keri 1.1.17 Matter._infil).
// rawSizeForCode is how many bytes each fixed-size code is defined to carry.
//
// Here so the encoder can refuse a length its code cannot mean. Absent it,
// MatterFixedQB64 padded whatever it was handed and prepended the code, so a
// 65-byte P-256 point under the Ed25519 code "B" produced a well-formed-looking
// 88-character identifier where the spec says 44 — no error, and a value every
// decoder then rejected as malformed while blaming whoever passed it on. An
// encoder that cannot say no is how a wrong key becomes a valid-looking name.
var rawSizeForCode = map[string]int{
	"A":    32, // Ed25519 seed
	"B":    32, // Ed25519 non-transferable identifier
	"D":    32, // Ed25519 verification key
	"E":    32, // Blake3-256 digest
	"0B":   64, // Ed25519 signature
	"0I":   64, // secp256r1 signature, raw r||s
	"1AAI": 33, // secp256r1 non-transferable identifier, compressed point
	"1AAJ": 33, // secp256r1 verification key, compressed point
}

func MatterFixedQB64(code string, raw []byte) (string, error) {
	if len(code) < 1 {
		return "", fmt.Errorf("matter code required")
	}
	// Checked before encoding, not after. A code names a size; a value of any
	// other size is not that thing, and saying so here is the only place it can
	// still be said cheaply.
	if want, known := rawSizeForCode[code]; known && len(raw) != want {
		return "", fmt.Errorf("code %q carries %d bytes, got %d", code, want, len(raw))
	}
	ps := (3 - (len(raw) % 3)) % 3
	cs := len(code)
	padded := make([]byte, ps+len(raw))
	copy(padded[ps:], raw)
	b64 := base64.RawURLEncoding.EncodeToString(padded)
	if cs%4 > len(b64) {
		return "", fmt.Errorf("invalid matter encoding for code %q", code)
	}
	return code + b64[cs%4:], nil
}

// EncodeLargeFixed encodes a fixed-size primitive under a CESR code.
//
// Delegates the framing to MatterFixedQB64 rather than concatenating the code
// with raw base64, which is what this used to do. That shortcut is correct only
// when the raw size divides by three; for anything else it omits the lead bytes
// the encoding requires and leaves a body that is not a whole number of base64
// quadruples. Every post-quantum key here is 2 mod 3, so all of them were
// affected — and a malformed primitive does not fail alone, because the CESR
// specification's remedy for a confused parser is a cold-start resynchronisation
// of the whole stream.
func EncodeLargeFixed(code string, raw []byte, expectedLen int) (string, error) {
	if code == "" {
		return "", fmt.Errorf("a CESR code is required")
	}
	if expectedLen > 0 && len(raw) != expectedLen {
		return "", fmt.Errorf("expected %d raw bytes for %s, got %d", expectedLen, code, len(raw))
	}
	return MatterFixedQB64(code, raw)
}

// NonTransferableAIDQB64 encodes a raw Ed25519 public key as a CESR
// non-transferable identifier (code "B").
//
// A non-transferable identifier IS its verifying key, so anyone holding the
// identifier can check a signature made under it without fetching anything —
// no key history, no address, no network. That is exactly what a witness needs
// to be: the point of a receipt is that a third party can check it, and a
// receipt whose key must first be looked up somewhere just moves the question
// to whoever answers the lookup.
//
// The trade is that such an identifier cannot rotate — its key is fixed for
// life. For a witness that is the correct trade, because a witness is a role
// something performs rather than a party with a history, and replacing the key
// means naming a different witness.
func NonTransferableAIDQB64(pub []byte) string {
	s, err := MatterFixedQB64("B", pub)
	if err != nil {
		return ""
	}
	return s
}

// KeyFromNonTransferableAID recovers the verifying key a non-transferable
// identifier is made of.
//
// The inverse of NonTransferableAIDQB64, kept beside it so the two cannot drift.
// This is the whole reason a witness is named this way: given the identifier
// written in a key event, a verifier holds the key already and checks a receipt
// without asking anybody anything.
func KeyFromNonTransferableAID(aid string) ([]byte, error) {
	const code = "B"
	if len(aid) != 44 || aid[:1] != code {
		return nil, fmt.Errorf("%q is not a non-transferable identifier", aid)
	}
	// One code character, so one leading pad character to realign to base64.
	raw, err := base64.RawURLEncoding.DecodeString("A" + aid[1:])
	if err != nil {
		return nil, fmt.Errorf("identifier is not valid base64url: %w", err)
	}
	if len(raw) != 33 {
		return nil, fmt.Errorf("expected 32 key bytes, got %d", len(raw)-1)
	}
	return raw[1:], nil
}

// KeyFromVerkeyQB64 recovers the raw Ed25519 key from a CESR verfer (code "D").
//
// The inverse of VerkeyQB64. Separate from DecodeLargeFixed because the two
// encodings differ in more than the code: a 1-character code pads by one byte
// and replaces one leading character, where the 4-character provisional codes
// are a straight prefix. Decoding one with the other's rules yields bytes that
// are wrong rather than an error, which is the failure worth designing out.
func KeyFromVerkeyQB64(qb64 string) ([]byte, error) {
	const code = "D"
	if len(qb64) != 44 || qb64[:1] != code {
		return nil, fmt.Errorf("%q is not a CESR Ed25519 verifying key", qb64)
	}
	raw, err := base64.RawURLEncoding.DecodeString("A" + qb64[1:])
	if err != nil {
		return nil, fmt.Errorf("verifying key is not valid base64url: %w", err)
	}
	if len(raw) != 33 {
		return nil, fmt.Errorf("expected 32 key bytes, got %d", len(raw)-1)
	}
	return raw[1:], nil
}

// VerkeyQB64 encodes a raw Ed25519 public key as a CESR qb64 verfer (code "D"). Use this for
// keys passed to the KERI driver's inception endpoints: the driver's _extract_raw_key reads a
// leading "B"/"D" as a CESR code, so a raw base64 key that happens to start with B/D is
// misparsed. qb64 is unambiguous. Falls back to empty string only on an impossible encode error.
func VerkeyQB64(pub []byte) string {
	s, err := MatterFixedQB64("D", pub)
	if err != nil {
		return ""
	}
	return s
}

// A MACHINE'S KEY IS secp256r1, AND ONLY A MACHINE'S.
//
// Every secure element a desktop actually has does NIST P-256 and nothing else:
// Apple's Secure Enclave, the Microsoft Platform Crypto Provider, and TPM 2.0.
// No shipping TPM implements Ed25519 and the TCG registry defines no Edwards
// curve at all, so a machine key that insists on Ed25519 is a key no hardware
// can hold — which is how three platforms ended up with signers hardcoded to
// refuse.
//
// So machines move to P-256 and everything else stays where it is. People,
// organisations and instances remain Ed25519; this is the machine's own key,
// used to say "this is me" and to sign its own requests, and it is never an
// identity anybody founds anything on.
//
// The codes are keripy's, from the version this project pins, not invented
// here: ECDSA_256r1N is the non-transferable identifier and ECDSA_256r1 the
// verification key, both carrying a 33-byte compressed point.
const (
	// CodeP256N names a machine by its own key, the way "B" does for Ed25519.
	CodeP256N = "1AAI"
	// CodeP256 is the verification-key form, the way "D" is for Ed25519.
	CodeP256 = "1AAJ"
	// CodeP256Sig carries a signature as raw r||s, never DER.
	CodeP256Sig = "0I"
)

// CompressP256 turns an uncompressed X9.63 point into the 33-byte form CESR
// carries.
//
// Apple hands back 65 bytes — 0x04 then X then Y — because that is what
// SecKeyCopyExternalRepresentation produces. CESR's P-256 codes are sized for
// the compressed point, so this is not an optimisation but the encoding the
// code means. Y is recovered from its parity, which is what the leading 0x02 or
// 0x03 records.
func CompressP256(uncompressed []byte) ([]byte, error) {
	if len(uncompressed) == 33 && (uncompressed[0] == 0x02 || uncompressed[0] == 0x03) {
		return uncompressed, nil // already compressed
	}
	if len(uncompressed) != 65 || uncompressed[0] != 0x04 {
		return nil, fmt.Errorf("not an uncompressed P-256 point: %d bytes", len(uncompressed))
	}
	out := make([]byte, 33)
	// Odd or even Y decides the prefix; X is carried whole.
	out[0] = 0x02 | (uncompressed[64] & 1)
	copy(out[1:], uncompressed[1:33])
	return out, nil
}

// MachineAIDQB64 names a machine by its P-256 key.
func MachineAIDQB64(pub []byte) (string, error) {
	c, err := CompressP256(pub)
	if err != nil {
		return "", err
	}
	return MatterFixedQB64(CodeP256N, c)
}

// MachineVerkeyQB64 is the same key in verification-key form.
func MachineVerkeyQB64(pub []byte) (string, error) {
	c, err := CompressP256(pub)
	if err != nil {
		return "", err
	}
	return MatterFixedQB64(CodeP256, c)
}

// KeyFromMachineAID recovers the compressed point a machine identifier is made
// of, and refuses anything that is not one.
//
// Kept beside the encoder for the reason its Ed25519 counterpart is: the two
// have to agree, and the way they stop agreeing is being edited apart.
func KeyFromMachineAID(aid string) ([]byte, error) {
	if len(aid) != 48 || aid[:4] != CodeP256N {
		return nil, fmt.Errorf("%q is not a machine identifier", aid)
	}
	raw, err := base64.RawURLEncoding.DecodeString(aid[4:])
	if err != nil {
		return nil, fmt.Errorf("machine identifier is not valid base64url: %w", err)
	}
	if len(raw) != 33 {
		return nil, fmt.Errorf("expected a 33-byte compressed point, got %d", len(raw))
	}
	// VALIDATED, NOT MERELY MEASURED. A 33-byte value of the right length whose
	// prefix is not 0x02 or 0x03 is not a point on the curve, and letting it
	// through means it is classified as neither a P-256 key nor an Ed25519 one
	// later — where the Ed25519 verifier panics on a 33-byte key rather than
	// returning false. So a grant carrying such a pair could be stored and then
	// take down every request made against it.
	if x, _ := elliptic.UnmarshalCompressed(elliptic.P256(), raw); x == nil {
		return nil, fmt.Errorf("that identifier does not name a point on P-256")
	}
	return raw, nil
}
