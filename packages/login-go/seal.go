package login

// Sealed front-end traffic (ADR-072 section 2 step 5, Amendment 4): the Go half
// of packages/login-web/src/seal.ts, held to the same cases by
// packages/login-web/test-vectors/seal.json.
//
// A utility app's front end reaches the app's back end through a relay that is
// not trusted. Every call is ONE outer POST to one fixed path whose body is
//
//	{"v":1,"epk":<65-byte P-256 point, base64url>,"ct":<base64url>}
//
// and every answer is one 200 whose body is {"v":1,"n":<16 to 32 bytes>,"ct":<base64url>}. What the
// call and the answer are (method, target, headers, status, body) is inside
// ct, so the relay reads none of it.
//
// The front end makes a fresh P-256 key for each call and agrees a secret with
// the back end's sealing key (ECDH). Four values come from that secret with
// HKDF-SHA256, salted by epk||sealing key and told apart by their info: the
// request's key and nonce, and the answer's key and nonce. The request's is
// used once only because the back end refuses an epk it has seen. The answer
// never relies on that: the back end adds 32 random bytes of its own (n) to the
// answer's salt and carries them in the answer, so two answers to one call
// (a replay, or a restart that forgot) never share an AES-GCM key and nonce.
// Both directions are AES-256-GCM, with the version, the relay identifier, the
// direction and epk (and, for an answer, n) as associated data, so neither can
// be taken for the other, nor for another app's, nor relabelled by a later version.
//
// Every base64url value is read strictly (the one canonical spelling, no
// padding, no line breaks) and every field name is case-sensitive, so one call
// has one spelling and a replay memory keyed on the bytes sees it. The plaintext is its length (4 bytes, big-endian), the content, then
// zeros up to a bucket size, so the relay sees only which bucket a message is
// in (SealBucket).
//
// The signatures a call and an answer carry (the browser's proof, the app's
// signed answer) are part of the content and are checked after it is opened.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strconv"
)

const (
	// SealPath is the one path a sealed call is POSTed to.
	SealPath = "/sealed"
	// SealVersion is the envelope's version.
	SealVersion = 1
	// SealBucket is the smallest a sealed plaintext is; larger ones double.
	SealBucket = 1024
	// SealMax is the most content one sealed message may carry.
	SealMax = 16 << 20

	sealKeyLabel = "APP-SEAL-KEY-V1"
	sealLabel    = "APP-SEAL-V1"
)

// ErrSealed is every refusal of a sealed message. It says nothing about why, so
// what a relay tries tells it nothing.
var ErrSealed = errors.New("the sealed message is not accepted")

type outerRequest struct {
	V   int    `json:"v"`
	Epk string `json:"epk"`
	Ct  string `json:"ct"`
}

type outerAnswer struct {
	V  int    `json:"v"`
	N  string `json:"n"`
	Ct string `json:"ct"`
}

var b64 = base64.RawURLEncoding

// unb64 reads base64url in its one canonical spelling: Go's decoder alone
// accepts unused trailing bits and ignores line breaks, so the text must
// be what the bytes encode to.
func unb64(s string) ([]byte, error) {
	b, err := b64.Strict().DecodeString(s)
	if err != nil || b64.EncodeToString(b) != s {
		return nil, ErrSealed
	}
	return b, nil
}

// answerNonceMin and answerNonceMax bound n, the back end's own random value in an answer.
const (
	answerNonceMin = 16
	answerNonceMax = 32
)

// SealKey is the back end's sealing key: the one a front end seals its calls to.
// It is made from the relay identifier's seed, so it needs no keeping of its own.
type SealKey struct{ priv *ecdh.PrivateKey }

// SealKeyFromSeed makes the sealing key of the relay identifier whose signing
// seed this is. The first counter whose 32 bytes are a valid P-256 scalar is used.
func SealKeyFromSeed(seed []byte) (*SealKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("a seed is 32 bytes")
	}
	for ctr := byte(0); ctr < 8; ctr++ {
		okm, err := hkdf.Key(sha256.New, seed, nil, sealKeyLabel+string([]byte{ctr}), 32)
		if err != nil {
			return nil, err
		}
		if k, err := ecdh.P256().NewPrivateKey(okm); err == nil {
			return &SealKey{k}, nil
		}
	}
	return nil, errors.New("no sealing key could be made from this seed")
}

// Public is the sealing key's public half, 65 bytes (uncompressed).
func (k *SealKey) Public() []byte { return k.priv.PublicKey().Bytes() }

// SealKeyStatementText is what the relay identifier's key signs to vouch for a
// sealing key: the identifier, then the key.
func SealKeyStatementText(rid string, pub []byte) []byte {
	return []byte(sealKeyLabel + "\n" + rid + "\n" + b64.EncodeToString(pub))
}

// SealKeyStatement is what a sign-in link carries (`seal`): the relay
// identifier's inception, the sealing key, and the identifier's signature over
// SealKeyStatementText. `inception` is the event as the identifier is the
// digest of it, and `sign` signs with the identifier's key.
func SealKeyStatement(inception []byte, k *SealKey, rid string, sign func([]byte) ([]byte, error)) (string, error) {
	sig, err := sign(SealKeyStatementText(rid, k.Public()))
	if err != nil {
		return "", err
	}
	j, err := json.Marshal(map[string]string{"inception": b64.EncodeToString(inception), "key": b64.EncodeToString(k.Public()), "sig": b64.EncodeToString(sig)})
	if err != nil {
		return "", err
	}
	return b64.EncodeToString(j), nil
}

// Reply is what one sealed call leaves behind to seal or open its answer with.
type Reply struct {
	secret, epk, spk []byte
	rid              string
}

// Ephemeral is the call's epk as its decoded bytes: what a back end keeps to
// refuse a call it has seen, whatever the call's spelling.
func (r *Reply) Ephemeral() string { return string(r.epk) }

// derive makes a direction's key and nonce from the agreed secret. `n` is the
// back end's own random value in an answer, and nil in a request.
func derive(secret, epk, spk, n []byte, rid, dir string) (key, nonce []byte, err error) {
	salt := append(append(append([]byte{}, epk...), spk...), n...)
	if key, err = hkdf.Key(sha256.New, secret, salt, sealLabel+" "+dir+" key\n"+rid, 32); err != nil {
		return nil, nil, err
	}
	nonce, err = hkdf.Key(sha256.New, secret, salt, sealLabel+" "+dir+" nonce\n"+rid, 12)
	return key, nonce, err
}

// aadFor is the associated data: the label, the relay identifier, the direction,
// the version and epk, and for an answer n too.
func aadFor(rid, dir string, epk, n []byte) []byte {
	a := sealLabel + "\n" + rid + "\n" + dir + "\n" + strconv.Itoa(SealVersion) + "\n" + b64.EncodeToString(epk)
	if n != nil {
		a += "\n" + b64.EncodeToString(n)
	}
	return []byte(a)
}

// pad is the length, the content and zeros to the bucket.
func pad(content []byte) ([]byte, error) {
	if len(content) > SealMax {
		return nil, ErrSealed
	}
	n := SealBucket
	for n < len(content)+4 {
		n *= 2
	}
	out := make([]byte, n)
	binary.BigEndian.PutUint32(out, uint32(len(content)))
	copy(out[4:], content)
	return out, nil
}

func unpad(p []byte) ([]byte, error) {
	if len(p) < 4 {
		return nil, ErrSealed
	}
	n := int(binary.BigEndian.Uint32(p))
	if n > len(p)-4 || n > SealMax {
		return nil, ErrSealed
	}
	// The padding is zeros and the size is the bucket the content needs, so a
	// message that is neither was not made by an honest sealer.
	want := SealBucket
	for want < n+4 {
		want *= 2
	}
	if len(p) != want {
		return nil, ErrSealed
	}
	for _, b := range p[4+n:] {
		if b != 0 {
			return nil, ErrSealed
		}
	}
	return p[4 : 4+n], nil
}

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func sealWith(key, nonce, aad, content []byte) ([]byte, error) {
	p, err := pad(content)
	if err != nil {
		return nil, err
	}
	a, err := gcm(key)
	if err != nil {
		return nil, err
	}
	return a.Seal(nil, nonce, p, aad), nil
}

func openWith(key, nonce, aad, ct []byte) ([]byte, error) {
	a, err := gcm(key)
	if err != nil {
		return nil, ErrSealed
	}
	p, err := a.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, ErrSealed
	}
	return unpad(p)
}

// SealRequest seals `content` (a call) for the back end whose sealing key is `spk`, as
// the relay identifier `rid`, and returns the outer body to POST to SealPath
// with the Reply that opens its answer.
func SealRequest(rid string, spk, content []byte) (outer []byte, reply *Reply, err error) {
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return sealRequestWith(eph, rid, spk, content)
}

func sealRequestWith(eph *ecdh.PrivateKey, rid string, spk, content []byte) ([]byte, *Reply, error) {
	pub, err := ecdh.P256().NewPublicKey(spk)
	if err != nil {
		return nil, nil, ErrSealed
	}
	secret, err := eph.ECDH(pub)
	if err != nil {
		return nil, nil, ErrSealed
	}
	epk := eph.PublicKey().Bytes()
	rk, rn, err := derive(secret, epk, spk, nil, rid, "request")
	if err != nil {
		return nil, nil, err
	}
	ct, err := sealWith(rk, rn, aadFor(rid, "request", epk, nil), content)
	if err != nil {
		return nil, nil, err
	}
	out, err := json.Marshal(outerRequest{V: SealVersion, Epk: b64.EncodeToString(epk), Ct: b64.EncodeToString(ct)})
	return out, &Reply{secret, epk, spk, rid}, err
}

// OpenRequest opens a sealed call made to this key as the relay identifier
// `rid`. It returns the content and the Reply that seals its answer. Every
// failure is ErrSealed.
func (k *SealKey) OpenRequest(rid string, outer []byte) ([]byte, *Reply, error) {
	f, err := fields(outer, "v", "epk", "ct")
	if err != nil || !isVersion(f["v"]) {
		return nil, nil, ErrSealed
	}
	epkB, err1 := unb64(textField(f["epk"]))
	ctB, err2 := unb64(textField(f["ct"]))
	if err1 != nil || err2 != nil {
		return nil, nil, ErrSealed
	}
	pub, err := ecdh.P256().NewPublicKey(epkB)
	if err != nil {
		return nil, nil, ErrSealed
	}
	secret, err := k.priv.ECDH(pub)
	if err != nil {
		return nil, nil, ErrSealed
	}
	spk := k.Public()
	rk, rn, err := derive(secret, epkB, spk, nil, rid, "request")
	if err != nil {
		return nil, nil, ErrSealed
	}
	content, err := openWith(rk, rn, aadFor(rid, "request", epkB, nil), ctB)
	if err != nil {
		return nil, nil, ErrSealed
	}
	return content, &Reply{secret, epkB, spk, rid}, nil
}

// Seal seals the answer's content for the front end that made the call. The
// back end's own random n is made here, for every answer.
func (r *Reply) Seal(content []byte) ([]byte, error) {
	n := make([]byte, answerNonceMax)
	if _, err := rand.Read(n); err != nil {
		return nil, err
	}
	return r.sealWithN(n, content)
}

func (r *Reply) sealWithN(n, content []byte) ([]byte, error) {
	if len(n) < answerNonceMin || len(n) > answerNonceMax {
		return nil, ErrSealed
	}
	key, nonce, err := derive(r.secret, r.epk, r.spk, n, r.rid, "answer")
	if err != nil {
		return nil, err
	}
	ct, err := sealWith(key, nonce, aadFor(r.rid, "answer", r.epk, n), content)
	if err != nil {
		return nil, err
	}
	return json.Marshal(outerAnswer{V: SealVersion, N: b64.EncodeToString(n), Ct: b64.EncodeToString(ct)})
}

// Open opens a sealed answer to the call this Reply came from.
func (r *Reply) Open(outer []byte) ([]byte, error) {
	f, err := fields(outer, "v", "n", "ct")
	if err != nil || !isVersion(f["v"]) {
		return nil, ErrSealed
	}
	n, err1 := unb64(textField(f["n"]))
	ct, err2 := unb64(textField(f["ct"]))
	if err1 != nil || err2 != nil || len(n) < answerNonceMin || len(n) > answerNonceMax {
		return nil, ErrSealed
	}
	key, nonce, err := derive(r.secret, r.epk, r.spk, n, r.rid, "answer")
	if err != nil {
		return nil, ErrSealed
	}
	return openWith(key, nonce, aadFor(r.rid, "answer", r.epk, n), ct)
}

// fields reads a JSON object that has exactly the named fields, spelled exactly
// (Go's own decoder matches names without regard to case, which the page's
// and the Dart port's do not), and nothing after it.
func fields(b []byte, names ...string) (map[string]json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil || len(m) != len(names) {
		return nil, ErrSealed
	}
	for _, n := range names {
		if _, ok := m[n]; !ok {
			return nil, ErrSealed
		}
	}
	return m, nil
}

func isVersion(raw json.RawMessage) bool { return string(raw) == strconv.Itoa(SealVersion) }

// textField is a JSON string's value, or a string no base64url text can equal.
func textField(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "\x00"
	}
	return s
}
