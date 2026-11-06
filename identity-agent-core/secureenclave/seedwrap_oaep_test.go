package secureenclave

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// oaepDecryptSHA256MGF1SHA1 is the decoding half, standing in for the hardware in
// tests (the Keystore does this inside the secure element).
func oaepDecryptSHA256MGF1SHA1(priv *rsa.PrivateKey, ct []byte) ([]byte, error) {
	k := (priv.N.BitLen() + 7) / 8
	if len(ct) != k {
		return nil, errors.New("decryption error")
	}
	m := new(big.Int).Exp(new(big.Int).SetBytes(ct), priv.D, priv.N)
	em := m.FillBytes(make([]byte, k))
	seed, db := em[1:1+oaepHashLen], em[1+oaepHashLen:]
	xorInto(seed, mgf1SHA1(db, oaepHashLen))
	xorInto(db, mgf1SHA1(seed, len(db)))
	lHash := sha256.Sum256(nil)
	if em[0] != 0 || !bytes.Equal(db[:oaepHashLen], lHash[:]) {
		return nil, errors.New("decryption error")
	}
	rest := db[oaepHashLen:]
	i := bytes.IndexByte(rest, 1)
	if i < 0 || bytes.Count(rest[:i], []byte{0}) != i {
		return nil, errors.New("decryption error")
	}
	return rest[i+1:], nil
}

func testKeyFromTestdata(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "oaep", "key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(raw)
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return k.(*rsa.PrivateKey)
}

// A ciphertext OpenSSL made (rsa_oaep_md:sha256, rsa_mgf1_md:sha1) opens with
// this decoder: the padding is the standard one, not one of our own.
func TestOpenSSLsOAEPWithAShaOneMaskOpensHere(t *testing.T) {
	ct, err := os.ReadFile(filepath.Join("testdata", "oaep", "openssl.ct"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := oaepDecryptSHA256MGF1SHA1(testKeyFromTestdata(t), ct)
	if err != nil || string(got) != "a data key made elsewhere....." {
		t.Fatalf("%q %v", got, err)
	}
}

// What the core encrypts, OpenSSL opens. Skipped where there is no openssl.
func TestWhatTheCoreSealsOpenSSLOpens(t *testing.T) {
	ossl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("no openssl")
	}
	key := testKeyFromTestdata(t)
	msg := bytes.Repeat([]byte{0x5a}, 32)
	ct, err := oaepEncryptSHA256MGF1SHA1(&key.PublicKey, msg)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	in := filepath.Join(dir, "ct")
	os.WriteFile(in, ct, 0o600)
	out, err := exec.Command(ossl, "pkeyutl", "-decrypt", "-inkey", filepath.Join("testdata", "oaep", "key.pem"),
		"-in", in, "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256", "-pkeyopt", "rsa_mgf1_md:sha1").Output()
	if err != nil || !bytes.Equal(out, msg) {
		t.Fatalf("openssl could not open it: %v %x", err, out)
	}
}

func TestOAEPRoundTripsAndIsRandomised(t *testing.T) {
	key := softwareRSA(t)
	msg := bytes.Repeat([]byte{7}, 32)
	a, err := oaepEncryptSHA256MGF1SHA1(&key.PublicKey, msg)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := oaepEncryptSHA256MGF1SHA1(&key.PublicKey, msg)
	if bytes.Equal(a, b) || len(a) != 256 {
		t.Fatal("not randomised or wrong size")
	}
	if got, err := oaepDecryptSHA256MGF1SHA1(key, a); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("round trip: %v", err)
	}
	a[10] ^= 1
	if _, err := oaepDecryptSHA256MGF1SHA1(key, a); err == nil {
		t.Fatal("a flipped bit still decoded")
	}
	if _, err := oaepEncryptSHA256MGF1SHA1(&key.PublicKey, make([]byte, 191)); err == nil {
		t.Fatal("too long a message accepted")
	}
}
