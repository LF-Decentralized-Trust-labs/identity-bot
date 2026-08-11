package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"testing"

	"github.com/zeebo/blake3"
)

// Golden JCS vector — byte-pinned at build.
const goldenJCSInput = `{"b":2,"a":1,"nested":{"z":true,"y":null}}`
const goldenJCSOutput = `{"a":1,"b":2,"nested":{"y":null,"z":true}}`

func TestJCSGoldenVector(t *testing.T) {
	got, err := Canonicalize([]byte(goldenJCSInput))
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if string(got) != goldenJCSOutput {
		t.Fatalf("JCS golden mismatch\n got: %s\nwant: %s", got, goldenJCSOutput)
	}
}

func TestManifestSignatureGoldenVector(t *testing.T) {
	ta, priv, pub := TestTrustAnchor()

	artifactBytes := []byte("identity-agent-core-test-artifact-v1")
	blake := blake3.Sum256(artifactBytes)
	sha := sha256.Sum256(artifactBytes)

	unsigned := []byte(`{
  "manifest_version": 1,
  "published_at": "2026-06-15T00:00:00Z",
  "signing_key_id": "grape-release-test",
  "channels": {"stable": {"min_supported_manifest_version": 1}},
  "components": {
    "go_backend": {
      "version": "2.4.0",
      "minimum_version": "2.2.0",
      "critical": true,
      "artifacts": [{
        "platform": "darwin_arm64",
        "url": "https://releases.example.com/go_backend/2.4.0/darwin_arm64",
        "blake3_256": "` + hex.EncodeToString(blake[:]) + `",
        "sha256": "` + hex.EncodeToString(sha[:]) + `",
        "size_bytes": ` + strconv.Itoa(len(artifactBytes)) + `
      }]
    }
  },
  "compatibility": {"flutter_web": {"min_go_backend": "2.3.0", "max_go_backend": "2.5.x"}},
  "changelog": [{"version": "2.4.0", "date": "2026-06-15", "critical": true, "summary": "test", "entries": ["fix"]}],
  "signature": ""
}`)

	signed, err := SignManifestForTest(unsigned, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	canonical, err := CanonicalizeWithoutField(signed, "signature")
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	if len(canonical) == 0 {
		t.Fatal("empty canonical bytes")
	}

	m, err := VerifyManifest(signed, ta)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if m.Components["go_backend"].Version != "2.4.0" {
		t.Fatalf("unexpected version %s", m.Components["go_backend"].Version)
	}

	var tamperedObj map[string]interface{}
	if err := jsonUnmarshal(signed, &tamperedObj); err != nil {
		t.Fatalf("unmarshal signed: %v", err)
	}
	components := tamperedObj["components"].(map[string]interface{})
	goBackend := components["go_backend"].(map[string]interface{})
	goBackend["version"] = "9.9.9"
	tampered, err := jsonMarshal(tamperedObj)
	if err != nil {
		t.Fatalf("marshal tampered: %v", err)
	}
	if _, err := VerifyManifest(tampered, ta); err != ErrSignatureInvalid {
		t.Fatalf("expected signature_invalid, got %v", err)
	}

	badVersion := replaceJSONField(signed, "manifest_version", "2")
	if _, err := VerifyManifest(badVersion, ta); err != ErrUnknownManifestVersion {
		t.Fatalf("expected unknown_manifest_version, got %v", err)
	}

	wrongTA, _ := NewTrustAnchor(map[string][]byte{"other": pub})
	if _, err := VerifyManifest(signed, wrongTA); err != ErrUntrustedSigningKey {
		t.Fatalf("expected untrusted_signing_key, got %v", err)
	}

	if err := VerifyArtifactBytes(artifactBytes, m.Components["go_backend"].Artifacts[0], true); err != nil {
		t.Fatalf("artifact verify: %v", err)
	}
	bad := append([]byte(nil), artifactBytes...)
	bad[0] ^= 0xff
	if err := VerifyArtifactBytes(bad, m.Components["go_backend"].Artifacts[0], false); err != ErrChecksumMismatch {
		t.Fatalf("expected checksum_mismatch, got %v", err)
	}
}

func TestKeyTransitionGoldenVector(t *testing.T) {
	ta, priv, _ := TestTrustAnchor()
	newSeed := make([]byte, ed25519.SeedSize)
	for i := range newSeed {
		newSeed[i] = 0xAB
	}
	newPriv := ed25519.NewKeyFromSeed(newSeed)
	newPub := newPriv.Public().(ed25519.PublicKey)

	raw := []byte(`{
  "old_key_id": "grape-release-test",
  "new_key_id": "grape-release-2027",
  "new_public_key": "` + EncodeBase64URL(newPub) + `",
  "endorsed_at": "2027-01-01T00:00:00Z",
  "signature": ""
}`)
	signed, err := SignManifestForTest(raw, priv)
	if err != nil {
		t.Fatalf("sign transition: %v", err)
	}
	kt, err := VerifyKeyTransition(signed, ta)
	if err != nil {
		t.Fatalf("verify transition: %v", err)
	}
	if kt.NewKeyID != "grape-release-2027" {
		t.Fatalf("unexpected new key id %s", kt.NewKeyID)
	}
	if _, ok := ta.PublicKey("grape-release-2027"); !ok {
		t.Fatal("rotation chain did not learn new key")
	}
}

func TestAnonymousPollAssertions(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://updates.example.com/v1/manifest.json", nil)
	req.Header.Set("Authorization", "Bearer x")
	if err := AssertAnonymousPoll(req); err == nil {
		t.Fatal("expected poll_leaks_identity for authorization")
	}
	req.Header.Del("Authorization")
	req.Header.Set("X-Agent-Version", "1.0")
	if err := AssertAnonymousPoll(req); err == nil {
		t.Fatal("expected poll_leaks_identity for version header")
	}
}

func replaceJSONField(raw []byte, field, value string) []byte {
	var obj map[string]interface{}
	if err := jsonUnmarshal(raw, &obj); err != nil {
		return raw
	}
	if value == "2" {
		obj[field] = 2
	}
	out, _ := jsonMarshal(obj)
	return out
}
