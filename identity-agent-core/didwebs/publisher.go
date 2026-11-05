package didwebs

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mr-tron/base58"

	"identity-agent-core/iacrypto"
)

// PublishInput is the live keystate used to derive did:webs artifacts.
type PublishInput struct {
	AID  string
	Host string
	// Plain is set for a document served over plain HTTP (the direct listener),
	// whose OOBI service endpoint is then http:// where it is otherwise https://.
	Plain            bool
	PublicKeyB64     string
	SequenceNumber   int
	KELEvents        []map[string]interface{}
	WitnessReceipts  int
	WitnessThreshold int
}

// BuildDidJSON returns the did.json document (the contract §2).
func BuildDidJSON(in PublishInput) ([]byte, error) {
	if in.AID == "" || in.Host == "" {
		return nil, fmt.Errorf("aid and host required")
	}
	pubRaw, err := iacrypto.DecodeSized(in.PublicKeyB64, ed25519.PublicKeySize, false)
	if err != nil {
		return nil, fmt.Errorf("invalid ed25519 public key")
	}
	scheme := "https"
	if in.Plain {
		scheme = "http"
	}
	did := fmt.Sprintf("did:webs:%s:%s", colonHost(in.Host), in.AID)
	keyID := fmt.Sprintf("%s#%s", did, keyIDFromPub(pubRaw))
	multibase := "z" + base58.Encode(pubRaw)
	doc := map[string]interface{}{
		"@context": []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/ed25519-2020/v1",
		},
		"id": did,
		"verificationMethod": []map[string]interface{}{
			{
				"id": keyID, "type": "Ed25519VerificationKey2020", "controller": did,
				"publicKeyMultibase": multibase,
			},
		},
		"authentication":  []string{keyID},
		"assertionMethod": []string{keyID},
		"service": []map[string]interface{}{
			{
				"id": fmt.Sprintf("%s#oobi", did), "type": "KERI-OOBI",
				"serviceEndpoint": fmt.Sprintf("%s://%s/%s/oobi", scheme, in.Host, in.AID),
			},
		},
	}
	return json.MarshalIndent(doc, "", "  ")
}

// BuildCesrStream returns KEL JSON bytes for dev; production uses driver /cesr-stream (BLOCKED).
func BuildCesrStream(in PublishInput) ([]byte, bool, string) {
	complete := in.WitnessReceipts >= in.WitnessThreshold && in.WitnessThreshold > 0
	hdr := fmt.Sprintf("%d/%d", in.WitnessReceipts, in.WitnessThreshold)
	if len(in.KELEvents) == 0 {
		return []byte("[]"), false, hdr
	}
	raw, _ := json.Marshal(in.KELEvents)
	return raw, complete, hdr
}

// colonHost is ColonHost with a port written as %3A, the did:web form: a colon
// inside the host would read as a path segment.
func colonHost(host string) string {
	head, tail := host, ""
	if i := strings.Index(host, "/"); i != -1 {
		head, tail = host[:i], host[i:]
	}
	if i := strings.LastIndex(head, ":"); i != -1 && !strings.Contains(head[i:], "]") && strings.Count(head, ":") == 1 {
		head = head[:i] + "%3A" + head[i+1:]
	}
	return ColonHost(head + tail)
}

// ColonHost maps URL host/path segments to did:webs colon form (the contract §1).
func ColonHost(host string) string {
	return strings.ReplaceAll(host, "/", ":")
}

func keyIDFromPub(pub []byte) string {
	return KeyIDFromPub(pub)
}

// KeyIDFromPub returns a stable did:webs verificationMethod fragment (dev stub).
func KeyIDFromPub(pub []byte) string {
	return base58.Encode(pub)[:16]
}
