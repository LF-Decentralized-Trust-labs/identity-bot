//go:build kerigo_pqtest

package keymath

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"testing"

	keri "github.com/grapeid/keri-go"
)

// The operation writes a 4420-character indexed signature that keri-go reads
// back at the same index and prior-next place, with the signature intact.
func TestTheIndexedPostQuantumSignatureIsWrittenInATestBuild(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, 32)
	sig, err := SignMLDSA65(seed, []byte("an event"))
	if err != nil {
		t.Fatal(err)
	}
	req, _ := json.Marshal(map[string]any{"sig_b64": base64.StdEncoding.EncodeToString(sig), "index": 1, "ondex": 1})
	out, err := Do("index_mldsa65_sig", req)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Sig string `json:"sig_qb64"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Sig) != 4420 || got.Sig[:2] != "3Z" {
		t.Fatalf("an indexed ML-DSA-65 signature is 4420 characters under 3Z: %d %.4s", len(got.Sig), got.Sig)
	}
	read, err := keri.ParseIndexedSignature(got.Sig)
	if err != nil {
		t.Fatal(err)
	}
	if read.At.Index != 1 || read.At.Ondex != 1 || !bytes.Equal(read.Raw, sig) {
		t.Fatalf("read back at %+v", read.At)
	}
}

// The two places are written as asked, not swapped.
func TestAnIndexedPostQuantumSignatureKeepsItsIndexAndPriorNextApart(t *testing.T) {
	sig, err := SignMLDSA65(bytes.Repeat([]byte{7}, 32), []byte("an event"))
	if err != nil {
		t.Fatal(err)
	}
	for _, at := range [][2]int{{1, 0}, {0, 3}, {2, 1}} {
		req, _ := json.Marshal(map[string]any{"sig_b64": base64.StdEncoding.EncodeToString(sig), "index": at[0], "ondex": at[1]})
		out, err := Do("index_mldsa65_sig", req)
		if err != nil {
			t.Fatal(err)
		}
		var got struct {
			Sig string `json:"sig_qb64"`
		}
		if err := json.Unmarshal(out, &got); err != nil {
			t.Fatal(err)
		}
		read, err := keri.ParseIndexedSignature(got.Sig)
		if err != nil || read.At.Index != at[0] || read.At.Ondex != at[1] || !bytes.Equal(read.Raw, sig) {
			t.Fatalf("index %d, prior-next %d was read back as %+v: %v", at[0], at[1], read.At, err)
		}
	}
}

// A current-only ML-DSA-65 signature is written under keri-go's current-only
// code and reads back as one, at its index.
func TestACurrentOnlyPostQuantumSignatureOpensNothing(t *testing.T) {
	sig, err := SignMLDSA65(bytes.Repeat([]byte{7}, 32), []byte("an event"))
	if err != nil {
		t.Fatal(err)
	}
	req, _ := json.Marshal(map[string]any{"sig_b64": base64.StdEncoding.EncodeToString(sig), "index": 1, "current_only": true})
	out, err := Do("index_mldsa65_sig", req)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Sig string `json:"sig_qb64"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	read, err := keri.ParseIndexedSignature(got.Sig)
	if err != nil || read.At.Index != 1 || !read.At.CurrentOnly || !bytes.Equal(read.Raw, sig) || got.Sig[:2] != "3Y" {
		t.Fatalf("read back %+v: %v", read.At, err)
	}
}
