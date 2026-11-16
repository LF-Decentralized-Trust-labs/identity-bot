package conversationbundle

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"identity-agent-core/internal/contractcheck"
)

// contracts/conversation-bundle/genuine-bundle-with-head.json is a genuine
// export that carries the Identity Agent's signed head statement, so a checker
// in any language is tested on the head, which genuine-bundle.json (written
// before exports carried one) does not reach. head-tamper-vectors.json is each
// way the head's envelope can be changed without the signatures noticing, as an
// RFC 6902 patch over it: every one must fail, and at the head statement.

const headTamperFile = "../contracts/conversation-bundle/head-tamper-vectors.json"

type tamperVectors struct {
	Genuine string `json:"genuine"`
	Control struct {
		Name     string            `json:"name"`
		Patch    []json.RawMessage `json:"patch"`
		Verifies bool              `json:"verifies"`
	} `json:"control"`
	Vectors []struct {
		Name    string    `json:"name"`
		Patch   []patchOp `json:"patch"`
		Because string    `json:"because"`
		_       struct{}  `json:"-"`
	} `json:"vectors"`
}

type patchOp struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value"`
}

// applyPatch applies RFC 6902 add, replace and remove to a parsed JSON value.
// It is as much of the RFC as the vectors use, and refuses the rest.
func applyPatch(doc any, ops []patchOp) (any, error) {
	for _, op := range ops {
		parts := strings.Split(strings.TrimPrefix(op.Path, "/"), "/")
		for i, p := range parts {
			parts[i] = strings.ReplaceAll(strings.ReplaceAll(p, "~1", "/"), "~0", "~")
		}
		parent := doc
		for _, p := range parts[:len(parts)-1] {
			switch n := parent.(type) {
			case map[string]any:
				parent = n[p]
			case []any:
				i, err := strconv.Atoi(p)
				if err != nil || i >= len(n) {
					return nil, fmt.Errorf("%s: no such place", op.Path)
				}
				parent = n[i]
			default:
				return nil, fmt.Errorf("%s: no such place", op.Path)
			}
		}
		obj, ok := parent.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s: only a member of an object is patched here", op.Path)
		}
		key := parts[len(parts)-1]
		_, exists := obj[key]
		switch op.Op {
		case "add":
			obj[key] = op.Value
		case "replace":
			if !exists {
				return nil, fmt.Errorf("%s: replace of what is not there", op.Path)
			}
			obj[key] = op.Value
		case "remove":
			if !exists {
				return nil, fmt.Errorf("%s: remove of what is not there", op.Path)
			}
			delete(obj, key)
		default:
			return nil, fmt.Errorf("%s: %q is not an operation these vectors use", op.Path, op.Op)
		}
	}
	return doc, nil
}

func patched(t *testing.T, genuine []byte, ops []patchOp) []byte {
	t.Helper()
	var doc any
	if err := json.Unmarshal(genuine, &doc); err != nil {
		t.Fatal(err)
	}
	doc, err := applyPatch(doc, ops)
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func theHeadVector(t *testing.T) ([]byte, *Bundle) {
	t.Helper()
	raw, err := os.ReadFile(headVectorFile)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Read(raw)
	if err != nil {
		t.Fatalf("the published head-bearing vector does not read as a bundle: %v", err)
	}
	return raw, b
}

func TestThePublishedHeadBearingBundleVerifiesAndItsHeadIsRead(t *testing.T) {
	_, b := theHeadVector(t)
	if b.Head == nil {
		t.Fatal("the published vector carries no head statement")
	}
	r := VerifyAgainst(b, b.Root)
	if !r.Verified {
		t.Fatalf("the published head-bearing bundle does not verify:\n%s", faultsOf(r))
	}
	if len(r.Messages) != len(b.Entries) || r.UncommittedEntries != 0 {
		t.Fatalf("the report covers %d messages of %d entries, %d uncommitted", len(r.Messages), len(b.Entries), r.UncommittedEntries)
	}
	// It is the head that fixes the end, so the vector reaches the head check.
	if r := Verify(b); !hasNote(r.CannotRuleOut, "the end is shown as of") {
		t.Fatalf("the report does not say the end is as of the head's time: %v", r.CannotRuleOut)
	}
	if r := VerifyAgainst(b, "EAnotherOrganisationAltogether"); r.Verified {
		t.Fatal("checked against another organisation, the bundle verified")
	}
}

func hasNote(notes []string, part string) bool {
	for _, n := range notes {
		if strings.Contains(n, part) {
			return true
		}
	}
	return false
}

func TestEveryTamperWithThePublishedHeadFails(t *testing.T) {
	genuine, _ := theHeadVector(t)
	raw, err := os.ReadFile(headTamperFile)
	if err != nil {
		t.Fatal(err)
	}
	var vs tamperVectors
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	if vs.Genuine != "genuine-bundle-with-head.json" {
		t.Fatalf("the vectors are over %q", vs.Genuine)
	}

	// The control changes nothing and verifies, so a refusal below is the patch's.
	if len(vs.Control.Patch) != 0 || !vs.Control.Verifies {
		t.Fatalf("the control is not an empty patch that verifies: %+v", vs.Control)
	}

	// The tampers cover every one TestAHeadStatementEnvelopeCarriesNothingUnsigned
	// holds a head to, so a case added there and not here is noticed.
	want := []string{"another-algorithm", "another-encryption", "another-sender", "no-sender", "missing-sender",
		"extra-sender-header", "extra-recipient-reference", "another-mode", "a-ciphertext", "an-iv", "recipients",
		"a-sender-key-log", "another-spelling-of-the-statement", "another-spelling-of-the-ed25519-signature",
		"another-spelling-of-the-mldsa-signature"}
	have := map[string]bool{}
	for _, v := range vs.Vectors {
		have[strings.TrimPrefix(v.Name, "head-")] = true
	}
	for _, w := range want {
		if !have[w] {
			t.Errorf("no vector for %q", w)
		}
	}
	if len(vs.Vectors) != len(want) {
		t.Errorf("%d vectors, want %d", len(vs.Vectors), len(want))
	}

	for _, v := range vs.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			if v.Because == "" || len(v.Patch) == 0 {
				t.Fatal("a vector says what it changes and why that is refused")
			}
			changed := patched(t, genuine, v.Patch)
			if string(changed) == string(patched(t, genuine, nil)) {
				t.Fatal("the patch changed nothing")
			}
			b, err := Read(changed)
			if err != nil {
				return // a reader that refuses the file has refused the tamper
			}
			r := Verify(b)
			if r.Verified {
				t.Fatalf("%s, and the bundle still verifies", v.Because)
			}
			for _, f := range r.Faults {
				if f.Where == "head statement" {
					return
				}
			}
			t.Fatalf("the bundle failed, but not at its head statement:\n%s", faultsOf(r))
		})
	}
}

// The control, patched and written out again, is the vector, and verifies: the
// patcher above changes nothing it was not asked to.
func TestTheHeadVectorPatchedWithNothingStillVerifies(t *testing.T) {
	genuine, _ := theHeadVector(t)
	b, err := Read(patched(t, genuine, nil))
	if err != nil {
		t.Fatal(err)
	}
	if r := Verify(b); !r.Verified {
		t.Fatalf("the control does not verify:\n%s", faultsOf(r))
	}
}

// The schema refuses the same tampers, checked by a validator that is not this
// code: contracts/check_conversation_bundle_schema.py, which needs the
// jsonschema module. The Go verifier above is the other half of the same claim,
// so a schema that drifted from it, or the other way, fails here.
func TestTheSchemaRefusesTheTampersTheVerifierDoes(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err == nil {
		if out, perr := exec.Command(py, "-I", "-c", "import jsonschema").CombinedOutput(); perr != nil {
			err = fmt.Errorf("%v: %s", perr, out)
		}
	}
	if err != nil {
		contractcheck.Unavailable(t, "python3 with the jsonschema module is not installed")
		return
	}
	out, err := exec.Command(py, "-I", "../contracts/check_conversation_bundle_schema.py", "../contracts").CombinedOutput()
	if err != nil {
		t.Fatalf("%v:\n%s", err, out)
	}
}
