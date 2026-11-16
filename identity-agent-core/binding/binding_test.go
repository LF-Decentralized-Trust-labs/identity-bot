package binding

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"identity-agent-core/iacrypto"
	"identity-agent-core/internal/contractcheck"
)

func seedOf(name string) []byte {
	h := sha256.Sum256([]byte("binding vector seed " + name))
	return h[:]
}

func keyOf(t testing.TB, name string) string {
	t.Helper()
	k, err := iacrypto.MatterFixedQB64("D", ed25519.NewKeyFromSeed(seedOf(name)).Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// The identifiers here are labels: what a verifier knows of an identifier is its key log,
// which the check is handed as KeyIsCurrent.
type world struct {
	t     testing.TB
	keys  map[string]string // identifier -> its current key
	stmt  Statement
	input Expect
}

func newWorld(t testing.TB) *world {
	w := &world{t: t, keys: map[string]string{
		"Erecord": keyOf(t, "record"), "Enew": keyOf(t, "new"), "Eother": keyOf(t, "other"),
	}}
	w.stmt = Statement{V: Version, Org: "Eorg", Site: "Esite", Record: "Erecord", New: "Enew", Invite: "Dinvite", Role: RolePerson}
	w.input = Expect{Org: "Eorg", Site: "Esite", Invite: "Dinvite", KeyIsCurrent: w.current}
	return w
}

func (w *world) current(id, key string) error {
	if w.keys[id] == "" || w.keys[id] != key {
		return errors.New("not in its key log")
	}
	return nil
}

func (w *world) link() Link {
	l, err := Sign(w.stmt, seedOf("record"), seedOf("new"))
	if err != nil {
		w.t.Fatal(err)
	}
	return l
}

func TestALinkSignedWithBothKeysIsAccepted(t *testing.T) {
	w := newWorld(t)
	if err := w.link().Verify(w.input); err != nil {
		t.Fatal(err)
	}
	w.stmt.Role = RoleOwner
	if err := w.link().Verify(w.input); err != nil {
		t.Fatalf("the owner's: %v", err)
	}
}

type refused struct {
	name string
	rule string // the rule, which every implementation names alike
	// make builds the link a verifier is handed, and may change what it expects.
	make func(w *world) Link
	want string
}

func refusals() []refused {
	return []refused{
		{"signed by the new identifier alone: the record's signature is the new key's", "record-signature", func(w *world) Link {
			l := w.link()
			l.RecordSig = l.NewSig
			return l
		}, "record's signature"},
		{"signed by the record's key alone: the new identifier's signature is the record's", "new-signature", func(w *world) Link {
			l := w.link()
			l.NewSig = l.RecordSig
			return l
		}, "new identifier's signature"},
		{"the record's signature missing", "missing-signature", func(w *world) Link { l := w.link(); l.RecordSig = ""; return l }, "both keys"},
		{"the new identifier's signature missing", "missing-signature", func(w *world) Link { l := w.link(); l.NewSig = ""; return l }, "both keys"},
		{"a key that is not the record identifier's", "key-not-of-identifier", func(w *world) Link {
			l := w.link()
			l.RecordKey = keyOf(w.t, "other")
			return l
		}, "not a key of Erecord"},
		{"a record identifier the new key's owner does not hold: signed with another's key", "key-not-of-identifier", func(w *world) Link {
			l, _ := Sign(w.stmt, seedOf("other"), seedOf("new"))
			return l
		}, "not a key of Erecord"},
		{"the statement changed after it was signed", "record-signature", func(w *world) Link {
			l := w.link()
			l.Statement.Role = RoleOwner
			return l
		}, "signature does not verify"},
		{"each key signed a different statement", "record-signature", func(w *world) Link {
			l := w.link()
			other := w.stmt
			other.Org = "Eelsewhere"
			l2, _ := Sign(other, seedOf("record"), seedOf("new"))
			l.RecordSig = l2.RecordSig
			return l
		}, "record's signature does not verify"},
		{"one identifier joined to itself", "same-identifier", func(w *world) Link {
			w.stmt.New = "Erecord"
			w.keys["Erecord"] = keyOf(w.t, "record")
			l, _ := Sign(w.stmt, seedOf("record"), seedOf("record"))
			return l
		}, "not one to itself"},
		{"made for another organisation", "organisation", func(w *world) Link { w.input.Org = "Eelsewhere"; return w.link() }, "another organisation"},
		{"made for another site", "site", func(w *world) Link { w.input.Site = "Eelsewhere"; return w.link() }, "another site"},
		{"answers another invite", "invite", func(w *world) Link { w.input.Invite = "Delsewhere"; return w.link() }, "another invite"},
		{"names no invite", "incomplete", func(w *world) Link { w.stmt.Invite = ""; return w.link() }, "names the organisation"},
		{"names neither a person nor the owner", "role", func(w *world) Link { w.stmt.Role = "admin"; return w.link() }, "person or the owner"},
		{"another version of the statement", "version", func(w *world) Link { w.stmt.V = "BIND2"; return w.link() }, "not a statement of a binding"},
		{"a check told nothing to expect", "not-told", func(w *world) Link { w.input = Expect{}; return w.link() }, "not told"},
		{"a key written with a space", "key-form", func(w *world) Link { l := w.link(); l.NewKey += " "; return l }, "not written as a key"},
		{"a key that is not a key", "key-form", func(w *world) Link { l := w.link(); l.NewKey = "nonsense"; return l }, "not a key"},
	}
}

func TestALinkThatIsNotSignedByBothKeysOverTheSameBytesIsRefused(t *testing.T) {
	for _, c := range refusals() {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			l := c.make(w)
			err := l.Verify(w.input)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("refused, but for %q, not %q", err, c.want)
			}
		})
	}
}

// What is published: a link, what its checker expects, the key log it consults, and the answer.
type vector struct {
	Name   string            `json:"name"`
	Rule   string            `json:"rule,omitempty"`
	Link   Link              `json:"link"`
	Expect vectorExpect      `json:"expect"`
	Keys   map[string]string `json:"keys"`
	Signed string            `json:"signed"`
	Valid  bool              `json:"valid"`
	Reason string            `json:"reason,omitempty"`
}

type vectorExpect struct{ Org, Site, Invite string }

type vectorFile struct {
	Description string   `json:"description"`
	Vectors     []vector `json:"vectors"`
}

const vectorsPath = "binding-vectors.json"

func makeVectors(t *testing.T) vectorFile {
	f := vectorFile{Description: "A binding joins two identifiers to one record by one statement signed with both keys over the same bytes (ADR-080). signed is the string both keys sign: the statement's fields in this order, as JSON with no spaces. keys is the key log the checker consults; expect is what it was told. Signatures are Ed25519, CESR qb64 (0B); keys are CESR qb64 (D)."}
	w := newWorld(t)
	good := w.link()
	f.Vectors = append(f.Vectors, vector{"accepted", "", good, vectorExpect{"Eorg", "Esite", "Dinvite"}, w.keys, string(good.Statement.SignedBytes()), true, ""})
	for _, c := range refusals() {
		w := newWorld(t)
		l := c.make(w)
		f.Vectors = append(f.Vectors, vector{c.name, c.rule, l, vectorExpect{w.input.Org, w.input.Site, w.input.Invite}, w.keys, string(l.Statement.SignedBytes()), false, c.want})
	}
	return f
}

func TestThePublishedVectorsAreWhatTheCodeMakesAndEveryOneIsJudgedAsItSays(t *testing.T) {
	made := makeVectors(t)
	if os.Getenv("WRITE_VECTORS") == "1" {
		b, _ := json.MarshalIndent(made, "", "  ")
		if err := os.WriteFile(vectorsPath, append(b, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var f vectorFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(made)
	got, _ := json.Marshal(f)
	if string(want) != string(got) {
		t.Fatal("the vectors file is not what the code makes: run with WRITE_VECTORS=1")
	}
	for _, v := range f.Vectors {
		e := Expect{Org: v.Expect.Org, Site: v.Expect.Site, Invite: v.Expect.Invite, KeyIsCurrent: func(id, key string) error {
			if v.Keys[id] == "" || v.Keys[id] != key {
				return errors.New("not in its key log")
			}
			return nil
		}}
		err := v.Link.Verify(e)
		if (err == nil) != v.Valid {
			t.Errorf("%s: valid=%v, got %v", v.Name, v.Valid, err)
		}
		if err != nil && !strings.Contains(err.Error(), v.Reason) {
			t.Errorf("%s: refused for %q, the file says %q", v.Name, err, v.Reason)
		}
	}
}

// An implementation written from the ADR, in another language, agrees with the vector file.
func TestAnIndependentImplementationAgreesWithTheBindingVectors(t *testing.T) {
	contractcheck.IndependentlyWith(t, "../contracts/check_binding_vectors.py", vectorsPath, "blake3")
}
