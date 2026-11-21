package setupfile

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"testing"

	"identity-agent-core/iacrypto"
)

// This version of the reader ships one kind, a website, which holds no
// permissions. So that what every item carries can be tested, and published as
// vectors another implementation can read, the tests make up two kinds and one
// extension, as an add-on would. None is shipped.
const exampleKinds = `Three things are made up for these vectors, and none is shipped. example.worker is a kind. Its own members, all optional, are "note" (text of at most 200 bytes, declared as prose, so text shaped like an identifier there is flagged and does not block), "title" (text of at most 200 bytes, not prose), "credential" (the name of a credential it needs, which the file's credentials_needed must name) and "reports_to" (the name of a utility app, which the kind declares its field names); any other member is one it does not know. example.utility_app is a kind whose items are utility apps, which a permission on a utility app may name. Its one own member, optional, is "note" (text of at most 200 bytes, prose). example.labels is an extension: an object with exactly one member, "label", one lower-case word ([a-z][a-z0-9_]{0,63}). Each declares its member names, so a finding may say them.`

type worker struct {
	Note, Title, Credential, ReportsTo string
	utilityApp                         bool
}

type workerKind struct{ utilityApp bool }

func (k workerKind) Name() string {
	if k.utilityApp {
		return "example.utility_app"
	}
	return "example.worker"
}

func (k workerKind) IsUtilityApp() bool { return k.utilityApp }

func (k workerKind) members() []string {
	if k.utilityApp {
		return []string{"note"}
	}
	return []string{"note", "title", "credential", "reports_to"}
}

// Declares is all this made-up kind may say: one sentence to a place.
func (k workerKind) Declares() Declaration {
	return Declaration{Members: k.members(), Says: map[string]string{
		BadField + "@note":       "a note is at most 200 bytes",
		BadField + "@title":      "a title is at most 200 bytes",
		BadField + "@credential": "a credential is named",
		BadField + "@reports_to": "a utility app is named",
	}}
}

func (k workerKind) Parse(own map[string]json.RawMessage) (Fields, error) {
	if err := OnlyMembers(own, "", k.members()...); err != nil {
		return nil, err
	}
	w := worker{utilityApp: k.utilityApp}
	for member, into := range map[string]*string{"note": &w.Note, "title": &w.Title, "credential": &w.Credential, "reports_to": &w.ReportsTo} {
		if raw, has := own[member]; has {
			var ok bool
			if *into, ok = Text(raw); !ok {
				return nil, &FieldError{Code: BadField, Where: member}
			}
		}
	}
	return w, nil
}

func (w worker) Check(Common) []Finding {
	var out []Finding
	block := func(where string) { out = append(out, Finding{Code: BadField, Where: where, Blocks: true}) }
	if len(w.Note) > 200 {
		block("note")
	}
	if len(w.Title) > 200 {
		block("title")
	}
	if w.Credential != "" && CheckName(w.Credential) != nil {
		block("credential")
	}
	if w.ReportsTo != "" && CheckName(w.ReportsTo) != nil {
		block("reports_to")
	}
	return out
}

func (w worker) Describe() []Row { return []Row{{"Note", w.Note}} }

func (w worker) Refers() References {
	r := References{Prose: []string{"note"}}
	if w.Credential != "" {
		r.Credentials = []string{w.Credential}
	}
	if w.ReportsTo != "" && CheckName(w.ReportsTo) == nil {
		r.UtilityApps = []string{w.ReportsTo}
	}
	return r
}

type labels struct{ Label string }

type labelsExtension struct{}

func (labelsExtension) Namespace() string { return "example.labels" }

func (labelsExtension) Declares() Declaration {
	return Declaration{Members: []string{"label"}, Says: map[string]string{BadField + "@label": "a label is one lower-case word"}}
}

func (labelsExtension) Parse(_ string, raw json.RawMessage) (Fields, error) {
	m, err := Members(raw, "", "label")
	if err != nil {
		return nil, err
	}
	var l labels
	var ok bool
	if l.Label, ok = Text(m["label"]); !ok || !wordShape.MatchString(l.Label) {
		return nil, &FieldError{Code: BadField, Where: "label"}
	}
	return l, nil
}

func (labels) Check(Common) []Finding { return nil }
func (l labels) Describe() []Row      { return []Row{{"Label", l.Label}} }
func (labels) Refers() References     { return References{} }

func withExamples(t testing.TB) *Registry {
	t.Helper()
	r := NewRegistry()
	if err := r.AddKind(workerKind{}); err != nil {
		t.Fatal(err)
	}
	if err := r.AddKind(workerKind{utilityApp: true}); err != nil {
		t.Fatal(err)
	}
	if err := r.AddExtension(labelsExtension{}); err != nil {
		t.Fatal(err)
	}
	return r
}

// Keys come from published seeds: the SHA-256 of a sentence.
const seedSentence = "set-up file vector seed "

func seedOf(name string) []byte {
	h := sha256.Sum256([]byte(seedSentence + name))
	return h[:]
}

func keyOf(name string) ed25519.PublicKey {
	return ed25519.NewKeyFromSeed(seedOf(name)).Public().(ed25519.PublicKey)
}

// identifierOf is an identifier for a published seed: its key under the CESR
// code D, as an identity that has never rotated is named.
func identifierOf(name string) string {
	id, err := iacrypto.MatterFixedQB64("D", keyOf(name))
	if err != nil {
		panic(err)
	}
	return id
}

func signer(name string) func([]byte) ([]byte, error) {
	return func(b []byte) ([]byte, error) { return ed25519.Sign(ed25519.NewKeyFromSeed(seedOf(name)), b), nil }
}

// keysOf is a Resolver over the published seeds: each named identity's log has
// one event, at 0, whose key is in force. earlier names those whose key at 0
// has since been rotated away from.
func keysOf(earlier ...string) Resolver {
	return func(by string, sn uint64) (KeyAt, error) {
		for _, name := range []string{"exporter", "other", "importer"} {
			if by == identifierOf(name) && sn == 0 {
				return KeyAt{Key: keyOf(name), InForce: !slices.Contains(earlier, name)}, nil
			}
		}
		return KeyAt{}, errors.New("no key log is held for that identifier at that event")
	}
}

// aSaltOf is a salt in CESR: 16 bytes under the code 0A.
func aSaltOf(name string) string {
	s, err := iacrypto.MatterFixedQB64("0A", seedOf(name)[:16])
	if err != nil {
		panic(err)
	}
	return s
}

// aDigest is a digest of some text, for where a file names a schema.
func aDigest(of string) string { return iacrypto.Blake3QB64Must([]byte(of)) }

type object = map[string]any

func website(name, origin string, policy object) object {
	return object{"kind": "website", "name": name, "origin": origin, "policy": policy}
}

func aWorker(name string, more object) object {
	o := object{"kind": "example.worker", "name": name}
	for k, v := range more {
		o[k] = v
	}
	return o
}

// twoWebsites is the plainest file: what the core alone can read in full.
func twoWebsites() object {
	return object{
		"format":  Format,
		"made_at": "2026-11-20T09:00:00Z",
		"about":   "An example set-up: two websites.",
		"items": []any{
			website("Staff portal", "https://portal.example", object{"mode": "invite", "membership_source": "employees",
				"required_cred_schema": aDigest("an example schema"), "required_cred_issuer": "self"}),
			website("Public notes", "https://notes.example:8443", object{"mode": "open"}),
		},
	}
}

// aFullFile carries everything an item may: permissions, a permission on a
// utility app named in the same file, limits, a grant end, an extension and a
// credential by name.
func aFullFile() object {
	return object{
		"format": Format,
		"items": []any{
			object{"kind": "example.utility_app", "name": "Board", "note": "A utility app, made up for these vectors."},
			aWorker("Reader", object{
				"permissions": []any{"code.repository.read", object{"utility_app": "Board", "permission": "write"}},
				"limits":      object{"code.repository.read": object{"repository": []any{"example/handbook", "example/site"}}},
				"grant_end":   "2027-06-30T00:00:00Z",
				"note":        "Reads two repositories and writes to the board.",
				"credential":  "Model sign-in",
				"extensions":  object{"example.labels": object{"label": "docs"}},
			}),
			aWorker("Builder", object{
				"permissions": []any{"code.repository.write", "machine.provide"},
				"limits":      object{"code.repository.write": object{"repository": []any{"example/site"}}},
			}),
			website("Public notes", "https://notes.example", object{"mode": "open"}),
		},
		"credentials_needed": []any{object{"name": "Model sign-in", "about": "The sign-in the example worker's model uses."}},
	}
}

func text(t testing.TB, o object) []byte {
	t.Helper()
	b, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

func read(t testing.TB, data []byte, o Options) *Result {
	t.Helper()
	if o.Registry == nil {
		o.Registry = withExamples(t)
	}
	r, err := Read(data, o)
	if err != nil {
		t.Fatalf("the file was refused: %v", err)
	}
	return r
}

func refusal(t testing.TB, data []byte) string {
	t.Helper()
	r, err := Read(data, Options{Registry: withExamples(t)})
	if err == nil {
		t.Fatalf("the file was read: %+v", r)
	}
	if CodeOf(err) == "" {
		t.Fatalf("the file was refused with no code: %v", err)
	}
	return CodeOf(err)
}

// codes are the codes of an item's findings that block it, or of those that do
// not, each once, sorted.
func codes(it Item, blocking bool) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, f := range it.Findings {
		if f.Blocks == blocking && !seen[f.Code] {
			seen[f.Code] = true
			out = append(out, f.Code)
		}
	}
	sort.Strings(out)
	return out
}

func only(t testing.TB, it Item, state State, want ...string) {
	t.Helper()
	got := codes(it, true)
	if it.State != state || len(got) != len(want) {
		t.Fatalf("item %d (%q) is %s for %v, wanted %s for %v: %+v", it.Index, it.Name, it.State, got, state, want, it.Findings)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("item %d (%q) is %s for %v, wanted %s for %v", it.Index, it.Name, it.State, got, state, want)
		}
	}
}
