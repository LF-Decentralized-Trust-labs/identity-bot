package setupfile

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"identity-agent-core/internal/contractcheck"
)

const vectorsPath = "set-up-file-vectors.json"

type vectorKey struct {
	// Seed is the 32-byte Ed25519 seed (RFC 8032), in hexadecimal: the SHA-256
	// of SeedOf.
	SeedOf     string `json:"seed_of"`
	Seed       string `json:"seed"`
	Key        string `json:"key"`
	Identifier string `json:"identifier"`
}

type vectorItem struct {
	Kind        string   `json:"kind"`
	Name        string   `json:"name"`
	State       State    `json:"state"`
	Blocks      []string `json:"blocks"`
	Flags       []string `json:"flags"`
	Rest        string   `json:"rest"`
	UtilityApps []string `json:"utility_apps"`
	DependsOn   []string `json:"depends_on"`
	Credentials []string `json:"credentials"`
}

type fileVector struct {
	Name string `json:"name"`
	// File is the file, as text; or FileHex is its bytes in hexadecimal, for a
	// file that is not UTF-8 or that holds a string judged a secret, so that
	// the published vectors hold no such string as text.
	File    string `json:"file,omitempty"`
	FileHex string `json:"file_hex,omitempty"`
	// Knows, when given, are the only capabilities the reading Identity Agent
	// knows, and Now the time it is asked.
	Knows []string `json:"knows,omitempty"`
	Now   string   `json:"now,omitempty"`
	// The reader holds the key log of each identity in keys: one event, at 0,
	// whose key is in force. EarlierKeys names those whose key at 0 has since
	// been rotated away from, and NoKeyLog is a reader that holds no key log.
	EarlierKeys []string `json:"earlier_keys,omitempty"`
	NoKeyLog    bool     `json:"no_key_log,omitempty"`
	// Refused is why the file is refused whole, or "".
	Refused string `json:"refused"`
	// The rest is given for a file that is read.
	Contents string       `json:"contents,omitempty"`
	Flags    []string     `json:"flags,omitempty"`
	Items    []vectorItem `json:"items,omitempty"`
	// Seal is what the seal is found to be, SealedBy whose signature verified,
	// and SealInput the bytes the seal's signature is over.
	Seal      SealState `json:"seal,omitempty"`
	SealedBy  string    `json:"sealed_by,omitempty"`
	SealInput string    `json:"seal_input,omitempty"`
}

func (v fileVector) bytes() []byte {
	if v.FileHex != "" {
		b, _ := hex.DecodeString(v.FileHex)
		return b
	}
	return []byte(v.File)
}

type vectorPick struct {
	Index        int          `json:"index"`
	Acknowledged []Permission `json:"acknowledged"`
}

type vectorChoice struct {
	IdentityAgent string            `json:"identity_agent"`
	Proposal      string            `json:"proposal"`
	Nonce         string            `json:"nonce"`
	Items         []vectorPick      `json:"items"`
	UtilityApps   map[string]string `json:"utility_apps"`
	Credentials   map[string]string `json:"credentials"`
}

// approvalVector is a choice made from one of the files above, and the list
// it gives.
type approvalVector struct {
	Name string `json:"name"`
	// From is the name of the file the choice is made from, read as that
	// vector says.
	From   string       `json:"from"`
	Choice vectorChoice `json:"choice"`
	// NeedsAcknowledging are the capabilities the importing Identity Agent has
	// the owner acknowledge one by one.
	NeedsAcknowledging []string `json:"needs_acknowledging"`
	Refused            string   `json:"refused"`
	// Bytes are what the approval signs, and Digest their digest; given for a
	// choice that is not refused.
	Bytes  string `json:"bytes,omitempty"`
	Digest string `json:"digest,omitempty"`
}

// listVector is the bytes of a chosen list as a device asked to approve one
// is handed them.
type listVector struct {
	Name               string   `json:"name"`
	List               string   `json:"list"`
	NeedsAcknowledging []string `json:"needs_acknowledging"`
	Refused            string   `json:"refused"`
}

type vectorSet struct {
	Description  string               `json:"description"`
	ExampleKinds string               `json:"example_kinds"`
	Keys         map[string]vectorKey `json:"keys"`
	Files        []fileVector         `json:"files"`
	Approvals    []approvalVector     `json:"approvals"`
	Lists        []listVector         `json:"lists"`
}

func optionsOf(t testing.TB, v fileVector) Options {
	o := Options{Registry: withExamples(t)}
	if v.Knows != nil {
		o.KnowsPermission = func(p Permission) bool { return !p.onApp() && slices.Contains(v.Knows, p.Capability) }
	}
	if v.Now != "" {
		o.Now, _ = time.Parse(time.RFC3339, v.Now)
	}
	return o
}

func resolverOf(v fileVector) Resolver {
	if v.NoKeyLog {
		return nil
	}
	return keysOf(v.EarlierKeys...)
}

func needing(capabilities []string) func(Permission) bool {
	return func(p Permission) bool { return !p.onApp() && slices.Contains(capabilities, p.Capability) }
}

func none(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func flagsOf(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		if !f.Blocks && !slices.Contains(out, f.Code) {
			out = append(out, f.Code)
		}
	}
	slices.Sort(out)
	return out
}

// judged fills in everything a vector says about a file from what the reader
// makes of it.
func judged(t testing.TB, v fileVector) fileVector {
	t.Helper()
	v.Refused, v.Contents, v.Flags, v.Items, v.Seal, v.SealedBy, v.SealInput = "", "", nil, nil, "", "", ""
	r, err := Read(v.bytes(), optionsOf(t, v))
	if err != nil {
		if v.Refused = CodeOf(err); v.Refused == "" {
			t.Fatalf("%s: refused with no code: %v", v.Name, err)
		}
		return v
	}
	v.Contents, v.Flags = r.Contents, flagsOf(r.Flags)
	for _, it := range r.Items {
		v.Items = append(v.Items, vectorItem{Kind: it.Kind, Name: it.Name, State: it.State, Blocks: codes(it, true), Flags: codes(it, false),
			Rest: it.Rest, UtilityApps: none(it.UtilityApps), DependsOn: none(it.DependsOn), Credentials: none(it.Credentials)})
	}
	found := r.CheckSeal(resolverOf(v))
	v.Seal, v.SealedBy = found.State(), found.By()
	if r.Seal != nil {
		if input, err := SealInput(r.Seal.By, r.Seal.Contents, r.Seal.KelSN); err == nil {
			v.SealInput = string(input)
		}
	}
	return v
}

func (c vectorChoice) choice(r *Result, v fileVector) Choice {
	out := Choice{IdentityAgent: c.IdentityAgent, Proposal: c.Proposal, Nonce: c.Nonce, Seal: r.CheckSeal(resolverOf(v)),
		UtilityApps: c.UtilityApps, Credentials: c.Credentials}
	for _, p := range c.Items {
		out.Items = append(out.Items, Pick{Index: p.Index, Acknowledged: p.Acknowledged})
	}
	return out
}

func written(t testing.TB) vectorSet {
	t.Helper()
	set := vectorSet{
		Description: "Set-up files (ADR-088, docs/set-up-file.md), each with what a reader makes of it. file is the file's text, or file_hex its bytes in hexadecimal where they are not UTF-8 or where any string in the file, a value or a member's name, is in a spelling only a secret has (secret_shaped), so that no such string is held in these vectors as text. " +
			"A file is refused whole for the reason in refused, or read: contents is the digest of its canonical contents (the file without its seal, in RFC 8785 canonical JSON, as Blake3-256 in CESR qb64), flags what the person is told of the file's own notes, " +
			"and each item is ready, blocked (blocks: the reasons, each once, sorted) or not_understood, with its flags, its rest digest, the utility apps it names, those of them that are utility-app items of the file (depends_on) and the credentials it needs. " +
			"seal is what the seal is found to be by a reader that holds, for each identity in keys, a key log of one event, at 0, whose key is in force (earlier_keys names those whose key has since been rotated away from; no_key_log is a reader that holds none); sealed_by is whose signature verified, and seal_input the bytes signed. " +
			"approvals are choices made from those files: bytes is the chosen list an approval signs (in RFC 8785 canonical JSON) and digest its digest, or refused says why the choice gives no list. lists are the bytes of a chosen list as a device is handed them, read or refused. " +
			"Keys are Ed25519, each from a published seed; an identifier is the key in CESR qb64 under the code D. Signatures are CESR indexed signatures (code A, index 0). " +
			"The reader of these vectors knows the kind website and the example kinds and extension described in example_kinds, and nothing else. The Unicode facts text is judged by are in unicode-15.0.json, beside this file.",
		ExampleKinds: exampleKinds,
		Keys:         map[string]vectorKey{},
	}
	for _, name := range []string{"exporter", "other", "importer"} {
		set.Keys[name] = vectorKey{SeedOf: seedSentence + name, Seed: hex.EncodeToString(seedOf(name)), Key: identifierOf(name), Identifier: identifierOf(name)}
	}
	add := func(name string, file []byte, more ...func(*fileVector)) {
		v := fileVector{Name: name}
		if utf8.Valid(file) && !holdsSecretShapedText(file) {
			v.File = string(file)
		} else {
			v.FileHex = hex.EncodeToString(file)
		}
		for _, m := range more {
			m(&v)
		}
		set.Files = append(set.Files, judged(t, v))
	}
	with := func(base object, change func(f object)) []byte {
		change(base)
		return text(t, base)
	}
	item := func(f object, i int) object { return f["items"].([]any)[i].(object) }
	workers := func(items ...any) []byte {
		return with(aFullFile(), func(f object) { f["items"] = items })
	}

	// Files that are read.
	add("two websites", text(t, twoWebsites()))
	add(fullFile, text(t, aFullFile()))
	add("a kind the reader does not know is listed and skipped", with(twoWebsites(), func(f object) {
		f["items"] = append(f["items"].([]any), object{"kind": "example.unknown", "name": "Something newer", "anything": []any{1, object{"deep": true}}},
			object{"kind": "example.unknown", "name": "Two  spaces"}, object{"kind": "example.unknown", "name": identifierOf("an asset")},
			object{"kind": "example.unknown"}, object{"kind": "example.unknown", "name": "Something newer"})
	}))
	add("an AI agent and a utility app are kinds this version does not yet read: listed and skipped", with(twoWebsites(), func(f object) {
		f["items"] = append(f["items"].([]any), object{"kind": "ai_agent", "name": "Reader", "permissions": []any{"code.repository.read"}},
			object{"kind": "utility_app", "name": "Board"})
	}))
	add("a permission the Identity Agent does not know, and a grant that would already have ended", text(t, aFullFile()), func(v *fileVector) {
		v.Knows, v.Now = []string{"code.repository.read", "code.repository.write"}, "2027-06-30T00:00:00Z"
	})
	add("items blocked, each for one reason, beside one that is ready", workers(
		aWorker("Ready", nil),
		aWorker("A field this version does not know", object{"colour": "green"}),
		aWorker("An extension this version does not know", object{"extensions": object{"example.other": object{"x": "y"}}}),
		aWorker("An extension with a field it does not know", object{"extensions": object{"example.labels": object{"label": "docs", "more": "x"}}}),
		aWorker("Extensions that are not an object", object{"extensions": []any{}}),
		aWorker("ready", nil),
		aWorker("An identifier where a name is not prose", object{"title": "Ask " + identifierOf("another AI agent") + " first."}),
		aWorker("A record number where text is not prose", object{"title": "Its record is 0123456789abcdef0123456789abcdef."}),
		aWorker("A hidden character in text", object{"note": "Left\u202eright"}),
		aWorker("A permission carrying an identifier", object{"permissions": []any{"board.a0123456789abcdef0123456789abcdef.write"}}),
		aWorker("A permission on a utility app with a member too many", object{"permissions": []any{object{"utility_app": "Ready", "permission": "write", "more": true}}}),
		aWorker("One permission on a utility app, twice in two cases", object{"permissions": []any{
			object{"utility_app": "Board", "permission": "write"}, object{"utility_app": "BOARD", "permission": "write"}}}),
		aWorker("A limit on a permission it does not ask for", object{"permissions": []any{"code.repository.read"},
			"limits": object{"code.repository.write": object{"repository": []any{"example/site"}}}}),
		aWorker("A limit keyed by nothing beside a utility app", object{"permissions": []any{object{"utility_app": "Board", "permission": "write"}},
			"limits": object{"": object{"repository": []any{"example/site"}}}}),
		aWorker("A limit with no values", object{"permissions": []any{"code.repository.read"}, "limits": object{"code.repository.read": object{"repository": []any{}}}}),
		aWorker("A grant end that is not a time in UTC", object{"grant_end": "2027-06-30T00:00:00+01:00"}),
		aWorker("A grant end in the year 0000", object{"grant_end": "0000-01-01T00:00:00Z"}),
		aWorker("A credential the file does not name", object{"credential": "Another sign-in"}),
		aWorker("A note over its own limit", object{"note": strings.Repeat("long ", 50)}),
		aWorker("A note that is not text", object{"note": 7}),
		website("A website with a path", "https://portal.example/staff", object{"mode": "open"}),
		website("A website with its default port written", "https://portal.example:443", object{"mode": "open"}),
		website("A website with a host in capitals", "https://Portal.example", object{"mode": "open"}),
		website("A website with a gate the reader has no field for", "https://gated.example", object{"mode": "open", "required_aal": 2}),
		object{"kind": "website", "name": "A website with permissions", "origin": "https://granted.example", "policy": object{"mode": "open"},
			"permissions": []any{"code.repository.read"}},
		website("A website with an issuer and no credential", "https://issuer.example", object{"mode": "invite", "required_cred_issuer": "self"}),
		website("A website with an issuer from elsewhere", "https://elsewhere.example", object{"mode": "invite",
			"required_cred_schema": aDigest("an example schema"), "required_cred_issuer": identifierOf("other")}),
		website("A second website of one origin", "https://elsewhere.example", object{"mode": "open"}),
		object{"kind": "Not A Kind", "name": "A kind that is not written as one"},
		object{"kind": "example.worker"},
		"not an item",
	))
	var named, unnamed, noted, unnoted []any
	for _, n := range writtenNames {
		named = append(named, aWorker(n[1], nil))
		noted = append(noted, aWorker(fmt.Sprintf("Note %d", len(noted)), object{"note": n[1]}))
	}
	for _, n := range notNames {
		unnamed = append(unnamed, aWorker(n[1], nil))
	}
	for _, n := range writtenText {
		noted = append(noted, aWorker(fmt.Sprintf("Note %d", len(noted)), object{"note": n[1]}))
	}
	for _, n := range notText {
		unnoted = append(unnoted, aWorker(fmt.Sprintf("Note %d", len(unnoted)), object{"note": n[1]}))
	}
	unnamed = append(unnamed, aWorker(strings.Repeat("A name that is too long ", 3), nil), aWorker(identifierOf("an asset"), nil),
		aWorker("0123456789abcdef0123456789abcdef", nil))
	add("names as their languages write them, each a name", workers(named...))
	add("text that is not a name, each blocked and none kept as a name", workers(unnamed...))
	add("text as languages write it, each read", workers(noted...))
	add("text that holds what is not seen, each blocked", workers(unnoted...))
	for _, pair := range oneName {
		add("two spellings of one name, the second a duplicate: "+pair[0], workers(aWorker(pair[1], nil), aWorker(pair[2], nil)))
	}
	for _, pair := range twoNames {
		add("two names that are not one: "+pair[0], workers(aWorker(pair[1], nil), aWorker(pair[2], nil)))
	}
	add("text that looks like a secret blocks one item, and text that only looks odd does not", workers(
		aWorker("A link to a shared document", object{"note": "See https://docs.google.com/document/d/1x7Zr2Lm9Xc4Vb1Nn8Kp3Jh6Gf5Ds0Aa7Qw2Er9Ty4U/edit"}),
		aWorker("A long title with a year", object{"note": "Quarterly-Report-2026-Final-Version-For-The-Board"}),
		aWorker("A file name with a year", object{"note": "Employee_Handbook_2026_Final_Reviewed_Version.pdf"}),
		aWorker("A long link with a date", object{"note": "https://news.example/2026/11/20/how-we-rebuilt-the-handbook-for-everyone-in-2026-11-20"}),
		aWorker("A slug that begins like a token", object{"note": "sk-this-is-a-long-hyphenated-slug"}),
		aWorker("A link naming a user and no password", object{"note": "https://reader@docs.example/handbook"}),
		aWorker("A link with a placeholder for its password", object{"note": "postgres://USER:PASSWORD@HOST/handbook and https://user:pass@docs.example"}),
		aWorker("A link with a password in brackets", object{"note": "https://user:<password>@docs.example/handbook"}),
		aWorker("A mail address after a colon", object{"note": "mailto:someone:else@docs.example"}),
		aWorker("Two words a line apart", object{"note": joined("AK", "IA") + "\nABCDEFGHIJKLMNOP"}),
		aWorker("Two words a no-break space apart", object{"note": joined("AK", "IA") + "\u00a0ABCDEFGHIJKLMNOP"}),
		aWorker("A slug that begins like a token and ends in a word", object{"note": "sk-Report-2026-final-version-x"}),
		aWorker("A slug that begins like a token and ends in a long word", object{"note": "sk-notes-internationalisationguide"}),
		aWorker("Links with a placeholder in closed brackets, as a variable, or as words", object{"note": "https://user:${DB_PASSWORD}@docs.example https://user:{{password}}@docs.example https://user:[password]@docs.example https://user:%s@docs.example https://user:your-password@docs.example https://user:YOUR_PASSWORD@docs.example"}),
		aWorker("Twenty-four characters that begin like a salt and are not one", object{"note": "0A" + strings.Repeat("a", 22)}),
		aWorker("An image by its digest", object{"note": "image@sha256:" + strings.Repeat("0f1e2d3c", 8)}),
		aWorker("A long random run", object{"note": "q7Zr2Lm9Xc4Vb1Nn8Kp3Jh6Gf5Ds0Aa7Qw2Er9Ty4Ui"}),
		aWorker("A commit in prose", object{"note": "Start from commit 3f2a9c1b7d4e6f8091a2b3c4d5e6f708192a3b4c."}),
		aWorker("A record number in prose", object{"note": "Its record is 0123456789abcdef0123456789abcdef."}),
		aWorker("An identifier in prose", object{"note": "Ask " + identifierOf("another AI agent") + " first."}),
		aWorker("A commit where text is not prose", object{"title": "3f2a9c1b7d4e6f8091a2b3c4d5e6f708192a3b4c"}),
		aWorker("A limit naming a zone by its identifier", object{"permissions": []any{"dns.record.write"},
			"limits": object{"dns.record.write": object{"zone": []any{"0123456789abcdef0123456789abcdef"}}}}),
	), func(v *fileVector) {})
	add("a note about the file that holds a digest is flagged, and the file is read", with(twoWebsites(), func(f object) {
		f["about"] = "Exported at commit 3f2a9c1b7d4e6f8091a2b3c4d5e6f708192a3b4c."
	}))
	add("a website named as a utility app is named does not stand for it", with(aFullFile(), func(f object) {
		f["items"].([]any)[0] = website("Board", "https://board.example", object{"mode": "open"})
	}))

	// Seals.
	add("sealed", sealed(t, twoWebsites(), "exporter", "exporter"))
	oneByte := bytes.Replace(sealed(t, twoWebsites(), "exporter", "exporter"), []byte("Staff portal"), []byte("Staff portaI"), 1)
	add("sealed, then changed by one byte", oneByte)
	add("sealed, with a signature made by another key", sealed(t, twoWebsites(), "exporter", "other"))
	var laidOut object
	_ = json.Unmarshal(sealed(t, twoWebsites(), "exporter", "exporter"), &laidOut)
	compact, _ := json.Marshal(laidOut)
	add("sealed, and written again on one line", compact)
	add("sealed by a key its sealer has since rotated away from", sealed(t, twoWebsites(), "exporter", "exporter"), func(v *fileVector) { v.EarlierKeys = []string{"exporter"} })
	add("sealed, and read where no key log is held", sealed(t, twoWebsites(), "exporter", "exporter"), func(v *fileVector) { v.NoKeyLog = true })
	var forged object
	_ = json.Unmarshal(sealed(t, twoWebsites(), "exporter", "other"), &forged)
	add("a seal forged in another's name over other contents is broken, not changed", with(forged, func(f object) {
		f["seal"].(object)["contents"] = aDigest("some other contents")
	}))
	sealedFull := sealed(t, aFullFile(), "exporter", "exporter")
	add(sealedFullFile, sealedFull)
	add(changedFullFile, bytes.Replace(sealedFull, []byte("Builder"), []byte("Bilder"), 1))
	add(fieldNamesFile, with(aFullFile(), func(f object) { item(f, 2)["reports_to"] = "Board" }))
	add("a field names a utility app by something that is not a name", with(aFullFile(), func(f object) { item(f, 2)["reports_to"] = "Two  spaces" }))

	// Files refused whole.
	add("refused: a newer version", with(twoWebsites(), func(f object) { f["format"] = "identity-agent-set-up/2"; f["added_by_version_2"] = true }))
	add("refused: not a set-up file", with(twoWebsites(), func(f object) { f["format"] = "another-file/1" }))
	add("refused: no format", with(twoWebsites(), func(f object) { delete(f, "format") }))
	add("refused: a member of the file this version does not know", with(twoWebsites(), func(f object) { f["defaults"] = object{"mode": "open"} }))
	add("refused: a member of the file named as a token is, for the token and not for the member", with(twoWebsites(), func(f object) {
		f[keyShaped("a GitHub token")] = true
	}))
	add("refused: no items", with(twoWebsites(), func(f object) { delete(f, "items") }))
	add("refused: a time that is not in UTC to the second", with(twoWebsites(), func(f object) { f["made_at"] = "2026-11-20 09:00" }))
	add("refused: a time in the year 0000", with(twoWebsites(), func(f object) { f["made_at"] = "0000-01-01T00:00:00Z" }))
	good := string(text(t, twoWebsites()))
	add("refused: a member named twice", []byte(strings.Replace(good, `"mode": "open"`, `"mode": "invite", "mode": "open"`, 1)))
	add("refused: text after the object", []byte(good+"{}"))
	add("refused: a list, not an object", []byte("["+good+"]"))
	add("refused: half of a surrogate pair", []byte(strings.Replace(good, "two websites", `two \ud800 websites`, 1)))
	add("refused: a byte order mark", []byte("\xef\xbb\xbf"+good))
	add("refused: bytes that are not UTF-8", []byte(strings.Replace(good, "two websites", "two \xff websites", 1)))
	deep := func(n int) []byte {
		return []byte(strings.Replace(good, `"mode": "open"`, `"mode": "open", "deep": `+strings.Repeat("[", n)+strings.Repeat("]", n), 1))
	}
	add("a file nested 64 deep is read, and its item blocked for the field", deep(60))
	add("refused: nested 65 deep", deep(61))
	for _, n := range []string{"1.5", "1e3", "1E400", "-0", "9007199254740993"} {
		add("refused: the number "+n, []byte(strings.Replace(good, `"mode": "open"`, `"mode": "open", "weight": `+n, 1)))
	}
	// Two faults in one file: the reason is the one that comes first in the
	// order a reader checks, whatever order the file's members are in.
	add("refused: a token and a null, for the token", with(twoWebsites(), func(f object) {
		f["about"] = nil
		f["zz_token"] = keyShaped("a GitHub token")
	}))
	add("refused: a null and a number that is not whole, for the null", with(twoWebsites(), func(f object) {
		f["a_number"] = 1.5
		f["zz_null"] = nil
	}))
	add("refused: a number that is not whole in a member this version does not know, for the number", with(twoWebsites(), func(f object) { f["weight"] = 1.5 }))
	nulls := map[string]func(f object){
		"the note about the file":       func(f object) { f["about"] = nil },
		"the list of items":             func(f object) { f["items"] = nil },
		"a credential's note":           func(f object) { f["credentials_needed"] = []any{object{"name": "Model sign-in", "about": nil}} },
		"a website's membership source": func(f object) { item(f, 0)["policy"].(object)["membership_source"] = nil },
		"a website's required schema":   func(f object) { item(f, 0)["policy"].(object)["required_cred_schema"] = nil },
		"a website's required issuer":   func(f object) { item(f, 0)["policy"].(object)["required_cred_issuer"] = nil },
		"an item's extensions":          func(f object) { item(f, 1)["extensions"] = nil },
		"an item's name":                func(f object) { item(f, 1)["name"] = nil },
		"a value of a kind nobody knows": func(f object) {
			f["items"] = append(f["items"].([]any), object{"kind": "example.unknown", "name": "X", "deep": []any{object{"k": nil}}})
		},
	}
	for _, name := range sorted(nulls) {
		add("refused: null as "+name, with(twoWebsites(), nulls[name]))
	}
	secrets := map[string]string{
		"a private key block":                               keyShaped("a private key block"),
		"a seed in CESR":                                    "A" + identifierOf("a seed")[1:],
		"a salt in CESR":                                    aSaltOf("a salt"),
		"a token that begins sk- after a route":             keyShaped("sk- after a route, and 64 hexadecimal"),
		"a token that begins sk- in lower case":             keyShaped("sk- and 32 hexadecimal digits"),
		"a mail service key":                                keyShaped("a mail service key"),
		"a PGP private key block":                           keyShaped("a PGP private key block"),
		"a link whose password only begins like a variable": "postgres://admin:$uperS3cret9@db.example/handbook",
		"a link whose password begins with an encoded sign": "postgres://admin:%24uperS3cret9@db.example/handbook",
		"a link whose password only begins like a bracket":  "postgres://admin:{Xk29fj3Lq8@db.example/handbook",
		"a token that begins sk-":                           keyShaped("sk- and 32 letters and digits"),
		"a live key":                                        keyShaped("a live key"),
		"a restricted live key":                             keyShaped("a restricted live key"),
		"a GitHub token":                                    keyShaped("a GitHub token"),
		"a GitLab token":                                    keyShaped("a GitLab token"),
		"an npm token":                                      keyShaped("an npm token"),
		"an age key":                                        keyShaped("an age key"),
		"a JSON Web Token":                                  keyShaped("a JSON Web Token"),
		"a link with a user and a password":                 "postgres://reader:hunter2@db.example/handbook",
		"a key split by a joiner":                           keyShaped("an access key split by a joiner"),
		"a token that begins sk- split by a joiner":         keyShaped("sk- with a project, split by a joiner"),
		"a key split by a soft hyphen":                      keyShaped("an access key split by a soft hyphen"),
		"a key split by a zero-width space":                 keyShaped("an access key split by a zero-width space"),
		"a key split by a word joiner":                      keyShaped("an access key split by a word joiner"),
		"a key split by a byte order mark":                  keyShaped("an access key split by a byte order mark"),
		"a key split by a tag character":                    keyShaped("an access key split by a tag character"),
		"a key in fullwidth letters":                        keyShaped("an access key in fullwidth letters"),
	}
	for _, name := range sorted(secrets) {
		s := secrets[name]
		add("refused: "+name+", in the note about the file", with(twoWebsites(), func(f object) { f["about"] = "Kept here for now: " + s }))
	}
	add("refused: a token in an item of a kind the reader does not know", with(twoWebsites(), func(f object) {
		f["items"] = append(f["items"].([]any), object{"kind": "example.unknown", "name": "X", "deep": []any{object{"k": secrets["a GitHub token"]}}})
	}))
	add("refused: a key split by a zero-width space in an item of a kind the reader does not know", with(twoWebsites(), func(f object) {
		f["items"] = append(f["items"].([]any), object{"kind": "example.unknown", "name": "X", "deep": []any{object{"k": secrets["a key split by a zero-width space"]}}})
	}))
	add("refused: a token as a limit's value", with(aFullFile(), func(f object) {
		item(f, 1)["limits"].(object)["code.repository.read"].(object)["repository"] = []any{secrets["a GitHub token"]}
	}))
	add("refused: a credential named twice", with(aFullFile(), func(f object) {
		f["credentials_needed"] = []any{object{"name": "Model sign-in"}, object{"name": "model sign-in"}}
	}))
	add("refused: a credential named by an identifier", with(aFullFile(), func(f object) {
		f["credentials_needed"] = []any{object{"name": identifierOf("a stored credential")}}
	}))
	add("refused: a credential with a member this version does not know", with(aFullFile(), func(f object) {
		f["credentials_needed"] = []any{object{"name": "Model sign-in", "secret": "none"}}
	}))
	seals := map[string]func(s object){
		"a member this version does not know": func(s object) { s["key"] = identifierOf("exporter") },
		"no key event":                        func(s object) { delete(s, "kel_sn") },
		"a key event that is null":            func(s object) { s["kel_sn"] = nil },
		"a key event written as text":         func(s object) { s["kel_sn"] = "0" },
		"a signature at another index":        func(s object) { s["signature"] = "AB" + s["signature"].(string)[2:] },
	}
	for _, name := range sorted(seals) {
		var f object
		_ = json.Unmarshal(compact, &f)
		seals[name](f["seal"].(object))
		add("refused: a seal with "+name, text(t, f))
	}

	// Choices, and the lists they give.
	needs := []string{"code.repository.write", "machine.provide"}
	files := map[string]fileVector{}
	for _, v := range set.Files {
		files[v.Name] = v
	}
	choose := func(name, from string, change func(c *vectorChoice), needs ...string) *Approved {
		v := files[from]
		c := vectorChoice{IdentityAgent: identifierOf("importer"), Proposal: "proposal-0123456789abcdef", Nonce: "nonce-0123456789abcdefghij",
			Items: []vectorPick{{0, []Permission{}}, {1, []Permission{}},
				{2, []Permission{{Capability: "code.repository.write"}, {Capability: "machine.provide"}}}},
			UtilityApps: map[string]string{}, Credentials: map[string]string{}}
		if change != nil {
			change(&c)
		}
		out := approvalVector{Name: name, From: from, Choice: c, NeedsAcknowledging: append([]string{}, needs...)}
		r, err := Read(v.bytes(), optionsOf(t, v))
		if err != nil {
			t.Fatal(err)
		}
		a, err := r.Approve(c.choice(r, v), needing(needs))
		if err != nil {
			out.Refused = CodeOf(err)
		} else {
			out.Bytes, out.Digest = string(a.Bytes()), a.Digest()
		}
		set.Approvals = append(set.Approvals, out)
		return a
	}
	first := choose("three items, the third with both its permissions acknowledged, and the utility app the second names an item of the list", fullFile, nil, needs...)
	choose("the same items chosen in another order give the same list", fullFile, func(c *vectorChoice) {
		c.Items[0], c.Items[2] = c.Items[2], c.Items[0]
		c.Items[0].Acknowledged = []Permission{{Capability: "machine.provide"}, {Capability: "code.repository.write"}}
	}, needs...)
	choose("the utility app a permission names is one already here, by its identifier, and the credential is mapped", fullFile, func(c *vectorChoice) {
		c.Items = c.Items[1:]
		c.UtilityApps = map[string]string{"Board": identifierOf("other")}
		c.Credentials = map[string]string{"Model sign-in": "Shared model sign-in"}
	}, needs...)
	choose("a choice from a sealed file names who sealed it", sealedFullFile, nil, needs...)
	choose("refused: a permission that must be acknowledged is not", fullFile, func(c *vectorChoice) { c.Items[2].Acknowledged = c.Items[2].Acknowledged[:1] }, needs...)
	choose("refused: an acknowledgement of a permission the item does not ask for", fullFile, func(c *vectorChoice) {
		c.Items[1].Acknowledged = []Permission{{Capability: "machine.provide"}}
	}, needs...)
	choose("refused: the utility app a permission names is neither chosen nor mapped", fullFile, func(c *vectorChoice) { c.Items = c.Items[1:] }, needs...)
	choose("refused: the utility app a permission names is both chosen and mapped", fullFile, func(c *vectorChoice) {
		c.UtilityApps = map[string]string{"Board": identifierOf("other")}
	}, needs...)
	choose("refused: a website of the name is chosen where a permission names a utility app", "a website named as a utility app is named does not stand for it", nil, needs...)
	choose("refused: an item that is blocked", "a permission the Identity Agent does not know, and a grant that would already have ended", nil, needs...)
	choose("refused: an item chosen twice", fullFile, func(c *vectorChoice) { c.Items = append(c.Items, vectorPick{1, []Permission{}}) }, needs...)
	choose("refused: a credential mapped that the file does not name", fullFile, func(c *vectorChoice) {
		c.Credentials = map[string]string{"Another sign-in": "Shared model sign-in"}
	}, needs...)
	choose("a choice from a file that carries a seal made for other contents names nobody", changedFullFile, nil, needs...)
	choose("a utility app a field names is an item of the list", fieldNamesFile, nil, needs...)
	choose("a utility app a field names is one already here", fieldNamesFile, func(c *vectorChoice) {
		c.Items = c.Items[2:]
		c.UtilityApps = map[string]string{"Board": identifierOf("other")}
	}, needs...)
	choose("refused: a utility app a field names is neither chosen nor mapped", fieldNamesFile, func(c *vectorChoice) { c.Items = c.Items[2:] }, needs...)
	choose("refused: a utility app mapped twice, under two spellings of one name", fullFile, func(c *vectorChoice) {
		c.Items = c.Items[1:]
		c.UtilityApps = map[string]string{"Board": identifierOf("other"), "BOARD": identifierOf("exporter")}
	}, needs...)
	choose("refused: a credential mapped twice, under two spellings of one name", fullFile, func(c *vectorChoice) {
		c.Credentials = map[string]string{"Model sign-in": "One sign-in", "model SIGN-IN": "Another sign-in"}
	}, needs...)
	choose("refused: a short nonce", fullFile, func(c *vectorChoice) { c.Nonce = "short" }, needs...)

	// Lists a device is handed.
	list := func(name string, raw []byte) {
		v := listVector{Name: name, List: string(raw), NeedsAcknowledging: needs}
		if _, err := ReadApproval(raw, needing(needs)); err != nil {
			v.Refused = CodeOf(err)
		}
		set.Lists = append(set.Lists, v)
	}
	items := func(l object, i int) object { return l["items"].([]any)[i].(object) }
	list("the list of the first choice above", first.Bytes())
	var spaced object
	_ = json.Unmarshal(first.Bytes(), &spaced)
	indented, _ := json.MarshalIndent(spaced, "", " ")
	list("refused: the same list written with spaces", indented)
	edits := map[string]func(l object){
		"a member nobody defined":                                 func(l object) { l["note"] = "approve this" },
		"a member of an item nobody defined":                      func(l object) { items(l, 0)["also"] = true },
		"a member left out":                                       func(l object) { delete(l, "credentials") },
		"a null":                                                  func(l object) { l["utility_apps"] = nil },
		"a seal that holds, by nobody":                            func(l object) { l["source"].(object)["seal"] = "sealed" },
		"a sealer named for a file found unsealed":                func(l object) { l["source"].(object)["sealed_by"] = identifierOf("exporter") },
		"the items out of the file's order":                       func(l object) { l["items"] = []any{items(l, 1), items(l, 0), items(l, 2)} },
		"a limit keyed by nothing":                                func(l object) { items(l, 1)["limits"].(object)[""] = object{"x": []any{"y"}} },
		"an acknowledgement out of the item's order":              func(l object) { items(l, 2)["acknowledged"] = []any{"machine.provide", "code.repository.write"} },
		"an acknowledgement taken away":                           func(l object) { items(l, 2)["acknowledged"] = []any{"code.repository.write"} },
		"a utility app left unbound":                              func(l object) { l["utility_apps"] = []any{} },
		"a utility app a field names that the list does not bind": func(l object) { items(l, 2)["utility_apps"] = []any{"Other board"} },
		"a sealer named for a seal made for other contents": func(l object) {
			l["source"].(object)["seal"], l["source"].(object)["sealed_by"] = "changed", identifierOf("exporter")
		},
		"a utility app that is no item of the list":      func(l object) { l["items"] = l["items"].([]any)[1:] },
		"an existing utility app with no identifier":     func(l object) { l["utility_apps"].([]any)[0].(object)["is"] = "existing" },
		"a change, which this version does not perform":  func(l object) { items(l, 0)["operation"] = "change" },
		"a removal, which this version does not perform": func(l object) { items(l, 0)["operation"] = "remove" },
		"a list of another version":                      func(l object) { l["format"] = "identity-agent-set-up-approval/2" },
		"one name twice":                                 func(l object) { items(l, 2)["name"] = "READER" },
	}
	for _, name := range sorted(edits) {
		list("refused: "+name, edited(t, first, edits[name]))
	}
	return set
}

const (
	fullFile        = "permissions, a permission on a utility app the file names, limits, a grant end, an extension and a credential by name"
	sealedFullFile  = "the same file, sealed"
	changedFullFile = "the same file, sealed, then changed"
	fieldNamesFile  = "a field of an item names a utility app"
)

func TestThePublishedVectorsAreWhatThisPackageMakes(t *testing.T) {
	made := written(t)
	raw, err := json.MarshalIndent(made, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	if contractcheck.Writing(t) {
		if err := os.WriteFile(vectorsPath, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	published, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	// Byte for byte: the file is what this package writes, so no value in it
	// stands unchecked.
	if !bytes.Equal(published, raw) {
		t.Fatalf("%s is not what this package produces. Regenerate it with IA_WRITE_CONTRACTS=1 go test ./setupfile and review the diff: every changed line is a change another implementation has to make.", vectorsPath)
	}
	var set vectorSet
	if err := json.Unmarshal(published, &set); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(set, made) {
		t.Fatal("the published vectors do not read back as they were written")
	}
}

// What the description says of file_hex is true: no string in the published
// vectors, nor any string in a file they hold as text, is in a spelling only
// a secret has.
func TestTheVectorsHoldNoStringJudgedASecret(t *testing.T) {
	raw, err := json.Marshal(written(t))
	if err != nil {
		t.Fatal(err)
	}
	var all any
	if err := json.Unmarshal(raw, &all); err != nil {
		t.Fatal(err)
	}
	var walk func(v any, where string)
	walk = func(v any, where string) {
		switch v := v.(type) {
		case string:
			if where == "file" && holdsSecretShapedText([]byte(v)) || where != "file" && shapeOf(v) == secretShape {
				t.Errorf("a string judged a secret is held as text in a vector's %s", where)
			}
		case []any:
			for _, e := range v {
				walk(e, where)
			}
		case map[string]any:
			for k, e := range v {
				if shapeOf(k) == secretShape {
					t.Error("a member's name in the vectors is judged a secret")
				}
				walk(e, k)
			}
		}
	}
	walk(all, "")
	// And the rule is not idle: some file that is UTF-8 is carried in
	// file_hex for it.
	found := false
	for _, v := range written(t).Files {
		found = found || v.FileHex != "" && utf8.Valid(v.bytes())
	}
	if !found {
		t.Fatal("no file that is UTF-8 is carried in file_hex")
	}
}

func TestTheVectorsHoldEveryRuleTheyAreThereFor(t *testing.T) {
	set := written(t)
	refused, blocks, flags, states, seals := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[State]bool{}, map[SealState]bool{}
	for _, v := range set.Files {
		refused[v.Refused] = true
		seals[v.Seal] = true
		for _, f := range v.Flags {
			flags[f] = true
		}
		if strings.HasPrefix(v.Name, "refused:") != (v.Refused != "") {
			t.Errorf("%s: refused as %q", v.Name, v.Refused)
		}
		for _, it := range v.Items {
			states[it.State] = true
			for _, b := range it.Blocks {
				blocks[b] = true
			}
			for _, f := range it.Flags {
				flags[f] = true
			}
			// One reason to an item, so a checker that gets one rule wrong
			// fails on the item that is there for it.
			if (strings.HasPrefix(v.Name, "items blocked") || strings.HasPrefix(v.Name, "text that is not a name")) && len(it.Blocks) > 1 {
				t.Errorf("%s: %q is blocked for %v", v.Name, it.Name, it.Blocks)
			}
		}
	}
	for _, code := range []string{NotJSON, NotASetUpFile, NewerVersion, SecretShaped, NullValue, BadNumber, UnknownField, BadField, BadSeal, DuplicateName, NameIdentifier} {
		if !refused[code] {
			t.Errorf("no file is refused for %s", code)
		}
	}
	for _, code := range []string{UnknownKind, NotAnObject, UnknownField, UnknownExtension, BadField, BadName, NameIdentifier, DuplicateName, DuplicateItem,
		UnknownPermission, IdentifierShaped, LooksLikeASecret, HiddenCharacter, UnknownCredential, LimitWithoutPermission, GrantEnded} {
		if !blocks[code] {
			t.Errorf("no item is blocked for %s", code)
		}
	}
	for _, code := range []string{NeedsAccessHere, NeedsSetUpHere, IdentifierInText} {
		if !flags[code] {
			t.Errorf("nothing is flagged %s", code)
		}
	}
	for _, s := range []State{Ready, Blocked, NotUnderstood} {
		if !states[s] {
			t.Errorf("no item is %s", s)
		}
	}
	for _, s := range []SealState{Unsealed, Sealed, SealedByAnEarlierKey, Changed, Broken, Unchecked} {
		if !seals[s] {
			t.Errorf("no file's seal is %s", s)
		}
	}
	choices, lists := map[string]bool{}, map[string]bool{}
	for _, a := range set.Approvals {
		choices[a.Refused] = true
		if strings.HasPrefix(a.Name, "refused:") != (a.Refused != "") {
			t.Errorf("%s: refused as %q", a.Name, a.Refused)
		}
	}
	for _, l := range set.Lists {
		lists[l.Refused] = true
		if strings.HasPrefix(l.Name, "refused:") != (l.Refused != "") {
			t.Errorf("%s: refused as %q", l.Name, l.Refused)
		}
	}
	for _, code := range []string{"", BadApproval, NotAcknowledged} {
		if !choices[code] {
			t.Errorf("no choice is refused for %q", code)
		}
	}
	for _, code := range []string{"", BadApproval, NotBuilt, NotAcknowledged} {
		if !lists[code] {
			t.Errorf("no list is refused for %q", code)
		}
	}
	// TooLarge, TooManyItems and TextTooLong are held by this package's own
	// tests: a vector for each would be megabytes of nothing.
}

// An implementation written from docs/set-up-file.md, in another language,
// reads every vector as this one does.
func TestAnIndependentImplementationAgreesWithTheSetUpFileVectors(t *testing.T) {
	contractcheck.IndependentlyWith(t, "../contracts/check_set_up_file_vectors.py", vectorsPath, "blake3")
}
