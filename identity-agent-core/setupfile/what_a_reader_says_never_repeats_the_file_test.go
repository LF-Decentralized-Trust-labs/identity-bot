package setupfile

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// said is everything a reader says of a file: the refusal, or every finding.
func everythingSaid(r *Result, err error) string {
	if err != nil {
		var ref *Refusal
		errors.As(err, &ref)
		return err.Error() + "\n" + ref.Where + "\n" + ref.Text
	}
	var b strings.Builder
	for _, f := range r.Flags {
		fmt.Fprintln(&b, f.Where, f.Text)
	}
	for _, it := range r.Items {
		for _, f := range it.Findings {
			fmt.Fprintln(&b, f.Where, f.Text)
		}
	}
	return b.String()
}

// What a reader says is logged and shown. A member's name comes from the
// file, so it is said only when it is a short plain word.
func TestWhatAReaderSaysNeverRepeatsTextFromTheFile(t *testing.T) {
	token := keyShaped("a GitHub token")
	long := strings.Repeat("a long member name\nwith a line of its own ", 30000)
	odd := "turned\u202earound"
	likely := "q7Zr2Lm9Xc4Vb1Nn8Kp3Jh6Gf5Ds0Aa7Qw2Er9Ty4Ui"
	places := map[string]func(f object, name string){
		"a member of the file":        func(f object, name string) { f[name] = true },
		"a member of an item":         func(f object, name string) { f["items"].([]any)[1].(object)[name] = true },
		"a member of a kind's object": func(f object, name string) { f["items"].([]any)[3].(object)["policy"].(object)[name] = true },
		"an extension's namespace":    func(f object, name string) { f["items"].([]any)[1].(object)["extensions"].(object)[name] = object{} },
		"a member of an extension": func(f object, name string) {
			f["items"].([]any)[1].(object)["extensions"].(object)["example.labels"].(object)[name] = "x"
		},
		"a capability of a limit": func(f object, name string) {
			f["items"].([]any)[1].(object)["limits"].(object)[name] = object{"x": []any{"y"}}
		},
		"an argument of a limit": func(f object, name string) {
			f["items"].([]any)[1].(object)["limits"].(object)["code.repository.read"].(object)[name] = []any{"y"}
		},
	}
	for place, put := range places {
		for what, name := range map[string]string{"a token": token, "a megabyte with line breaks": long, "a hidden character": odd, "what may be a secret": likely} {
			f := aFullFile()
			put(f, name)
			r, err := Read(text(t, f), Options{Registry: withExamples(t)})
			all := everythingSaid(r, err)
			if strings.Contains(all, name) || strings.Contains(all, name[:8]) || len(all) > 20000 {
				t.Fatalf("%s named by %s: the reader says it back (%d bytes): %.300q", place, what, len(all), all)
			}
			if what == "a token" && CodeOf(err) != SecretShaped {
				t.Fatalf("%s named by a token: refused as %q, not for the token", place, CodeOf(err))
			}
		}
	}
	// Nor is a short plain name said: it may be a password as well as a
	// word. The place is said by position, and by the format's own words.
	f := twoWebsites()
	f["hunter2"] = true
	f["items"].([]any)[0].(object)["policy"].(object)["hunter2"] = true
	if _, err := Read(text(t, f), Options{}); strings.Contains(err.Error(), "hunter2") || !strings.Contains(err.Error(), "member 3") {
		t.Fatalf("a member of the file is said by its name, or not by its place: %v", err)
	}
	delete(f, "hunter2")
	r, err := Read(text(t, f), Options{})
	if all := everythingSaid(r, err); strings.Contains(all, "hunter2") || !strings.Contains(all, "policy.member 1") {
		t.Fatalf("a member of an item is said by its name, or not by its place: %s", all)
	}
	// Nor does a value come back: an origin, a secret, a number.
	g := aFullFile()
	g["items"].([]any)[3].(object)["origin"] = "https://Not-An-Origin.example/with/a/path"
	g["items"].([]any)[1].(object)["title"] = likely
	if all := everythingSaid(Read(text(t, g), Options{Registry: withExamples(t)})); strings.Contains(all, "Not-An-Origin") || strings.Contains(all, likely) {
		t.Fatalf("a value is said back: %s", all)
	}
	h := twoWebsites()
	h["format"] = "identity-agent-set-up/9999"
	if _, err := Read(text(t, h), Options{}); strings.Contains(err.Error(), "9999") {
		t.Fatalf("the file's version is said back: %v", err)
	}
}

// What a kind or an extension says is an add-on's words, held to the same.
type talkative struct{ worker }

func (talkative) Check(Common) []Finding {
	return []Finding{
		{Code: BadField, Where: "hunter2", Text: "the file says hunter2", Blocks: true},
		{Code: "a_code_it_never_declared", Where: "policy.hunter2", Text: "hunter2"},
		{Code: BadField, Where: strings.Repeat("w", 400), Text: "said\u202eback", Blocks: true}}
}

type talkativeKind struct{ nothing bool }

func (talkativeKind) Name() string { return "example.talkative" }
func (k talkativeKind) Parse(map[string]json.RawMessage) (Fields, error) {
	if k.nothing {
		return nil, nil
	}
	return talkative{}, nil
}

func TestWhatAnAddOnSaysIsHeldToWhatAnyFindingIs(t *testing.T) {
	for _, kind := range []talkativeKind{{}, {nothing: true}} {
		reg := NewRegistry()
		if err := reg.AddKind(kind); err != nil {
			t.Fatal(err)
		}
		f := twoWebsites()
		f["items"] = []any{object{"kind": "example.talkative", "name": "Talker"}}
		// A kind that reads nothing and reports no error is a kind that
		// failed: the item is blocked, and nothing panics.
		r := read(t, text(t, f), Options{Registry: reg})
		only(t, r.Items[0], Blocked, BadField)
		// A kind's words are never passed on, short and plain or not: only a
		// code it declared or the reader's own, the reader's sentence for it,
		// and a place made of the format's words.
		if all := everythingSaid(r, nil); strings.Contains(all, "hunter2") || strings.Contains(all, "www") || strings.Contains(all, "\u202e") {
			t.Fatalf("an add-on's words were passed on as they came: %q", all)
		}
	}
}

// null is never a member's value. A lenient reader takes it for an empty
// string, for nothing, or for zero, each in its own way.
func TestNullIsNeverAValue(t *testing.T) {
	item := func(f object, i int) object { return f["items"].([]any)[i].(object) }
	for name, put := range map[string]func(f object){
		"the note":            func(f object) { f["about"] = nil },
		"the time":            func(f object) { f["made_at"] = nil },
		"the items":           func(f object) { f["items"] = nil },
		"an item":             func(f object) { f["items"] = append(f["items"].([]any), nil) },
		"the credentials":     func(f object) { f["credentials_needed"] = nil },
		"a credential's note": func(f object) { f["credentials_needed"] = []any{object{"name": "Model sign-in", "about": nil}} },
		"a kind":              func(f object) { item(f, 1)["kind"] = nil },
		"permissions":         func(f object) { item(f, 1)["permissions"] = nil },
		"a permission":        func(f object) { item(f, 1)["permissions"] = []any{nil} },
		"limits":              func(f object) { item(f, 1)["limits"] = nil },
		"a limit's values":    func(f object) { item(f, 1)["limits"].(object)["code.repository.read"].(object)["repository"] = nil },
		"a limit's value": func(f object) {
			item(f, 1)["limits"].(object)["code.repository.read"].(object)["repository"] = []any{nil}
		},
		"a grant end":         func(f object) { item(f, 1)["grant_end"] = nil },
		"extensions":          func(f object) { item(f, 1)["extensions"] = nil },
		"an extension":        func(f object) { item(f, 1)["extensions"].(object)["example.labels"] = nil },
		"a kind's own text":   func(f object) { item(f, 1)["note"] = nil },
		"a website's origin":  func(f object) { item(f, 3)["origin"] = nil },
		"a website's policy":  func(f object) { item(f, 3)["policy"] = nil },
		"a website's mode":    func(f object) { item(f, 3)["policy"].(object)["mode"] = nil },
		"a membership source": func(f object) { item(f, 3)["policy"].(object)["membership_source"] = nil },
		"a required schema":   func(f object) { item(f, 3)["policy"].(object)["required_cred_schema"] = nil },
		"a required issuer":   func(f object) { item(f, 3)["policy"].(object)["required_cred_issuer"] = nil },
	} {
		f := aFullFile()
		put(f)
		if got := refusal(t, text(t, f)); got != NullValue {
			t.Fatalf("null as %s was refused as %s", name, got)
		}
	}
	f := aFullFile()
	f["format"] = nil
	if got := refusal(t, text(t, f)); got != NotASetUpFile {
		t.Fatalf("a null format was refused as %s", got)
	}
	// The helper a kind reads text with takes only text.
	for _, notText := range []string{`null`, `7`, `true`, `["a"]`, `{}`, ``} {
		if s, ok := Text(json.RawMessage(notText)); ok {
			t.Fatalf("%s was read as the text %q", notText, s)
		}
	}
	if s, ok := Text(json.RawMessage(`"a\u00e9"`)); !ok || s != "a\u00e9" {
		t.Fatalf("text was read as %q, %v", s, ok)
	}
}

// A limit is on a capability. A permission on a utility app is not one, and
// leaves no opening for a limit keyed by nothing.
func TestALimitKeyedByNothingIsNeverHeld(t *testing.T) {
	f := aFullFile()
	f["items"].([]any)[1].(object)["limits"].(object)[""] = object{"repository": []any{"example/site"}}
	r := read(t, text(t, f), Options{})
	only(t, r.Items[1], Blocked, LimitWithoutPermission)
}

// A key or a token refuses the file. What only may be one blocks its item,
// and text that only looks odd is text.
func TestWhatMayBeASecretBlocksOneItemAndNeverTheFile(t *testing.T) {
	for name, s := range map[string]string{
		"64 hexadecimal characters": strings.Repeat("0f1e2d3c", 8),
		"an image by its digest":    "image@sha256:" + strings.Repeat("0f1e2d3c", 8),
		"a long random run":         "q7Zr2Lm9Xc4Vb1Nn8Kp3Jh6Gf5Ds0Aa7Qw2Er9Ty4Ui",
	} {
		for place, put := range map[string]func(f object){
			"prose": func(f object) { f["items"].([]any)[1].(object)["note"] = s },
			"text":  func(f object) { f["items"].([]any)[1].(object)["title"] = s },
			"a limit's value": func(f object) {
				f["items"].([]any)[1].(object)["limits"].(object)["code.repository.read"].(object)["repository"] = []any{s}
			},
		} {
			f := aFullFile()
			put(f)
			r := read(t, text(t, f), Options{})
			only(t, r.Items[1], Blocked, LooksLikeASecret)
			only(t, r.Items[2], Ready)
			if strings.Contains(everythingSaid(r, nil), s[len(s)-20:]) {
				t.Fatalf("%s in %s is said back", name, place)
			}
		}
		// In a note about the file it is flagged, and the file is read.
		f := aFullFile()
		f["about"] = "Kept here: " + s
		r := read(t, text(t, f), Options{})
		if len(r.Flags) != 1 || r.Flags[0].Code != LooksLikeASecret || r.Flags[0].Blocks {
			t.Fatalf("%s in the file's note is flagged %+v", name, r.Flags)
		}
	}
	for _, fine := range []string{
		"Quarterly-Report-2026-Final-Version-For-The-Board",
		"Employee_Handbook_2026_Final_Reviewed_Version.pdf",
		"https://news.example/2026/11/20/how-we-rebuilt-the-handbook-for-everyone-in-2026-11-20",
		"sk-this-is-a-long-hyphenated-slug",
	} {
		for _, member := range []string{"note", "title"} {
			f := aFullFile()
			f["items"].([]any)[1].(object)[member] = fine
			only(t, read(t, text(t, f), Options{}).Items[1], Ready)
		}
	}
	// In prose, a commit or a record number is flagged and does not block.
	for _, id := range []string{"3f2a9c1b7d4e6f8091a2b3c4d5e6f708192a3b4c", "0123456789abcdef0123456789abcdef", identifierOf("another AI agent")} {
		f := aFullFile()
		f["items"].([]any)[1].(object)["note"] = "Start from " + id + "."
		it := read(t, text(t, f), Options{}).Items[1]
		only(t, it, Ready)
		if !it.has(IdentifierInText) {
			t.Fatalf("an identifier in prose is not flagged: %+v", it.Findings)
		}
	}
}

func TestTwoWebsitesOfOneOriginAreOneWebsiteTwice(t *testing.T) {
	f := twoWebsites()
	f["items"] = append(f["items"].([]any), website("The portal again", "https://portal.example", object{"mode": "open"}))
	r := read(t, text(t, f), Options{})
	only(t, r.Items[0], Ready)
	only(t, r.Items[2], Blocked, DuplicateItem)
}
