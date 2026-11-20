package setupfile

import (
	"bytes"
	"encoding/json"
	"unicode"

	"fmt"
	"identity-agent-core/statements"
	"strings"
	"testing"
	"time"
)

func TestAFileTheCoreUnderstandsIsReadInFull(t *testing.T) {
	r := read(t, text(t, twoWebsites()), Options{Registry: NewRegistry()})
	if len(r.Items) != 2 || r.Format != Format || r.MadeAt == "" || r.Contents == "" || r.Seal != nil {
		t.Fatalf("the file was not read in full: %+v", r)
	}
	only(t, r.Items[0], Ready)
	only(t, r.Items[1], Ready)
	w := r.Items[0].Fields.(Website)
	if w.Origin != "https://portal.example" || w.Policy.Mode != ModeInvite || w.Policy.RequiredCredIssuer != Self {
		t.Fatalf("the website was not read as written: %+v", w)
	}
	// A list of members the importer must already keep, and a schema named by
	// its identifier, are told to the person; neither blocks.
	if got := codes(r.Items[0], false); len(got) != 2 || got[0] != NeedsAccessHere || got[1] != NeedsSetUpHere {
		t.Fatalf("the website's flags are %v", got)
	}
	if rows := w.Describe(); len(rows) < 4 || rows[0].Value != w.Origin {
		t.Fatalf("the website is described as %v", rows)
	}
}

func TestAFileWithAFieldThisVersionDoesNotKnowBlocksThatItem(t *testing.T) {
	f := twoWebsites()
	f["items"].([]any)[0].(object)["colour"] = "green"
	f["items"].([]any)[1].(object)["policy"].(object)["required_aal"] = 2
	r := read(t, text(t, f), Options{})
	only(t, r.Items[0], Blocked, UnknownField)
	only(t, r.Items[1], Blocked, UnknownField)
	// The finding says which field by its position among the object's
	// members in sorted order, never by the name the file gave it.
	if r.Items[0].Findings[0].Where != "member 1" || r.Items[1].Findings[0].Where != "policy.member 2" {
		t.Fatalf("the findings do not say which field: %+v %+v", r.Items[0].Findings, r.Items[1].Findings)
	}
	// The same holds under "extensions": a namespace nobody added is a field
	// this version does not know.
	g := aFullFile()
	g["items"].([]any)[1].(object)["extensions"].(object)["example.other"] = object{"x": "y"}
	only(t, read(t, text(t, g), Options{}).Items[1], Blocked, UnknownExtension)
}

func TestAFileOfANewerVersionIsRefused(t *testing.T) {
	f := twoWebsites()
	f["format"] = "identity-agent-set-up/2"
	f["something_version_2_added"] = true
	if got := refusal(t, text(t, f)); got != NewerVersion {
		t.Fatalf("a newer file was refused as %s", got)
	}
	for _, notOne := range []any{"identity-agent-set-up", "identity-agent-set-up/0", "identity-agent-set-up/01", "another-file/1", 1, nil} {
		f := twoWebsites()
		f["format"] = notOne
		if got := refusal(t, text(t, f)); got != NotASetUpFile {
			t.Fatalf("format %v was refused as %s", notOne, got)
		}
	}
}

func TestAKindThisVersionDoesNotKnowIsListedAndSkippedNeverDropped(t *testing.T) {
	// The core alone does not know example.worker.
	r := read(t, text(t, aFullFile()), Options{Registry: NewRegistry()})
	if len(r.Items) != 4 {
		t.Fatalf("%d of 4 items are listed", len(r.Items))
	}
	for _, i := range []int{0, 1, 2} {
		only(t, r.Items[i], NotUnderstood, UnknownKind)
		if r.Items[i].Name == "" || !strings.HasPrefix(r.Items[i].Kind, "example.") || r.Items[i].Rest == "" {
			t.Fatalf("a skipped item is not listed by its kind and name: %+v", r.Items[i])
		}
	}
	only(t, r.Items[3], Ready)
}

func TestAFileHoldingSomethingShapedLikeAKeyIsRefused(t *testing.T) {
	seed := "A" + identifierOf("a seed")[1:] // an Ed25519 seed in CESR is 44 characters under the code A
	for name, secret := range map[string]string{
		"a private key block":   keyShaped("a private key block"),
		"a seed in CESR":        seed,
		"a salt in CESR":        aSaltOf("a salt"),
		"a token":               keyShaped("sk- and 32 letters and digits"),
		"a token after a route": keyShaped("sk- after a route, and 64 hexadecimal"),
		"a token in lower case": keyShaped("sk- and 32 hexadecimal digits"),
		"a mail service key":    keyShaped("a mail service key"),
		"a PGP key block":       keyShaped("a PGP private key block"),
		"a live key":            keyShaped("a live key"),
		"a restricted key":      keyShaped("a restricted live key"),
		"a GitLab token":        keyShaped("a GitLab token"),
		"an npm token":          keyShaped("an npm token"),
		"an age key":            keyShaped("an age key"),
		"a web token":           keyShaped("a JSON Web Token"),
		"a password in a link":  "postgres://reader:hunter2@db.example/handbook",
		// Each is the key with a character in it that is not seen.
		"a key split by a joiner":      keyShaped("an access key split by a joiner"),
		"a token split by a joiner":    keyShaped("sk- with a project, split by a joiner"),
		"a key split by a soft hyphen": keyShaped("an access key split by a soft hyphen"),
	} {
		for _, place := range []func(object, string){
			func(f object, s string) { f["about"] = "Kept here for now: " + s },
			func(f object, s string) { f["items"].([]any)[1].(object)["note"] = s },
			func(f object, s string) {
				f["items"].([]any)[1].(object)["limits"].(object)["code.repository.read"].(object)["repository"] = []any{s}
			},
			// In an item of a kind nobody knows, too: it is skipped, and it is
			// still in a file that would be kept.
			func(f object, s string) {
				f["items"] = append(f["items"].([]any), object{"kind": "example.unknown", "name": "X", "deep": []any{object{"k": s}}})
			},
			func(f object, s string) { f["items"].([]any)[0].(object)[s] = "the secret is a member's name" },
		} {
			f := aFullFile()
			place(f, secret)
			_, err := Read(text(t, f), Options{Registry: withExamples(t)})
			if CodeOf(err) != SecretShaped {
				t.Fatalf("a file holding %s was not refused as holding a secret: %v", name, err)
			}
			// The refusal says where, and never what.
			if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), secret[:12]) {
				t.Fatalf("the refusal repeats the secret: %v", err)
			}
		}
	}
}

func TestANameThatAlreadyAppearsInTheFileIsRefused(t *testing.T) {
	f := aFullFile()
	items := f["items"].([]any)
	// The same name in another case, with space around it and on another kind
	// of item: a person cannot tell the two apart.
	items = append(items, website("public NOTES", "https://other.example", object{"mode": "open"}), aWorker("BOARD", nil))
	f["items"] = items
	r := read(t, text(t, f), Options{})
	only(t, r.Items[0], Ready)
	only(t, r.Items[3], Ready)
	only(t, r.Items[4], Blocked, DuplicateName)
	only(t, r.Items[5], Blocked, DuplicateName)
	// A credential named twice refuses the file: the list is the file's own.
	g := aFullFile()
	g["credentials_needed"] = []any{object{"name": "Model sign-in"}, object{"name": "model sign-in"}}
	if got := refusal(t, text(t, g)); got != DuplicateName {
		t.Fatalf("a credential named twice was refused as %s", got)
	}
}

func nameIs(t *testing.T, name string) Item {
	t.Helper()
	f := twoWebsites()
	f["items"].([]any)[0].(object)["name"] = name
	return read(t, text(t, f), Options{}).Items[0]
}

func TestANameIsWhatAPersonCallsAThing(t *testing.T) {
	for _, n := range writtenNames {
		if it := nameIs(t, n[1]); it.State != Ready || it.Name != n[1] {
			t.Errorf("%s is not taken as a name: %+v", n[0], it.Findings)
		}
	}
	for _, n := range notNames {
		it := nameIs(t, n[1])
		if it.State != Blocked || !it.has(BadName) {
			t.Errorf("%s is taken as a name", n[0])
		}
		// A name that is not a name is not kept: it is text from the file.
		if it.Name != "" {
			t.Errorf("%s is kept as the item's name", n[0])
		}
	}
	for name, want := range map[string]string{
		"":                                 BadName,
		strings.Repeat("n", MaxName+1):     BadName,
		" Padded":                          BadName,
		"Padded ":                          BadName,
		"Two\nlines":                       BadName,
		"a\ttab":                           BadName,
		identifierOf("an asset"):           NameIdentifier,
		"0123456789abcdef0123456789abcdef": NameIdentifier,
	} {
		only(t, nameIs(t, name), Blocked, want)
	}
	only(t, nameIs(t, strings.Repeat("n", MaxName)), Ready)
	// An item with no name, or a name that is not text, is still listed.
	f := twoWebsites()
	delete(f["items"].([]any)[0].(object), "name")
	f["items"].([]any)[1].(object)["name"] = 7
	r := read(t, text(t, f), Options{})
	only(t, r.Items[0], Blocked, BadName)
	only(t, r.Items[1], Blocked, BadName)
}

// Two spellings of the same letters are one name, so neither can stand
// beside the other; two names that differ in a letter are two.
func TestTwoSpellingsOfTheSameLettersAreOneName(t *testing.T) {
	both := func(a, b string) (Item, Item) {
		f := twoWebsites()
		f["items"].([]any)[0].(object)["name"] = a
		f["items"].([]any)[1].(object)["name"] = b
		r := read(t, text(t, f), Options{})
		return r.Items[0], r.Items[1]
	}
	for _, pair := range oneName {
		first, second := both(pair[1], pair[2])
		if !SameName(pair[1], pair[2]) || first.State != Ready || second.State != Blocked || !second.has(DuplicateName) {
			t.Errorf("%s: the two spellings are not one name: %+v", pair[0], second.Findings)
		}
	}
	for _, pair := range twoNames {
		first, second := both(pair[1], pair[2])
		if SameName(pair[1], pair[2]) || first.State != Ready || second.State != Ready {
			t.Errorf("%s: the two are taken for one name", pair[0])
		}
	}
}

func TestTextIsWhatALanguageWrites(t *testing.T) {
	note := func(s string) Item {
		f := aFullFile()
		f["items"].([]any)[1].(object)["note"] = s
		return read(t, text(t, f), Options{}).Items[1]
	}
	for _, n := range append(append([][2]string{}, writtenNames...), writtenText...) {
		if it := note(n[1]); it.State != Ready {
			t.Errorf("%s is not taken as text: %+v", n[0], it.Findings)
		}
	}
	for _, n := range notText {
		if it := note(n[1]); it.State != Blocked || !it.has(HiddenCharacter) {
			t.Errorf("%s is taken as text", n[0])
		}
	}
}

// The Unicode facts are pinned in a published file made from the Unicode
// Character Database, and nothing here reads the toolchain's own tables.
// While the toolchain happens to be at the same version, the pinned facts
// are held to it: the characters seen are those a signed statement takes,
// and case is what the toolchain folds.
func TestThePinnedUnicodeFactsAreThoseOfTheToolchainAtThatVersion(t *testing.T) {
	if pinned().Unicode != "15.0.0" || len(pinned().Seen) == 0 || len(pinned().nfd) == 0 || len(pinned().nfkd) == 0 || len(pinned().compose) == 0 || len(pinned().fold) == 0 {
		t.Fatalf("the pinned Unicode facts are of %q, or empty", pinned().Unicode)
	}
	// Characters assigned after the pinned version are not seen, whatever a
	// later toolchain knows of them.
	for _, later := range []rune{0x1C89, 0x1C8A, 0xA7CB, 0x2FFFF} {
		if seen(later) {
			t.Errorf("U+%04X, assigned after Unicode %s, is seen", later, pinned().Unicode)
		}
	}
	if unicode.Version != pinned().Unicode {
		t.Skipf("the toolchain is at Unicode %s; the facts stay pinned at %s", unicode.Version, pinned().Unicode)
	}
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		if want := r != '\n' && statements.Plain(string(r)); seen(r) != want {
			t.Fatalf("U+%04X: seen as itself is %v here, and %v for a signed statement", r, seen(r), want)
		}
		if isLetter(r) != unicode.IsLetter(r) || isMark(r) != unicode.IsMark(r) {
			t.Fatalf("U+%04X: a letter or a mark here and not to the toolchain, or the other way", r)
		}
		// Simple case folding: two characters fold alike exactly when the
		// toolchain says they are equal without case.
		for f, steps := unicode.SimpleFold(r), 0; f != r && steps < 8; f, steps = unicode.SimpleFold(f), steps+1 {
			fold := func(x rune) rune {
				if to, ok := pinned().fold[x]; ok {
					return to
				}
				return x
			}
			if (fold(r) == fold(f)) != strings.EqualFold(string(r), string(f)) {
				t.Fatalf("U+%04X and U+%04X: folded alike is %v, equal without case is %v", r, f, fold(r) == fold(f), strings.EqualFold(string(r), string(f)))
			}
		}
	}
}

func TestAMemberOfTheFileThisVersionDoesNotKnowRefusesTheFile(t *testing.T) {
	f := twoWebsites()
	f["defaults"] = object{"mode": "open"}
	if got := refusal(t, text(t, f)); got != UnknownField {
		t.Fatalf("refused as %s", got)
	}
}

func TestAFileTwoReadersWouldReadTwoWaysIsRefused(t *testing.T) {
	good := string(text(t, twoWebsites()))
	for name, bad := range map[string]string{
		"a member named twice":       strings.Replace(good, `"about":`, `"about": "one", "about":`, 1),
		"a member named twice, deep": strings.Replace(good, `"mode": "open"`, `"mode": "invite", "mode": "open"`, 1),
		"text after the object":      good + "{}",
		"a byte order mark":          "\xef\xbb\xbf" + good,
		"a list":                     "[" + good + "]",
		"bytes that are not UTF-8":   strings.Replace(good, "two websites", "two \xff websites", 1),
		"half of a surrogate pair":   strings.Replace(good, "two websites", `two \ud800 websites`, 1),
		"nothing":                    "",
		"null":                       "null",
	} {
		if got := refusal(t, []byte(bad)); got != NotJSON {
			t.Fatalf("%s was refused as %s", name, got)
		}
	}
	// A number is a whole number written one way, wherever it is: a kind
	// nobody knows may carry one, and the file's digest is over it.
	for _, n := range []string{"1.5", "1e3", "1.0", "-0", "9007199254740993"} {
		bad := strings.Replace(good, `"about":`, `"items_of_another_kind": `+n+`, "about":`, 1)
		bad = strings.Replace(bad, `"items_of_another_kind": `+n+`, `, "", 1)
		bad = strings.Replace(bad, `"mode": "open"`, `"mode": "open", "weight": `+n, 1)
		if got := refusal(t, []byte(bad)); got != BadNumber {
			t.Fatalf("the number %s was refused as %s", n, got)
		}
	}
}

func TestAFileOverItsBoundsIsRefused(t *testing.T) {
	big := twoWebsites()
	big["about"] = strings.Repeat("a ", MaxAbout)
	if got := refusal(t, text(t, big)); got != BadField {
		t.Fatalf("a long note was refused as %s", got)
	}
	huge := append(bytes.TrimRight(text(t, twoWebsites()), "\n"), bytes.Repeat([]byte(" "), MaxFileBytes)...)
	if got := refusal(t, huge); got != TooLarge {
		t.Fatalf("a file over the size limit was refused as %s", got)
	}
	many := twoWebsites()
	var items []any
	for i := 0; i <= MaxItems; i++ {
		items = append(items, website(fmt.Sprintf("Site %d", i), fmt.Sprintf("https://s%d.example", i), object{"mode": "open"}))
	}
	many["items"] = items
	if got := refusal(t, text(t, many)); got != TooManyItems {
		t.Fatalf("a file of %d items was refused as %s", len(items), got)
	}
	many["items"] = items[:MaxItems]
	if r := read(t, text(t, many), Options{}); len(r.Items) != MaxItems {
		t.Fatal("a file of exactly the most items was not read")
	}
	none := twoWebsites()
	delete(none, "items")
	if got := refusal(t, text(t, none)); got != BadField {
		t.Fatalf("a file with no items was refused as %s", got)
	}
}

func TestWhatEveryItemCarriesIsReadAndHeld(t *testing.T) {
	r := read(t, text(t, aFullFile()), Options{})
	for _, it := range r.Items {
		only(t, it, Ready)
	}
	reader := r.Items[1]
	if len(reader.Permissions) != 2 || reader.Permissions[1].UtilityApp != "Board" || reader.GrantEnd != "2027-06-30T00:00:00Z" ||
		len(reader.Limits["code.repository.read"]["repository"]) != 2 {
		t.Fatalf("the item was not read as written: %+v", reader.Common)
	}
	// It depends on the item it names a permission on, needs the credential
	// it names, and its limit is something this organisation must reach.
	if len(reader.DependsOn) != 1 || reader.DependsOn[0] != "Board" || len(reader.Credentials) != 1 || reader.Extensions["example.labels"] == nil {
		t.Fatalf("what the item refers to was not found: %+v", reader)
	}
	if got := codes(reader, false); len(got) != 1 || got[0] != NeedsAccessHere {
		t.Fatalf("the item's flags are %v", got)
	}

	blocked := func(change func(item object, file object), want string) {
		t.Helper()
		f := aFullFile()
		change(f["items"].([]any)[1].(object), f)
		only(t, read(t, text(t, f), Options{}).Items[1], Blocked, want)
	}
	// A permission never carries an identifier: a utility app is named.
	blocked(func(it, _ object) {
		it["permissions"] = []any{"board.a0123456789abcdef0123456789abcdef.write"}
		delete(it, "limits")
	}, BadField)
	blocked(func(it, _ object) {
		it["permissions"] = []any{"board:a0123456789abcdef0123456789abcdef:write"}
		delete(it, "limits")
	}, BadField)
	blocked(func(it, _ object) {
		it["permissions"] = []any{object{"utility_app": identifierOf("a utility app"), "permission": "write"}}
		delete(it, "limits")
	}, BadField)
	blocked(func(it, _ object) {
		it["permissions"] = []any{object{"utility_app": "Board", "permission": "write", "more": true}}
		delete(it, "limits")
	}, BadField)
	blocked(func(it, _ object) { it["permissions"] = []any{"code.repository.read", "code.repository.read"} }, BadField)
	blocked(func(it, _ object) { it["permissions"] = "code.repository.read"; delete(it, "limits") }, BadField)
	blocked(func(it, _ object) {
		it["limits"] = object{"code.repository.write": object{"repository": []any{"example/site"}}}
	}, LimitWithoutPermission)
	blocked(func(it, _ object) { it["limits"] = object{"code.repository.read": object{"repository": []any{}}} }, BadField)
	blocked(func(it, _ object) { it["limits"] = object{"code.repository.read": object{"repository": []any{7}}} }, BadField)
	blocked(func(it, _ object) { it["grant_end"] = "2027-06-30" }, BadField)
	blocked(func(it, _ object) { it["grant_end"] = "2027-06-30T00:00:00+01:00" }, BadField)
	blocked(func(it, _ object) { it["kind"] = "Example Worker" }, BadField)
	// Text is seen as itself, is not endless, and names nothing by identifier.
	blocked(func(it, _ object) { it["note"] = "Left\u202eright" }, HiddenCharacter)
	blocked(func(it, _ object) { it["title"] = "Ask " + identifierOf("another AI agent") + " first." }, IdentifierShaped)
	blocked(func(it, _ object) { it["title"] = "Its record is 0123456789abcdef0123456789abcdef." }, IdentifierShaped)
	blocked(func(it, _ object) { it["note"] = strings.Repeat("long ", 50) }, BadField)
	// A credential is one the file's own list names.
	blocked(func(it, _ object) { it["credential"] = "Another sign-in" }, UnknownCredential)
	blocked(func(_, f object) { delete(f, "credentials_needed") }, UnknownCredential)

	// What the importing Identity Agent knows, and when it is asked.
	knows := func(p Permission) bool { return p.Capability != "machine.provide" }
	k := read(t, text(t, aFullFile()), Options{KnowsPermission: knows})
	only(t, k.Items[1], Ready)
	only(t, k.Items[2], Blocked, UnknownPermission)
	late := read(t, text(t, aFullFile()), Options{Now: time.Date(2027, 6, 30, 0, 0, 0, 0, time.UTC)})
	only(t, late.Items[1], Blocked, GrantEnded)
	only(t, read(t, text(t, aFullFile()), Options{Now: time.Date(2027, 6, 29, 23, 59, 59, 0, time.UTC)}).Items[1], Ready)

	// Text of several lines is text; an item that is not an object is listed.
	f := aFullFile()
	f["items"].([]any)[1].(object)["note"] = "Line one.\n\tLine two."
	f["items"] = append(f["items"].([]any), "not an item")
	r = read(t, text(t, f), Options{})
	only(t, r.Items[1], Ready)
	only(t, r.Items[4], Blocked, NotAnObject)
}

func TestAWebsiteIsHeldToWhatTheCoreKeepsForOne(t *testing.T) {
	blocked := func(change func(site object), want string) {
		t.Helper()
		f := twoWebsites()
		change(f["items"].([]any)[0].(object))
		only(t, read(t, text(t, f), Options{}).Items[0], Blocked, want)
	}
	for _, origin := range []string{"portal.example", "https://portal.example/", "https://portal.example:443", "http://portal.example:80",
		"https://Portal.example", "https://portal.example/path", "https://user@portal.example", "ftp://portal.example", "https://", ""} {
		blocked(func(s object) { s["origin"] = origin }, BadField)
	}
	for _, origin := range []string{"https://portal.example", "http://portal.example", "https://portal.example:8443", "http://127.0.0.1:8080", "https://[::1]:8443"} {
		f := twoWebsites()
		f["items"].([]any)[0].(object)["origin"] = origin
		only(t, read(t, text(t, f), Options{}).Items[0], Ready)
	}
	blocked(func(s object) { s["policy"].(object)["mode"] = "anyone" }, BadField)
	blocked(func(s object) { delete(s, "policy") }, BadField)
	blocked(func(s object) { s["policy"].(object)["membership_source"] = "The Staff" }, BadField)
	blocked(func(s object) { s["policy"].(object)["required_cred_schema"] = "an employee credential" }, BadField)
	blocked(func(s object) { delete(s["policy"].(object), "required_cred_schema") }, BadField)
	blocked(func(s object) { s["policy"].(object)["required_cred_issuer"] = "the organisation" }, BadField)
	// A website is signed in to; it is granted nothing.
	blocked(func(s object) { s["permissions"] = []any{"code.repository.read"} }, BadField)
	blocked(func(s object) { s["grant_end"] = "2027-06-30T00:00:00Z" }, BadField)
	// An issuer from elsewhere stays, and the person is told.
	f := twoWebsites()
	f["items"].([]any)[0].(object)["policy"].(object)["required_cred_issuer"] = identifierOf("another organisation")
	r := read(t, text(t, f), Options{})
	only(t, r.Items[0], Ready)
	if got := codes(r.Items[0], false); len(got) != 2 || got[0] != NeedsAccessHere {
		t.Fatalf("an issuer from elsewhere is flagged %v", got)
	}
}

// The format defines an AI agent and a utility app, and this version does not
// read them yet: an item of either is listed and skipped, like any kind a
// reader does not yet understand, and never dropped.
func TestAnAIAgentAndAUtilityAppAreKindsThisVersionDoesNotYetUnderstand(t *testing.T) {
	f := twoWebsites()
	f["items"] = append(f["items"].([]any), object{"kind": KindAIAgent, "name": "Reader", "permissions": []any{"code.repository.read"}},
		object{"kind": KindUtilityApp, "name": "Board"})
	r := read(t, text(t, f), Options{})
	if len(r.Items) != 4 {
		t.Fatalf("%d of 4 items are listed", len(r.Items))
	}
	for _, it := range r.Items[2:] {
		only(t, it, NotUnderstood, UnknownKind)
		if it.Name == "" || it.Rest == "" {
			t.Fatalf("the item is not listed by its name: %+v", it)
		}
	}
}

func TestAnAddOnCarriesItsOwnKindsAndFieldsUnderItsOwnName(t *testing.T) {
	r := NewRegistry()
	if got := r.Kinds(); len(got) != 1 || got[0] != KindWebsite {
		t.Fatalf("the core's kinds are %v", got)
	}
	if err := r.AddKind(workerKind{}); err != nil {
		t.Fatal(err)
	}
	if err := r.AddKind(workerKind{}); err == nil {
		t.Fatal("a kind was added twice")
	}
	// One word is kept for the kinds the format itself defines.
	// So are the two the format reserves for itself: an AI agent and a utility
	// app are the format's kinds, and nobody else's.
	for _, name := range []string{"worker", KindAIAgent, KindUtilityApp, "Example.Worker", "example..worker", "", strings.Repeat("a", MaxKind) + ".b"} {
		if err := r.AddKind(named(name)); err == nil {
			t.Fatalf("the kind %q was added", name)
		}
	}
	if err := r.AddKind(named(KindWebsite)); err == nil {
		t.Fatal("the core's own kind was replaced")
	}
	if err := r.AddExtension(labelsExtension{}); err != nil {
		t.Fatal(err)
	}
	if err := r.AddExtension(labelsExtension{}); err == nil {
		t.Fatal("an extension was added twice")
	}
}

type named string

func (n named) Name() string                                   { return string(n) }
func (named) Parse(map[string]json.RawMessage) (Fields, error) { return worker{}, nil }

func TestTextLongerThanAnyTextMayBeBlocksThatItem(t *testing.T) {
	f := aFullFile()
	f["items"].([]any)[1].(object)["note"] = strings.Repeat("long ", MaxText/5+1)
	it := read(t, text(t, f), Options{}).Items[1]
	if it.State != Blocked || !it.has(TextTooLong) {
		t.Fatalf("an item with text over the limit is %s: %+v", it.State, it.Findings)
	}
}

func TestTextIsJudgedByItsShapeWordByWord(t *testing.T) {
	for text, want := range map[string]shape{
		"Reads the handbook and answers questions about it.":                                     plainShape,
		"See https://docs.example/guides/getting-started-with-the-handbook-2":                    plainShape,
		"a-very-long-hyphenated-name-with-2-things-in-it-and-3-more":                             plainShape,
		"getUserAccountBalanceForQuarter2Report":                                                 plainShape,
		"Quarterly-Report-2026-Final-Version-For-The-Board":                                      plainShape,
		"Employee_Handbook_2026_Final_Reviewed_Version.pdf":                                      plainShape,
		"https://news.example/2026/11/20/how-we-rebuilt-the-handbook-for-everyone-in-2026-11-20": plainShape,
		"sk-this-is-a-long-hyphenated-slug":                                                      plainShape,
		"sk-Report-2026-final-version-x":                                                         plainShape,
		"sk-notes-internationalisationguide":                                                     plainShape,
		keyShaped("sk- and 24 letters"):                                                          plainShape,
		"https://user:${DB_PASSWORD}@docs.example":                                               plainShape,
		"https://user:$DB_PASSWORD@docs.example":                                                 plainShape,
		"https://user:{{password}}@docs.example":                                                 plainShape,
		"https://user:{password}@docs.example":                                                   plainShape,
		"https://user:[password]@docs.example":                                                   plainShape,
		"https://user:%s@docs.example":                                                           plainShape,
		"https://user:your-password@docs.example":                                                plainShape,
		"https://user:YOUR_PASSWORD@docs.example":                                                plainShape,
		"postgres://admin:$uperS3cret9@db.example/handbook":                                      secretShape,
		"postgres://admin:%24uperS3cret9@db.example/handbook":                                    secretShape,
		"postgres://admin:{Xk29fj3Lq8@db.example/handbook":                                       secretShape,
		"postgres://admin:<Xk29fj3Lq8@db.example/handbook":                                       secretShape,
		"postgres://admin:[Xk29fj3Lq8@db.example/handbook":                                       secretShape,
		"postgres://admin:%sXk29@db.example/handbook":                                            secretShape,
		"postgres://admin:passwordXk29@db.example/handbook":                                      secretShape,
		"postgres://USER:PASSWORD@HOST/handbook":                                                 plainShape,
		"https://user:pass@docs.example/handbook":                                                plainShape,
		"https://user:<password>@docs.example/handbook":                                          plainShape,
		"mailto:someone:else@docs.example":                                                       plainShape,
		"0A" + strings.Repeat("a", 22):                                                           plainShape,
		"x" + aSaltOf("a salt"):                                                                  plainShape,
		aSaltOf("a salt"):                                                                        secretShape,
		keyShaped("sk- after a route, and 64 hexadecimal"):                                       secretShape,
		"postgres://reader:hunter2@db.example/handbook":                                          secretShape,
		"https://reader@docs.example/handbook":                                                   plainShape,
		"example/handbook":                                                                       plainShape,
		"12345678":                                                                               plainShape,
		identifierOf("an asset"):                                                                 identifierShape,
		aDigest("a document"):                                                                    identifierShape,
		"1AAI" + strings.Repeat("a", 44):                                                         identifierShape,
		"record 0123456789abcdef0123456789abcdef":                                                identifierShape,
		"commit 3f2a9c1b7d4e6f8091a2b3c4d5e6f708192a3b4c":                                        identifierShape,
		"image@sha256:" + strings.Repeat("0f1e2d3c", 8):                                          likelySecretShape,
		"q7Zr2Lm9Xc4Vb1Nn8Kp3Jh6Gf5Ds0Aa7Qw2Er9Ty4Ui":                                            likelySecretShape,
		"https://docs.google.com/document/d/1x7Zr2Lm9Xc4Vb1Nn8Kp3Jh6Gf5Ds0Aa7Qw2Er9Ty4U/edit":    likelySecretShape,
		keyShaped("an access key"):                                                               secretShape,
		keyShaped("a GitHub token"):                                                              secretShape,
		"Bearer " + keyShaped("a JSON Web Token"):                                                secretShape,
		// A character a reader cannot see does not split a key that looks
		// whole on a screen.
		keyShaped("an access key split by a joiner"):       secretShape,
		keyShaped("sk- with a project, split by a joiner"): secretShape,
		keyShaped("an access key split by a soft hyphen"):  secretShape,
		keyShaped("an access key split by two unseen"):     secretShape,
		"co\u00adoperate": plainShape,
	} {
		if got := shapeOf(text); got != want {
			t.Errorf("%q is shaped %d, wanted %d", text, got, want)
		}
	}
}
