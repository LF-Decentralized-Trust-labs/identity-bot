package setupfile

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"identity-agent-core/iacrypto"
	"identity-agent-core/update"
)

// needsAcknowledging stands for the importing Identity Agent's own list of
// permissions an owner acknowledges one by one.
func needsAcknowledging(p Permission) bool {
	return p.Capability == "code.repository.write" || p.Capability == "machine.provide"
}

func nothingNeedsAcknowledging(Permission) bool { return false }

// aChoice chooses the board, the reader and the builder of the full file, with
// the builder's two permissions acknowledged.
func aChoice(r *Result) Choice {
	return Choice{
		IdentityAgent: identifierOf("importer"),
		Proposal:      "proposal-0123456789abcdef", Nonce: "nonce-0123456789abcdefghij",
		Seal: r.CheckSeal(keysOf()),
		Items: []Pick{{Index: 0}, {Index: 1},
			{Index: 2, Acknowledged: []Permission{{Capability: "code.repository.write"}, {Capability: "machine.provide"}}}},
	}
}

func approved(t testing.TB, f object, change func(c *Choice)) *Approved {
	t.Helper()
	r := read(t, text(t, f), Options{})
	c := aChoice(r)
	if change != nil {
		change(&c)
	}
	a, err := r.Approve(c, needsAcknowledging)
	if err != nil {
		t.Fatalf("the choice gave no list: %v", err)
	}
	return a
}

func notApproved(t testing.TB, f object, change func(c *Choice)) error {
	t.Helper()
	r := read(t, text(t, f), Options{})
	c := aChoice(r)
	change(&c)
	a, err := r.Approve(c, needsAcknowledging)
	if err == nil {
		t.Fatalf("the choice gave a list: %s", a.Bytes())
	}
	return err
}

func TestTheBytesAnApprovalSignsChangeWhenAnyChosenItemChanges(t *testing.T) {
	base := approved(t, aFullFile(), nil)
	// Built again from the same file and choice, they are the same bytes, in
	// canonical JSON, with the digest a signed request carries.
	if again := approved(t, aFullFile(), nil); !bytes.Equal(base.Bytes(), again.Bytes()) {
		t.Fatal("the same choice gave two different lists")
	}
	if canonical, err := update.Canonicalize(base.Bytes()); err != nil || !bytes.Equal(canonical, base.Bytes()) {
		t.Fatal("the bytes are not canonical JSON")
	}
	if base.Digest() != iacrypto.Blake3QB64Must(base.Bytes()) {
		t.Fatalf("the digest is %q", base.Digest())
	}
	seen := map[string]string{string(base.Bytes()): "the list as chosen"}
	differs := func(name string, a *Approved) {
		t.Helper()
		if was, same := seen[string(a.Bytes())]; same {
			t.Fatalf("%s signs the same bytes as %s", name, was)
		}
		seen[string(a.Bytes())] = name
	}
	// Anything in the file about a chosen item: what every item carries, and,
	// through the digest of the rest, each field of its kind and extensions.
	for name, change := range map[string]func(reader object){
		"its name":                          func(it object) { it["name"] = "Reader 2" },
		"a permission added":                func(it object) { it["permissions"] = append(it["permissions"].([]any), "code.issue.read") },
		"a permission taken away":           func(it object) { it["permissions"] = it["permissions"].([]any)[:1] },
		"what it may do on the utility app": func(it object) { it["permissions"].([]any)[1].(object)["permission"] = "admin" },
		"one more value in a limit": func(it object) {
			it["limits"].(object)["code.repository.read"].(object)["repository"] = []any{"example/handbook", "example/site", "example/secret"}
		},
		"a limit taken away":      func(it object) { delete(it, "limits") },
		"its grant ending later":  func(it object) { it["grant_end"] = "2028-06-30T00:00:00Z" },
		"its grant never ending":  func(it object) { delete(it, "grant_end") },
		"a field of its kind":     func(it object) { it["note"] = "Reads two repositories and writes to the board!" },
		"the credential it needs": func(it object) { delete(it, "credential") },
		"a field of an extension": func(it object) { it["extensions"].(object)["example.labels"].(object)["label"] = "code" },
		"an extension taken away": func(it object) { delete(it, "extensions") },
	} {
		f := aFullFile()
		change(f["items"].([]any)[1].(object))
		differs("a file with "+name+" changed", approved(t, f, nil))
	}
	// And anything about the choice itself.
	for name, change := range map[string]func(c *Choice){
		"another Identity Agent": func(c *Choice) { c.IdentityAgent = identifierOf("other") },
		"another proposal":       func(c *Choice) { c.Proposal = "proposal-fedcba9876543210" },
		"another nonce":          func(c *Choice) { c.Nonce = "nonce-zyxwvutsrqponmlkjihg" },
		"one item fewer":         func(c *Choice) { c.Items = c.Items[:2] },
		"a credential mapped":    func(c *Choice) { c.Credentials = map[string]string{"Model sign-in": "Shared model sign-in"} },
		"the utility app being one already here": func(c *Choice) {
			c.Items = c.Items[1:]
			c.UtilityApps = map[string]string{"Board": identifierOf("a utility app here")}
		},
	} {
		differs("a choice with "+name, approved(t, aFullFile(), change))
	}
	// An item nobody chose is not in the bytes, so changing it changes nothing
	// but the file's own digest, which the bytes name.
	f := aFullFile()
	f["items"].([]any)[3].(object)["origin"] = "https://other.example"
	other := approved(t, f, nil)
	if other.List().Source.Contents == base.List().Source.Contents {
		t.Fatal("the file changed and its digest did not")
	}
	swapped := strings.Replace(string(other.Bytes()), other.List().Source.Contents, base.List().Source.Contents, 1)
	if swapped != string(base.Bytes()) {
		t.Fatal("an item that was not chosen is in the bytes")
	}
}

func TestAnApprovalWithoutAnAcknowledgementItNeedsIsRefused(t *testing.T) {
	err := notApproved(t, aFullFile(), func(c *Choice) { c.Items[2].Acknowledged = c.Items[2].Acknowledged[:1] })
	if CodeOf(err) != NotAcknowledged {
		t.Fatalf("a list missing an acknowledgement was not refused for it: %v", err)
	}
	// The acknowledgement is inside the signed bytes, so it cannot be added to
	// a list somebody already signed.
	r := read(t, text(t, aFullFile()), Options{})
	c := aChoice(r)
	c.Items[2].Acknowledged = c.Items[2].Acknowledged[:1]
	without, err := r.Approve(c, nothingNeedsAcknowledging)
	if err != nil || bytes.Equal(without.Bytes(), approved(t, aFullFile(), nil).Bytes()) {
		t.Fatalf("an acknowledgement is not in the bytes: %v", err)
	}
	// There are no bytes without the check: a list is not made by a caller
	// that does not say what needs acknowledging, and a list a device is
	// handed is held to the same.
	if _, err := r.Approve(aChoice(r), nil); CodeOf(err) != BadApproval {
		t.Fatalf("a list was made with no acknowledgement check: %v", err)
	}
	if _, err := ReadApproval(without.Bytes(), nil); CodeOf(err) != BadApproval {
		t.Fatalf("a list was read with no acknowledgement check: %v", err)
	}
	if _, err := ReadApproval(without.Bytes(), needsAcknowledging); CodeOf(err) != NotAcknowledged {
		t.Fatalf("a list missing an acknowledgement was read: %v", err)
	}
	// An acknowledgement of something the item does not ask for, or made
	// twice, is not one.
	for _, extra := range []Permission{{Capability: "dns.record.write"}, {Capability: "code.repository.write"}} {
		err := notApproved(t, aFullFile(), func(c *Choice) { c.Items[2].Acknowledged = append(c.Items[2].Acknowledged, extra) })
		if CodeOf(err) != BadApproval {
			t.Fatalf("an acknowledgement of %s was taken: %v", extra, err)
		}
	}
}

func TestAChosenListIsBuiltInOneOrderWhateverOrderItWasChosenIn(t *testing.T) {
	base := approved(t, aFullFile(), nil)
	turned := approved(t, aFullFile(), func(c *Choice) {
		c.Items[0], c.Items[2] = c.Items[2], c.Items[0]
		a := c.Items[0].Acknowledged
		a[0], a[1] = a[1], a[0]
	})
	if !bytes.Equal(base.Bytes(), turned.Bytes()) {
		t.Fatal("the same items chosen in another order gave another list")
	}
	for i, it := range base.List().Items {
		if it.Item != i {
			t.Fatalf("item %d of the list is item %d of the file", i, it.Item)
		}
	}
	if err := notApproved(t, aFullFile(), func(c *Choice) { c.Items = append(c.Items, Pick{Index: 1}) }); CodeOf(err) != BadApproval {
		t.Fatalf("an item chosen twice: %v", err)
	}
}

// A name in a permission would otherwise be bound when the list is applied, to
// whatever then has the name. The list says which utility app is meant.
func TestAPermissionOnAUtilityAppIsBoundToOneUtilityAppWhenTheListIsSigned(t *testing.T) {
	base := approved(t, aFullFile(), nil)
	if u := base.List().UtilityApps; len(u) != 1 || u[0] != (UtilityAppChoice{Name: "Board", Is: AnItem}) {
		t.Fatalf("the list binds %+v", u)
	}
	here := approved(t, aFullFile(), func(c *Choice) {
		c.Items = c.Items[1:]
		c.UtilityApps = map[string]string{"board": identifierOf("a utility app here")}
	})
	if u := here.List().UtilityApps; len(u) != 1 || u[0] != (UtilityAppChoice{Name: "Board", Is: Existing, Identifier: identifierOf("a utility app here")}) {
		t.Fatalf("the list binds %+v", u)
	}
	for name, change := range map[string]func(c *Choice){
		"neither chosen nor mapped": func(c *Choice) { c.Items = c.Items[1:] },
		"both chosen and mapped":    func(c *Choice) { c.UtilityApps = map[string]string{"Board": identifierOf("a utility app here")} },
		"mapped to something not an identifier": func(c *Choice) {
			c.Items = c.Items[1:]
			c.UtilityApps = map[string]string{"Board": "the board"}
		},
		"a utility app mapped that nothing names": func(c *Choice) { c.UtilityApps = map[string]string{"Other": identifierOf("a utility app here")} },
	} {
		if err := notApproved(t, aFullFile(), change); CodeOf(err) != BadApproval {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// An item of another kind that has the name is not the utility app: a
	// website called "Board" does not satisfy a permission on the utility app
	// "Board", in the reading or in the list.
	f := aFullFile()
	f["items"].([]any)[0] = website("Board", "https://board.example", object{"mode": "open"})
	r := read(t, text(t, f), Options{})
	only(t, r.Items[1], Ready)
	if r.Items[1].DependsOn != nil || len(r.Items[1].UtilityApps) != 1 || !r.Items[1].has(NeedsSetUpHere) {
		t.Fatalf("a website was taken for the utility app a permission names: %+v", r.Items[1])
	}
	if _, err := r.Approve(aChoice(r), needsAcknowledging); CodeOf(err) != BadApproval {
		t.Fatalf("a list bound a permission to a website: %v", err)
	}
	full := read(t, text(t, aFullFile()), Options{})
	if d := full.Items[1].DependsOn; len(d) != 1 || d[0] != "Board" || full.Items[1].has(NeedsSetUpHere) {
		t.Fatalf("the reader depends on %v", d)
	}
}

// The source of a list is only what was found of that file. Nothing lets a
// caller write "sealed" beside a file that had no seal.
func TestTheSourceOfAListIsOnlyWhatWasFoundOfThatFile(t *testing.T) {
	plain := approved(t, aFullFile(), nil)
	if s := plain.List().Source; s.Seal != Unsealed || s.SealedBy != "" {
		t.Fatalf("an unsealed file's list says %+v", s)
	}
	sealedFile := sealed(t, aFullFile(), "exporter", "exporter")
	r := read(t, sealedFile, Options{})
	// A file that carries a seal made for other contents names nobody.
	other := read(t, bytes.Replace(sealedFile, []byte("Builder"), []byte("Bilder"), 1), Options{})
	if a, err := other.Approve(aChoice(other), needsAcknowledging); err != nil || a.List().Source != (Source{Contents: other.Contents, Seal: Changed}) {
		t.Fatalf("a file with a seal made for other contents gives %+v, %v", a, err)
	}
	for state, resolve := range map[SealState]Resolver{Sealed: keysOf(), SealedByAnEarlierKey: keysOf("exporter"), Unchecked: nil} {
		c := aChoice(r)
		c.Seal = r.CheckSeal(resolve)
		a, err := r.Approve(c, needsAcknowledging)
		if err != nil {
			t.Fatal(err)
		}
		wantBy := identifierOf("exporter")
		if state == Unchecked {
			wantBy = ""
		}
		if a.List().Source.Seal != state || a.List().Source.SealedBy != wantBy {
			t.Fatalf("a file found %s gives a list that says %+v", state, a.List().Source)
		}
	}
	// What was found of another file, or of none, makes no list.
	if err := notApproved(t, aFullFile(), func(c *Choice) { c.Seal = r.CheckSeal(keysOf()) }); CodeOf(err) != BadApproval {
		t.Fatalf("a sealed file's outcome was used for an unsealed one: %v", err)
	}
	if err := notApproved(t, aFullFile(), func(c *Choice) { c.Seal = SealOutcome{} }); CodeOf(err) != BadApproval {
		t.Fatalf("a list was made with no seal check: %v", err)
	}
}

// Two keys that are one name would leave which was meant to the order a map
// is read in, and one choice would have two lists.
func TestAChoiceThatMapsOneNameTwiceGivesNoList(t *testing.T) {
	for range 20 {
		err := notApproved(t, aFullFile(), func(c *Choice) {
			c.Items = c.Items[1:]
			c.UtilityApps = map[string]string{"Board": identifierOf("a utility app here"), "BOARD": identifierOf("other")}
		})
		if CodeOf(err) != BadApproval {
			t.Fatalf("a utility app mapped under two spellings: %v", err)
		}
		err = notApproved(t, aFullFile(), func(c *Choice) {
			c.Credentials = map[string]string{"Model sign-in": "One sign-in", "model SIGN-IN": "Another sign-in"}
		})
		if CodeOf(err) != BadApproval {
			t.Fatalf("a credential mapped under two spellings: %v", err)
		}
	}
}

// A kind may say that a field of its own names a utility app. The list
// carries that name and binds it, exactly as it binds a permission's.
func TestAUtilityAppAFieldNamesIsBoundInTheListAsAPermissionsIs(t *testing.T) {
	f := aFullFile()
	f["items"].([]any)[2].(object)["reports_to"] = "Board"
	r := read(t, text(t, f), Options{})
	if b := r.Items[2]; len(b.NamedByFields) != 1 || len(b.DependsOn) != 1 || b.DependsOn[0] != "Board" {
		t.Fatalf("the field's utility app was not found: %+v", b)
	}
	// Chosen with the utility app, it is an item of the list.
	c := aChoice(r)
	a, err := r.Approve(c, needsAcknowledging)
	if err != nil {
		t.Fatal(err)
	}
	if got := a.List().Items[2].UtilityApps; len(got) != 1 || got[0] != "Board" {
		t.Fatalf("the list does not carry what the field names: %v", got)
	}
	// Chosen alone, the name must be bound: it is never left to be found when
	// the list is applied.
	c.Items = c.Items[2:]
	if _, err := r.Approve(c, needsAcknowledging); CodeOf(err) != BadApproval {
		t.Fatalf("a field's utility app was left unbound: %v", err)
	}
	c.UtilityApps = map[string]string{"Board": identifierOf("a utility app here")}
	a, err = r.Approve(c, needsAcknowledging)
	if err != nil {
		t.Fatal(err)
	}
	if u := a.List().UtilityApps; len(u) != 1 || u[0] != (UtilityAppChoice{Name: "Board", Is: Existing, Identifier: identifierOf("a utility app here")}) {
		t.Fatalf("the list binds %+v", u)
	}
	// A device handed the list sees the name, and a list without it is not
	// the list.
	_, err = ReadApproval(edited(t, a, func(l object) { l["items"].([]any)[0].(object)["utility_apps"] = []any{} }), needsAcknowledging)
	if CodeOf(err) != BadApproval {
		t.Fatalf("a list with a field's utility app taken out was read: %v", err)
	}
}

// What was approved is its bytes. The list handed out is a copy, and shares
// nothing with the file it was chosen from.
func TestWhatWasApprovedCannotBeChangedThroughTheListOrTheFile(t *testing.T) {
	r := read(t, text(t, aFullFile()), Options{})
	a, err := r.Approve(aChoice(r), needsAcknowledging)
	if err != nil {
		t.Fatal(err)
	}
	before := string(a.Bytes())
	list := a.List()
	list.Items[1].Permissions[0].Capability = "machine.provide"
	list.Items[1].Limits["code.repository.read"]["repository"][0] = "example/secret"
	r.Items[1].Permissions[0].Capability = "machine.provide"
	r.Items[1].Limits["code.repository.read"]["repository"][0] = "example/secret"
	again, _ := json.Marshal(a.List())
	if string(a.Bytes()) != before || strings.Contains(string(again), "example/secret") || a.List().Items[1].Permissions[0].Capability != "code.repository.read" {
		t.Fatal("what was approved was changed after it was approved")
	}
	// What an applier applies is what the bytes read back as.
	back, err := ReadApproval(a.Bytes(), needsAcknowledging)
	if err != nil || !reflect.DeepEqual(back.List(), a.List()) {
		t.Fatalf("the bytes do not read back as the list: %v", err)
	}
}

func TestOnlyAnItemThatIsReadyCanBeChosen(t *testing.T) {
	f := aFullFile()
	f["items"].([]any)[2].(object)["colour"] = "green"
	if err := notApproved(t, f, func(*Choice) {}); CodeOf(err) != BadApproval {
		t.Fatalf("a blocked item was chosen: %v", err)
	}
	if err := notApproved(t, aFullFile(), func(c *Choice) { c.Items = append(c.Items, Pick{Index: 9}) }); CodeOf(err) != BadApproval {
		t.Fatalf("an item the file does not have was chosen: %v", err)
	}
	if err := notApproved(t, aFullFile(), func(c *Choice) { c.Items = nil }); CodeOf(err) != BadApproval {
		t.Fatalf("nothing was chosen: %v", err)
	}
	// Nor can one of a kind the reader does not know: the reader as shipped
	// does not know the example kinds.
	core := read(t, text(t, aFullFile()), Options{Registry: NewRegistry()})
	c := aChoice(core)
	c.Items = []Pick{{Index: 1}}
	if _, err := core.Approve(c, needsAcknowledging); CodeOf(err) != BadApproval {
		t.Fatalf("an item that was not understood was chosen: %v", err)
	}
}

// edited is the list's bytes with one thing changed, written canonically
// again, as somebody who altered a list on its way to a device would send it.
func edited(t testing.TB, a *Approved, change func(list object)) []byte {
	t.Helper()
	var list object
	if err := json.Unmarshal(a.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	change(list)
	raw, _ := json.Marshal(list)
	canonical, err := update.Canonicalize(raw)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func TestAListADeviceIsHandedIsReadStrictly(t *testing.T) {
	a := approved(t, aFullFile(), nil)
	back, err := ReadApproval(a.Bytes(), needsAcknowledging)
	if err != nil || !bytes.Equal(back.Bytes(), a.Bytes()) {
		t.Fatalf("the bytes do not read back as the list they were made from: %v", err)
	}
	items := func(l object, i int) object { return l["items"].([]any)[i].(object) }
	for name, change := range map[string]func(l object){
		"a member nobody defined":            func(l object) { l["note"] = "approve this" },
		"a member of an item nobody defined": func(l object) { items(l, 0)["also"] = true },
		"a member left out":                  func(l object) { delete(l, "credentials") },
		"a null":                             func(l object) { l["utility_apps"] = nil },
		"another format":                     func(l object) { l["format"] = "identity-agent-set-up-approval/2" },
		"no Identity Agent":                  func(l object) { l["identity_agent"] = "this one" },
		"a short nonce":                      func(l object) { l["nonce"] = "short" },
		"no proposal":                        func(l object) { l["proposal"] = "" },
		"a seal state nobody defined":        func(l object) { l["source"].(object)["seal"] = "trusted" },
		"sealed by nobody":                   func(l object) { l["source"].(object)["seal"] = "sealed" },
		"a sealer named for a broken seal": func(l object) {
			l["source"] = object{"contents": a.List().Source.Contents, "seal": "broken", "sealed_by": identifierOf("exporter")}
		},
		"a sealer named for a file with no seal": func(l object) { l["source"].(object)["sealed_by"] = identifierOf("exporter") },
		"no items":                               func(l object) { l["items"] = []any{} },
		"the items out of the file's order":      func(l object) { l["items"] = []any{items(l, 1), items(l, 0), items(l, 2)} },
		"one item twice":                         func(l object) { items(l, 1)["item"] = 0 },
		"one name twice":                         func(l object) { items(l, 2)["name"] = "READER" },
		"a name that is an identifier":           func(l object) { items(l, 0)["name"] = identifierOf("an asset") },
		"a limit on a permission not held": func(l object) {
			items(l, 0)["limits"] = object{"dns.record.write": object{"zone": []any{"example.org"}}}
		},
		"a limit keyed by nothing":       func(l object) { items(l, 1)["limits"].(object)[""] = object{"x": []any{"y"}} },
		"a grant end that is not a time": func(l object) { items(l, 0)["grant_end"] = "next year" },
		"no digest of the rest":          func(l object) { items(l, 0)["rest"] = "" },
		"an acknowledgement out of order": func(l object) {
			items(l, 2)["acknowledged"] = []any{"machine.provide", "code.repository.write"}
		},
		"a utility app left unbound":     func(l object) { l["utility_apps"] = []any{} },
		"a utility app bound to nothing": func(l object) { l["utility_apps"].([]any)[0].(object)["is"] = "whichever" },
		"an item of the list with an identifier": func(l object) {
			l["utility_apps"].([]any)[0].(object)["identifier"] = identifierOf("a utility app here")
		},
		"an existing utility app with no identifier": func(l object) { l["utility_apps"].([]any)[0].(object)["is"] = "existing" },
		"a utility app that is no item of the list":  func(l object) { l["items"] = l["items"].([]any)[1:] },
		"a credential named twice": func(l object) {
			l["credentials"] = append(l["credentials"].([]any), object{"name": "model sign-in", "use": ""})
		},
		"a credential mapped to a secret": func(l object) {
			l["credentials"].([]any)[0].(object)["use"] = keyShaped("sk- and 32 letters and digits")
		},
	} {
		if _, err := ReadApproval(edited(t, a, change), needsAcknowledging); CodeOf(err) != BadApproval {
			t.Fatalf("a list with %s was read: %v", name, err)
		}
	}
	// The same list in another spelling is not the list: what is shown is
	// what is signed, byte for byte.
	var list object
	_ = json.Unmarshal(a.Bytes(), &list)
	spaced, _ := json.MarshalIndent(list, "", " ")
	if _, err := ReadApproval(spaced, needsAcknowledging); CodeOf(err) != BadApproval {
		t.Fatalf("a list written another way was read: %v", err)
	}
}

func TestThisVersionPerformsCreationsOnlyAndSaysSo(t *testing.T) {
	a := approved(t, aFullFile(), nil)
	for _, op := range []string{"change", "remove"} {
		_, err := ReadApproval(edited(t, a, func(l object) { l["items"].([]any)[0].(object)["operation"] = op }), needsAcknowledging)
		if CodeOf(err) != NotBuilt || !strings.Contains(err.Error(), "creations only") {
			t.Fatalf("a list that would %s was not refused as not built: %v", op, err)
		}
	}
	_, err := ReadApproval(edited(t, a, func(l object) { l["items"].([]any)[0].(object)["operation"] = "replace" }), needsAcknowledging)
	if CodeOf(err) != BadApproval {
		t.Fatalf("an operation nobody defined was not refused: %v", err)
	}
}

// A permission is a capability or a permission on a utility app. One with
// both set would be signed as one and held as the other.
func TestAPermissionThatIsBothThingsIsNeither(t *testing.T) {
	both := Permission{Capability: "code.repository.read", UtilityApp: "Board", Word: "write"}
	if _, err := json.Marshal(both); err == nil {
		t.Fatal("a permission with both spellings was written")
	}
	a := approved(t, aFullFile(), nil).List()
	a.Items[1].Permissions = []Permission{both}
	if _, err := a.approved(needsAcknowledging); CodeOf(err) != BadApproval {
		t.Fatalf("a list holding one was approved: %v", err)
	}
	for _, half := range []Permission{{UtilityApp: "Board"}, {Word: "write"}} {
		if _, err := json.Marshal(half); err == nil {
			t.Fatalf("half a permission was written: %+v", half)
		}
	}
}
