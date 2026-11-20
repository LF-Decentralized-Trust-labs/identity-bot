// Package setupfile is the format of the one file an Identity Agent's set-up
// is exported to and proposed from (ADR-088, docs/set-up-file.md): its types,
// the strict reader, the canonical bytes its digest and seal are over, and the
// canonical bytes an owner's approval of a chosen list signs.
//
// Everything here is a pure function. Nothing reads a store, a clock or a
// network: a caller supplies how a sealer's key is found, the permissions the
// importing Identity Agent knows, and the time.
//
// A file gives no authority. Reading one yields a list of items to show a
// person; what is created is decided by the owner's signed approval of the
// items they chose (Approve), and every identity and grant is made new by the
// importing Identity Agent.
//
// The reader drops nothing silently:
//
//   - a file of a newer major version is refused whole;
//   - an item of a kind this reader does not know is listed as not understood
//     and skipped in plain sight;
//   - a field this reader does not know, in an item whose kind it does know,
//     blocks that item;
//   - a key or a token refuses the file.
//
// Nothing a reader says repeats text from the file. A refusal and a finding
// say where and never what, and where is said in the format's own words and
// by position ("member 3"), never by a name the file gave a member. A kind an
// add-on adds says only what it declared it may say.
//
// What an approval authorises is its bytes. Whatever applies an approval
// applies what ReadApproval returns for those bytes, and nothing it was
// handed beside them.
package setupfile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"identity-agent-core/iacrypto"
	"identity-agent-core/internal/strictjson"
	"identity-agent-core/update"
)

// Format names the file and its major version.
const (
	FormatName = "identity-agent-set-up"
	Major      = 1
	Format     = "identity-agent-set-up/1"
)

// The bounds of a file. Each is a starting value this package proposes, except
// MaxName, which is the bound the core already holds an AI agent's name to
// where it lists AI agents to a contact.
const (
	// MaxFileBytes is the largest file read.
	MaxFileBytes = 4 << 20
	// MaxItems is the most items one file holds.
	MaxItems = 500
	// MaxName is the longest name, in bytes of UTF-8.
	MaxName = 64
	// MaxKind is the longest kind or extension namespace, in bytes.
	MaxKind = 64
	// MaxMember is the longest name of a member inside an item, in bytes.
	MaxMember = 128
	// MaxAbout is the longest note about the file, or about a credential, in bytes.
	MaxAbout = 2048
	// MaxText is the longest single string anywhere in an item, in bytes. A
	// kind may hold its own text to less.
	MaxText = 64 << 10
	// MaxPermissions is the most permissions one item asks for.
	MaxPermissions = 200
	// MaxLimitArguments is the most arguments one permission is limited on,
	// and MaxLimitValues the most values one argument is limited to.
	MaxLimitArguments = 32
	MaxLimitValues    = 256
	// MaxLimitValue is the longest limit value, in bytes.
	MaxLimitValue = 256
	// MaxCredentials is the most credentials a file says it will need.
	MaxCredentials = 200
)

// Self stands for the importing organisation's own identifier wherever a field
// names an identity: a file never carries the identifier of the organisation
// it was exported from.
const Self = "self"

// The reasons a file is refused whole. They are stable: another
// implementation refuses the same files for the same reasons.
const (
	TooLarge       = "too_large"
	NotJSON        = "not_json"
	NotASetUpFile  = "not_a_set_up_file"
	NewerVersion   = "newer_version"
	SecretShaped   = "secret_shaped"
	NullValue      = "null_value"
	BadNumber      = "bad_number"
	UnknownField   = "unknown_field"
	BadField       = "bad_field"
	BadSeal        = "bad_seal"
	TooManyItems   = "too_many_items"
	DuplicateName  = "duplicate_name"
	BadName        = "bad_name"
	NameIdentifier = "name_identifier_shaped"
)

// The reasons one item is blocked or not understood, beside those above that
// also apply to an item (UnknownField, BadField, BadName, NameIdentifier,
// DuplicateName).
const (
	UnknownKind            = "unknown_kind"
	NotAnObject            = "not_an_object"
	UnknownExtension       = "unknown_extension"
	UnknownPermission      = "unknown_permission"
	IdentifierShaped       = "identifier_shaped"
	LooksLikeASecret       = "looks_like_a_secret"
	TextTooLong            = "text_too_long"
	HiddenCharacter        = "hidden_character"
	UnknownCredential      = "unknown_credential"
	LimitWithoutPermission = "limit_without_permission"
	GrantEnded             = "grant_ended"
	// DuplicateItem is an item that is, by its kind's own measure, an earlier
	// item of the file again: a second website of one origin.
	DuplicateItem = "duplicate_item"
)

// What an item, or a file, is flagged with: it can be chosen, and the person
// is told.
const (
	// NeedsAccessHere marks a reference to something outside the Identity
	// Agent (a repository, a DNS zone, another identity) that the importing
	// organisation must itself be able to reach.
	NeedsAccessHere = "needs_access_here"
	// NeedsSetUpHere marks a name the importing Identity Agent must already
	// know: a membership source, or a utility app the file does not hold.
	NeedsSetUpHere = "needs_set_up_here"
	// IdentifierInText marks text a person wrote that holds something shaped
	// like an identifier or a digest.
	IdentifierInText = "identifier_in_text"
)

// State is what a reader made of one item.
type State string

const (
	// Ready is an item read in full, which may be chosen.
	Ready State = "ready"
	// Blocked is an item that cannot be chosen, with every reason.
	Blocked State = "blocked"
	// NotUnderstood is an item of a kind this reader does not know: listed,
	// and skipped.
	NotUnderstood State = "not_understood"
)

// Refusal is why a whole file, or a chosen list, is refused. Where names the
// place; nothing in it repeats text from the file.
type Refusal struct {
	Code  string
	Where string
	Text  string
}

func (r *Refusal) Error() string {
	if r.Where == "" {
		return r.Text
	}
	return r.Where + ": " + r.Text
}

// CodeOf is the stable code of a refusal, or "" for nil or any other error.
func CodeOf(err error) string {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Code
	}
	return ""
}

func refuse(code, where, text string, args ...any) *Refusal {
	return &Refusal{Code: code, Where: where, Text: fmt.Sprintf(text, args...)}
}

// Finding is one thing a reader says about an item. One that Blocks stops the
// item from being chosen, and the others are shown beside it.
type Finding struct {
	Code   string `json:"code"`
	Where  string `json:"where,omitempty"`
	Text   string `json:"text"`
	Blocks bool   `json:"blocks"`
}

// Permission is one thing an item may do. It is written either as a capability
// identifier ("code.repository.read"), or, for a permission on a utility app,
// as that utility app's name and the permission's own word, never the utility
// app's identifier, which means nothing to another Identity Agent. It is one
// or the other: a Permission with both set is not a permission.
type Permission struct {
	Capability string
	UtilityApp string
	Word       string
}

type permissionOnApp struct {
	UtilityApp string `json:"utility_app"`
	Permission string `json:"permission"`
}

func (p Permission) onApp() bool { return p.UtilityApp != "" || p.Word != "" }

// MarshalJSON writes a permission in its one spelling, and refuses one that
// has both.
func (p Permission) MarshalJSON() ([]byte, error) {
	switch {
	case !p.onApp():
		return json.Marshal(p.Capability)
	case p.Capability != "" || p.UtilityApp == "" || p.Word == "":
		return nil, errors.New("a permission is a capability, or a permission on a named utility app, and never both")
	}
	return json.Marshal(permissionOnApp{p.UtilityApp, p.Word})
}

// UnmarshalJSON reads either spelling, strictly.
func (p *Permission) UnmarshalJSON(raw []byte) error {
	*p = Permission{}
	if c, ok := Text(raw); ok {
		p.Capability = c
		return nil
	}
	members, ok := strictObject(raw)
	if !ok || len(members) != 2 {
		return errors.New("a permission is a capability, or a utility app's name and the permission on it")
	}
	name, okName := Text(members["utility_app"])
	word, okWord := Text(members["permission"])
	if !okName || !okWord || name == "" || word == "" {
		return errors.New("a permission on a utility app names the utility app and the permission")
	}
	p.UtilityApp, p.Word = name, word
	return nil
}

// String is the permission as a person reads it.
func (p Permission) String() string {
	if p.onApp() {
		return p.Word + " on " + strconv.Quote(p.UtilityApp)
	}
	return p.Capability
}

// key is what two permissions share exactly when they are one permission: a
// utility app is named as names are compared.
func (p Permission) key() string {
	if p.onApp() {
		return "on\x00" + foldName(p.UtilityApp) + "\x00" + p.Word
	}
	return "may\x00" + p.Capability
}

// Limits holds a permission to arguments: capability identifier, then
// argument, then the values that argument may take. It is the shape of an
// asset's grant constraints, with every value a string.
type Limits map[string]map[string][]string

// Common is what every item carries, whatever its kind.
type Common struct {
	Kind        string       `json:"kind"`
	Name        string       `json:"name"`
	Permissions []Permission `json:"permissions"`
	Limits      Limits       `json:"limits"`
	// GrantEnd is when the item's grant ends, as written; "" holds until
	// revoked.
	GrantEnd string `json:"grant_end"`
}

// commonMembers are the item members Common holds. Every other member is the
// kind's own, or "extensions".
var commonMembers = []string{"kind", "name", "permissions", "limits", "grant_end"}

// Credential is a credential the importer will need, by name only. The secret
// is never in a file: the owner maps the name to a credential the importing
// Identity Agent stores, or enters it afterwards.
type Credential struct {
	Name  string `json:"name"`
	About string `json:"about,omitempty"`
}

// Item is one item of a file, as read.
type Item struct {
	// Index is the item's place in the file, from 0.
	Index int
	State State
	Common
	// Fields are the kind's own fields, read by its Kind; nil unless the kind
	// is known and its fields were read.
	Fields Fields
	// Extensions are the item's extension fields, each read by its Extension.
	Extensions map[string]Fields
	// IsUtilityApp is whether the item's kind is a utility app, which a
	// permission on a utility app may name.
	IsUtilityApp bool
	// Rest is the digest of every member of the item that Common does not
	// hold (RestOf). An approval signs it, so the fields a person was shown
	// cannot be changed under their signature.
	Rest string
	// Findings are every reason the item is blocked or not understood, and
	// every flag.
	Findings []Finding
	// UtilityApps are the names of the utility apps the item's permissions
	// are on, and its fields refer to.
	UtilityApps []string
	// NamedByFields are those of UtilityApps the item's own fields name. A
	// chosen list carries them, so that they are bound as a permission's is.
	NamedByFields []string
	// DependsOn are those of UtilityApps that are utility-app items of this
	// file, by their names there. The others must already be in the importing
	// Identity Agent. An item of another kind that happens to have the name is
	// not the utility app.
	DependsOn []string
	// Credentials are the names of the credentials the item will need.
	Credentials []string
}

// Result is a file, read.
type Result struct {
	Format string
	MadeAt string
	About  string
	Items  []Item
	Needs  []Credential
	// Flags are what the person is told about the file itself: text in its
	// notes shaped like an identifier or a secret.
	Flags []Finding
	// Contents is the digest of the file's canonical contents: the file
	// without its seal. It is what a seal is over and what an approval names.
	Contents string
	// Seal is the file's seal as written, or nil for an unsealed file. A seal
	// is checked with CheckSeal; reading a file checks no signature.
	Seal *Seal
}

// Options are what the caller knows that a file cannot say.
type Options struct {
	// Registry holds the kinds and extensions the reader knows; nil knows the
	// kinds this package ships.
	Registry *Registry
	// KnowsPermission says whether the importing Identity Agent knows a
	// permission. One it does not know blocks the item. Nil checks only how a
	// permission is written.
	KnowsPermission func(Permission) bool
	// Now, when set, blocks an item whose grant would already have ended.
	Now time.Time
}

var formatShape = regexp.MustCompile(`^` + FormatName + `/([1-9][0-9]{0,3})$`)

var timeShape = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)

// aTime reads a time in the one spelling a file writes: UTC, to the second,
// in a year from 0001.
func aTime(s string) (time.Time, bool) {
	if !timeShape.MatchString(s) || strings.HasPrefix(s, "0000") {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	return t, err == nil
}

// topMembers are the members a file may hold.
var topMembers = map[string]bool{"format": true, "made_at": true, "about": true, "items": true, "credentials_needed": true, "seal": true}

// Read reads a file strictly. It returns a refusal when the file as a whole
// cannot be read, and otherwise every item, each ready, blocked or not
// understood. The order of the checks is the order of docs/set-up-file.md,
// "What a reader does".
func Read(data []byte, o Options) (*Result, error) {
	if len(data) > MaxFileBytes {
		return nil, refuse(TooLarge, "", "the file is larger than %d bytes", MaxFileBytes)
	}
	top, ok := strictObject(data)
	if !ok {
		return nil, refuse(NotJSON, "", "the file is not one JSON object, read the same way by every reader")
	}
	// The version first, so a newer file is told it is newer and not that it
	// has a field nobody knows.
	format, ok := Text(top["format"])
	m := formatShape.FindStringSubmatch(format)
	if !ok || m == nil {
		return nil, refuse(NotASetUpFile, "format", "the file does not say it is a set-up file")
	}
	if major, _ := strconv.Atoi(m[1]); major > Major {
		return nil, refuse(NewerVersion, "format", "the file is of a newer version than %d, which this reader reads", Major)
	}
	// Secrets before anything is said about the file's members, so that no
	// refusal can carry one. Nothing below the seal is looked at here: a seal
	// holds a signature and a digest, and is read by its own rule.
	without := map[string]json.RawMessage{}
	for k, v := range top {
		if k != "seal" {
			without[k] = v
		}
	}
	whole, _ := json.Marshal(without)
	if r := refusedWhole(decodeAny(whole)); r != nil {
		return nil, r
	}
	for i, k := range sorted(top) {
		if !topMembers[k] {
			return nil, refuse(UnknownField, at("", k, i, nil), "the file has a member this version does not know")
		}
	}
	res := &Result{Format: format}
	if err := res.readTop(top); err != nil {
		return nil, err
	}
	canonical, err := update.CanonicalizeWithoutField(data, "seal")
	if err != nil {
		return nil, refuse(NotJSON, "", "the file cannot be written in its canonical form")
	}
	if res.Contents, err = iacrypto.Blake3QB64(canonical); err != nil {
		return nil, err
	}
	var items []json.RawMessage
	if raw, ok := top["items"]; !ok || json.Unmarshal(raw, &items) != nil || items == nil {
		return nil, refuse(BadField, "items", "a set-up file has a list of items")
	}
	if len(items) > MaxItems {
		return nil, refuse(TooManyItems, "items", "the file has more than %d items", MaxItems)
	}
	reg := o.Registry
	if reg == nil {
		reg = NewRegistry()
	}
	needs := map[string]bool{}
	for _, c := range res.Needs {
		needs[foldName(c.Name)] = true
	}
	names, same := map[string]int{}, map[string]int{}
	for i, raw := range items {
		it, key := readItem(i, raw, reg, o, needs)
		if it.Name != "" && !it.has(BadName) && !it.has(NameIdentifier) {
			if first, taken := names[foldName(it.Name)]; taken {
				it.block(DuplicateName, "name", "item %d of the file already has this name", first)
			} else {
				names[foldName(it.Name)] = i
			}
		}
		if key != "" {
			key = it.Kind + "\x00" + key
			if first, taken := same[key]; taken {
				it.block(DuplicateItem, "", "item %d of the file is this one already", first)
			} else {
				same[key] = i
			}
		}
		res.Items = append(res.Items, it)
	}
	for i := range res.Items {
		it := &res.Items[i]
		for _, n := range it.UtilityApps {
			j, ok := names[foldName(n)]
			if ok && j != i && res.Items[j].IsUtilityApp {
				it.DependsOn = append(it.DependsOn, res.Items[j].Name)
			} else if it.State != NotUnderstood {
				it.flag(NeedsSetUpHere, "permissions", "a utility app this item names is not in the file, so it must already be in this Identity Agent")
			}
		}
	}
	return res, nil
}

// noteFlags flags a note of the file's own for what its text is shaped like.
func (res *Result) noteFlags(text, where string) {
	switch shapeOf(text) {
	case likelySecretShape:
		res.Flags = append(res.Flags, Finding{Code: LooksLikeASecret, Where: where, Text: "something here is long and random enough to be a key or a token"})
	case identifierShape:
		res.Flags = append(res.Flags, Finding{Code: IdentifierInText, Where: where, Text: "this text holds something shaped like an identifier or a digest"})
	}
}

func (res *Result) readTop(top map[string]json.RawMessage) error {
	if raw, ok := top["made_at"]; ok {
		s, isText := Text(raw)
		if _, isTime := aTime(s); !isText || !isTime {
			return refuse(BadField, "made_at", "the time the file was made is a time in UTC to the second")
		}
		res.MadeAt = s
	}
	if raw, ok := top["about"]; ok {
		s, isText := Text(raw)
		if !isText || len(s) > MaxAbout || !shownText(s) {
			return refuse(BadField, "about", "the note about the file is text of at most %d bytes", MaxAbout)
		}
		res.About = s
		res.noteFlags(s, "about")
	}
	if raw, ok := top["credentials_needed"]; ok {
		var each []json.RawMessage
		if json.Unmarshal(raw, &each) != nil || each == nil {
			return refuse(BadField, "credentials_needed", "the credentials needed are a list of names, each with an optional note")
		}
		if len(each) > MaxCredentials {
			return refuse(BadField, "credentials_needed", "the file names more than %d credentials", MaxCredentials)
		}
		seen := map[string]bool{}
		for i, one := range each {
			where := fmt.Sprintf("credentials_needed[%d]", i)
			members, ok := strictObject(one)
			if !ok || OnlyMembers(members, "", "name", "about") != nil {
				return refuse(BadField, where, "a credential is a name and an optional note")
			}
			c := Credential{}
			if c.Name, ok = Text(members["name"]); !ok {
				return refuse(BadName, where+".name", "a credential has a name")
			}
			if code, text := checkName(c.Name); code != "" {
				return refuse(code, where+".name", "%s", text)
			}
			if seen[foldName(c.Name)] {
				return refuse(DuplicateName, where+".name", "the file names this credential twice")
			}
			seen[foldName(c.Name)] = true
			if raw, has := members["about"]; has {
				if c.About, ok = Text(raw); !ok || len(c.About) > MaxAbout || !shownText(c.About) {
					return refuse(BadField, where+".about", "the note about a credential is text of at most %d bytes", MaxAbout)
				}
				res.noteFlags(c.About, where+".about")
			}
			res.Needs = append(res.Needs, c)
		}
	}
	if raw, ok := top["seal"]; ok {
		s, err := readSeal(raw)
		if err != nil {
			return err
		}
		res.Seal = s
	}
	return nil
}

func (it *Item) block(code, where, text string, args ...any) {
	it.Findings = append(it.Findings, Finding{Code: code, Where: where, Text: fmt.Sprintf(text, args...), Blocks: true})
	if it.State != NotUnderstood {
		it.State = Blocked
	}
}

func (it *Item) flag(code, where, text string, args ...any) {
	for _, f := range it.Findings {
		if f.Code == code && f.Where == where {
			return
		}
	}
	it.Findings = append(it.Findings, Finding{Code: code, Where: where, Text: fmt.Sprintf(text, args...)})
}

func (it *Item) has(code string) bool {
	for _, f := range it.Findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

// Declaration is what a kind or an extension says it may say. A reader passes
// on nothing else from one: an add-on is code somebody else wrote, reading a
// file somebody else wrote.
type Declaration struct {
	// Says gives the sentence for each code the kind may find, under the code
	// ("bad_field") or, for one place, the code and the place
	// ("bad_field@note"). A code of the reader's own needs no sentence.
	Says map[string]string
	// Members are the kind's own member names, which a finding may say.
	Members []string
}

// Declarer is a Kind or an Extension that declares what it may say.
type Declarer interface{ Declares() Declaration }

func declared(of any) Declaration {
	if d, ok := of.(Declarer); ok {
		return d.Declares()
	}
	return Declaration{}
}

// sentences are what the reader says for its own codes when a kind finds one
// and declares no sentence of its own.
var sentences = map[string]string{
	UnknownField:     "this version does not know this field",
	BadField:         "this is not written as its kind requires",
	BadName:          "this is not a name",
	NameIdentifier:   "this is shaped like an identifier, where a name is required",
	TextTooLong:      "this text is too long",
	NeedsAccessHere:  "this names something outside the Identity Agent, which this organisation must itself be able to reach",
	NeedsSetUpHere:   "this names something this Identity Agent must already have",
	IdentifierInText: "this text holds something shaped like an identifier or a digest",
}

var aPosition = regexp.MustCompile(`^member [0-9]+$`)

// take adds what a kind or an extension found: its code, when that is one it
// declared or one of the reader's; the sentence declared for that code; and
// the place, when every step of it is a word of the format or of the kind, or
// a position. No text a kind hands back is passed on, so nothing of the file
// can come through a kind.
func (it *Item) take(fs []Finding, d Declaration, under string) {
	for _, f := range fs {
		where := f.Where
		for _, step := range strings.Split(anIndex.ReplaceAllString(where, ""), ".") {
			if where != "" && !ownWords[step] && !slices.Contains(d.Members, step) && !aPosition.MatchString(step) {
				where = ""
			}
		}
		text, ok := d.Says[f.Code+"@"+where]
		if !ok {
			text, ok = d.Says[f.Code]
		}
		if !ok {
			text, ok = sentences[f.Code]
		}
		if !ok {
			f.Code, f.Blocks, text = BadField, true, "the kind found a fault it did not declare"
		}
		switch {
		case under != "" && where != "":
			where = under + "." + where
		case under != "":
			where = under
		}
		it.Findings = append(it.Findings, Finding{Code: f.Code, Where: where, Text: text, Blocks: f.Blocks})
		if f.Blocks && it.State != NotUnderstood {
			it.State = Blocked
		}
	}
}

// failed is why a kind or an extension could not read its fields, as a
// finding for take.
func failed(err error) []Finding {
	return []Finding{{Code: codeOr(err, UnknownField), Where: whereOf(err), Blocks: true}}
}

var kindShape = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`)

// AKind says whether s is written as a kind, or an extension's namespace, is:
// lower-case words of letters, digits and underscores, joined by dots.
func AKind(s string) bool { return len(s) <= MaxKind && kindShape.MatchString(s) }

var capabilityShape = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

var wordShape = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// readItem reads one item. key is what makes the item the same thing as
// another of its kind, by the kind's own measure, or "".
func readItem(i int, raw json.RawMessage, reg *Registry, o Options, needs map[string]bool) (it Item, key string) {
	it = Item{Index: i, State: Ready}
	members, ok := strictObject(raw)
	if !ok {
		it.block(NotAnObject, "", "an item is an object")
		return it, ""
	}
	// The kind and the name before anything else, so an item is always listed
	// by them, whatever else is wrong with it.
	if it.Kind, ok = Text(members["kind"]); !ok || !AKind(it.Kind) {
		it.Kind = ""
		it.block(BadField, "kind", "an item says what kind it is, in lower-case words joined by dots")
	}
	// A name that is not a name is not kept: it is text from the file, of any
	// length, and an item is listed by a name only when it has one.
	if it.Name, ok = Text(members["name"]); !ok {
		it.block(BadName, "name", "an item has a name")
	} else if code, text := checkName(it.Name); code != "" {
		it.Name = ""
		it.block(code, "name", "%s", text)
	}
	own := map[string]json.RawMessage{}
	for k, v := range members {
		if !slices.Contains(commonMembers, k) {
			own[k] = v
		}
	}
	it.Rest = RestOf(own)
	kind := reg.kinds[it.Kind]
	if it.Kind != "" && kind == nil {
		it.State = NotUnderstood
		it.Findings = append(it.Findings, Finding{Code: UnknownKind, Where: "kind", Blocks: true,
			Text: "this version does not know this kind of item, so it is skipped"})
		return it, ""
	}
	it.readCommon(members, o)
	if kind == nil {
		return it, ""
	}
	if u, is := kind.(UtilityAppKind); is {
		it.IsUtilityApp = u.IsUtilityApp()
	}
	exts, hasExts := own["extensions"]
	delete(own, "extensions")
	says := declared(kind)
	names := map[string]bool{}
	for _, m := range says.Members {
		names[m] = true
	}
	fields, err := kind.Parse(own)
	if err == nil && fields == nil {
		err = &FieldError{Code: BadField}
	}
	refs := References{}
	if err != nil {
		it.take(failed(err), says, "")
	} else {
		it.Fields = fields
		it.take(fields.Check(it.Common), says, "")
		refs = fields.Refers()
		if s, is := fields.(interface{ Same() string }); is {
			key = s.Same()
		}
	}
	if hasExts {
		byNamespace, ok := strictObject(exts)
		if !ok {
			it.block(BadField, "extensions", "extensions are an object, one member to a namespace")
		}
		for i, ns := range sorted(byNamespace) {
			ext := reg.extensions[ns]
			if ext == nil {
				it.block(UnknownExtension, at("extensions", ns, i, nil), "this version does not know this extension")
				continue
			}
			// A namespace the reader holds is a word of an add-on it was
			// built with, not of the file.
			under, extSays := "extensions."+ns, declared(ext)
			f, err := ext.Parse(it.Kind, byNamespace[ns])
			if err == nil && f == nil {
				err = &FieldError{Code: BadField}
			}
			if err != nil {
				it.take(failed(err), extSays, under)
				continue
			}
			if it.Extensions == nil {
				it.Extensions = map[string]Fields{}
			}
			it.Extensions[ns] = f
			it.take(f.Check(it.Common), extSays, under)
			r := f.Refers()
			refs.Credentials = append(refs.Credentials, r.Credentials...)
			refs.UtilityApps = append(refs.UtilityApps, r.UtilityApps...)
			for _, p := range r.Identifiers {
				refs.Identifiers = append(refs.Identifiers, under+"."+p)
			}
			for _, p := range r.Prose {
				refs.Prose = append(refs.Prose, under+"."+p)
			}
			names[ns] = true
			for _, m := range extSays.Members {
				names[m] = true
			}
		}
	}
	var named []string
	for _, p := range it.Permissions {
		if p.onApp() {
			named = append(named, p.UtilityApp)
		}
	}
	// A utility app a field names is a name like any other: one that is not a
	// name blocks the item.
	for _, n := range refs.UtilityApps {
		if CheckName(n) != nil {
			it.block(BadField, "", "a field names a utility app by something that is not a name")
		}
	}
	it.NamedByFields = unique(refs.UtilityApps)
	it.UtilityApps = unique(append(named, refs.UtilityApps...))
	it.Credentials = unique(refs.Credentials)
	for _, c := range it.Credentials {
		if !needs[foldName(c)] {
			it.block(UnknownCredential, "", "the item needs a credential the file's list of credentials does not name")
		}
	}
	rules := textRules{identifiers: map[string]bool{}, prose: map[string]bool{}, known: fields != nil, names: names}
	for _, p := range refs.Identifiers {
		rules.identifiers[p] = true
	}
	for _, p := range refs.Prose {
		rules.prose[p] = true
	}
	it.Findings = append(it.Findings, itemText(decodeAny(raw), rules)...)
	for _, f := range it.Findings {
		if f.Blocks {
			it.State = Blocked
		}
	}
	return it, key
}

// readCommon reads the members every item may carry.
func (it *Item) readCommon(members map[string]json.RawMessage, o Options) {
	it.Permissions, it.Limits = []Permission{}, Limits{}
	if raw, ok := members["permissions"]; ok {
		// Each permission is read by itself: it is a string or an object of
		// two members.
		var each []json.RawMessage
		err := json.Unmarshal(raw, &each)
		ps := make([]Permission, len(each))
		for i := range each {
			if err == nil {
				err = ps[i].UnmarshalJSON(each[i])
			}
		}
		if err != nil || each == nil || len(ps) > MaxPermissions {
			it.block(BadField, "permissions", "permissions are a list of at most %d, each a capability or a permission on a named utility app", MaxPermissions)
		} else {
			seen := map[string]bool{}
			for i, p := range ps {
				where := fmt.Sprintf("permissions[%d]", i)
				switch {
				case !p.onApp() && (len(p.Capability) > 128 || !capabilityShape.MatchString(p.Capability) || shapeOf(p.Capability) != plainShape):
					it.block(BadField, where, "a capability is lower-case words joined by dots, and never carries an identifier")
				case p.onApp() && !wordShape.MatchString(p.Word):
					it.block(BadField, where, "a permission on a utility app is one lower-case word")
				case p.onApp() && CheckName(p.UtilityApp) != nil:
					it.block(BadField, where, "a permission on a utility app names the utility app, and never carries its identifier")
				case seen[p.key()]:
					it.block(BadField, where, "the item asks for this permission twice")
				case o.KnowsPermission != nil && !o.KnowsPermission(p):
					it.block(UnknownPermission, where, "this Identity Agent does not know this permission")
				}
				seen[p.key()] = true
			}
			it.Permissions = ps
		}
	}
	if raw, ok := members["limits"]; ok {
		var l Limits
		if err := strictjson.Decode(raw, &l); err != nil || l == nil || hasNull(decodeAny(raw)) {
			it.block(BadField, "limits", "limits are an object: a capability, then an argument, then the values it may take")
		} else {
			it.Limits = l
			it.checkLimits()
		}
	}
	if raw, ok := members["grant_end"]; ok {
		s, isText := Text(raw)
		end, isTime := aTime(s)
		switch {
		case !isText || !isTime:
			it.block(BadField, "grant_end", "the end of a grant is a time in UTC to the second")
		case !o.Now.IsZero() && !end.After(o.Now):
			it.GrantEnd = s
			it.block(GrantEnded, "grant_end", "the grant would already have ended")
		default:
			it.GrantEnd = s
		}
	}
}

func hasNull(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case []any:
		return slices.ContainsFunc(t, hasNull)
	case map[string]any:
		for _, e := range t {
			if hasNull(e) {
				return true
			}
		}
	}
	return false
}

func (it *Item) checkLimits() {
	// A limit is on a capability. A permission on a utility app has none, so
	// it holds no place here: "" is never a capability an item asks for.
	held := map[string]bool{}
	for _, p := range it.Permissions {
		if !p.onApp() {
			held[p.Capability] = true
		}
	}
	for i, capability := range sorted(it.Limits) {
		// A capability and an argument are the file's words: said by position.
		where := at("limits", capability, i, nil)
		arguments := it.Limits[capability]
		switch {
		case !held[capability]:
			it.block(LimitWithoutPermission, where, "a limit is on a capability the item asks for")
			continue
		case len(arguments) == 0 || len(arguments) > MaxLimitArguments:
			it.block(BadField, where, "a limit names 1 to %d arguments", MaxLimitArguments)
			continue
		}
		for j, argument := range sorted(arguments) {
			values := arguments[argument]
			bad := !wordShape.MatchString(argument) || len(values) == 0 || len(values) > MaxLimitValues
			seen := map[string]bool{}
			for _, v := range values {
				bad = bad || v == "" || len(v) > MaxLimitValue || !shownLine(v) || seen[v]
				seen[v] = true
			}
			if bad {
				it.block(BadField, at(where, argument, j, nil), "an argument is one lower-case word, limited to 1 to %d different values of text on one line", MaxLimitValues)
			}
		}
		it.flag(NeedsAccessHere, where, "this limit names something outside the Identity Agent, which this organisation must itself be able to reach")
	}
}

// restLabel begins the bytes an item's rest digest is over, so that digest is
// never the digest of anything else.
const restLabel = "identity-agent-set-up-rest/1\n"

// RestOf is the digest of an item's members other than the five every item
// carries: Blake3-256 over restLabel and then those members as one object in
// canonical JSON. A device that is shown an item's other members before its
// owner approves checks them against this digest first.
func RestOf(own map[string]json.RawMessage) string {
	raw, _ := json.Marshal(own)
	canonical, err := update.Canonicalize(raw)
	if err != nil {
		return ""
	}
	return iacrypto.Blake3QB64Must(append([]byte(restLabel), canonical...))
}

// ownWords are the member names this format itself defines. They are the
// format's words, not a file's, so a refusal or a finding may say them.
var ownWords = func() map[string]bool {
	words := map[string]bool{}
	for _, w := range []string{"format", "made_at", "about", "items", "credentials_needed", "seal", "kind", "name", "permissions", "limits",
		"grant_end", "extensions", "utility_app", "permission", "by", "kel_sn", "contents", "signature",
		"origin", "policy", "mode", "membership_source", "required_cred_schema", "required_cred_issuer"} {
		words[w] = true
	}
	return words
}()

// at is a place inside where: the member's name when it is a word of the
// format, or of the kind (names), and otherwise its position among the
// object's members in sorted order, from 1. A name the file gave a member is
// never said: what a reader says is logged and shown, and a file is written
// by somebody else.
func at(where, name string, position int, names map[string]bool) string {
	said := fmt.Sprintf("member %d", position+1)
	if ownWords[name] || names[name] {
		said = name
	}
	if where == "" {
		return said
	}
	return where + "." + said
}

func sorted[V any](m map[string]V) []string { return slices.Sorted(maps.Keys(m)) }

func unique(in []string) []string {
	seen, out := map[string]bool{}, []string(nil)
	for _, s := range in {
		if !seen[foldName(s)] {
			seen[foldName(s)] = true
			out = append(out, s)
		}
	}
	return out
}

// strictObject reads raw as one JSON object every reader reads the same way
// (no member named twice, valid text, nothing after it), and returns its
// members unread. Numbers and nulls are judged afterwards, wherever they are.
func strictObject(raw []byte) (map[string]json.RawMessage, bool) {
	var probe map[string]any
	if err := strictjson.Decode(raw, &probe); err != nil || probe == nil {
		return nil, false
	}
	var members map[string]json.RawMessage
	return members, json.Unmarshal(raw, &members) == nil
}

func decodeAny(raw []byte) any {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	_ = dec.Decode(&v)
	return v
}
