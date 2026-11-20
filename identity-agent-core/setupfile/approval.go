package setupfile

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"

	"identity-agent-core/iacrypto"
	"identity-agent-core/internal/strictjson"
	"identity-agent-core/update"
)

// ApprovalFormat names the chosen list an owner's approval signs.
const ApprovalFormat = "identity-agent-set-up-approval/1"

// Operation is what one item of a proposal does.
type Operation string

// A proposal's model holds all three operations. This version performs
// creations only: a list that names a change or a removal is refused, and says
// so.
const (
	Create Operation = "create"
	Change Operation = "change"
	Remove Operation = "remove"
)

// The reasons a chosen list is refused.
const (
	// BadApproval is a chosen list that is not written as one is, or a choice
	// no list can be made from.
	BadApproval = "bad_approval"
	// NotBuilt is a chosen list naming an operation this version does not
	// perform.
	NotBuilt = "not_built"
	// NotAcknowledged is a chosen item holding a permission that must be
	// acknowledged, without its acknowledgement.
	NotAcknowledged = "not_acknowledged"
)

// ChosenItem is one item the owner chose, as their approval signs it: which
// item of the file it is, what every item carries in full, the digest of the
// rest, and the permissions the owner acknowledged one by one.
type ChosenItem struct {
	// Item is the item's place in the file, from 0.
	Item        int          `json:"item"`
	Operation   Operation    `json:"operation"`
	Kind        string       `json:"kind"`
	Name        string       `json:"name"`
	Permissions []Permission `json:"permissions"`
	Limits      Limits       `json:"limits"`
	GrantEnd    string       `json:"grant_end"`
	// Rest is Item.Rest: the digest of every member of the item not above.
	Rest string `json:"rest"`
	// Acknowledged are the item's permissions the owner acknowledged
	// expressly, in the order the item asks for them. Being inside the signed
	// bytes, an acknowledgement cannot be added afterwards.
	Acknowledged []Permission `json:"acknowledged"`
	// UtilityApps are the utility apps the item's own fields name, beside
	// those its permissions are on. They are in the signed bytes so that the
	// list binds them too, and a device can see them.
	UtilityApps []string `json:"utility_apps"`
}

// Source is the file a proposal came from, as the approval names it. It is
// filled only from a file that was read and what CheckSeal found of it.
type Source struct {
	// Contents is the digest of the file's contents (Result.Contents).
	Contents string `json:"contents"`
	// Seal is what the file's seal was found to be.
	Seal SealState `json:"seal"`
	// SealedBy is the Identity Agent that sealed these contents: set when
	// Seal is sealed or sealed_by_an_earlier_key, and "" otherwise. A file
	// that carries a seal made for other contents names nobody.
	SealedBy string `json:"sealed_by"`
}

// The two things a utility app a permission names can be.
const (
	// AnItem is a utility app this same list creates.
	AnItem = "item"
	// Existing is a utility app the importing Identity Agent already has,
	// named by its identifier there.
	Existing = "existing"
)

// UtilityAppChoice says which utility app a name in a chosen permission
// means. A name alone would be bound when the list is applied, to whatever
// then has it; this binds it when the owner signs.
type UtilityAppChoice struct {
	Name string `json:"name"`
	// Is is AnItem or Existing.
	Is string `json:"is"`
	// Identifier is the existing utility app's identifier in the importing
	// Identity Agent, and "" for an item of the list.
	Identifier string `json:"identifier"`
}

// CredentialChoice maps a credential the file needs to one the importing
// Identity Agent stores, by that credential's name there, or to "" for one the
// owner will enter afterwards.
type CredentialChoice struct {
	Name string `json:"name"`
	Use  string `json:"use"`
}

// Approval is the chosen list: exactly what an owner's signed approval
// authorises, and nothing else.
type Approval struct {
	Format string `json:"format"`
	// IdentityAgent is the importing Identity Agent, so an approval made for
	// one is refused by another.
	IdentityAgent string `json:"identity_agent"`
	// Proposal is the kept proposal the list was chosen from.
	Proposal string `json:"proposal"`
	// Nonce is made by the Identity Agent when the choice is fixed, and an
	// approval is used once.
	Nonce  string       `json:"nonce"`
	Source Source       `json:"source"`
	Items  []ChosenItem `json:"items"`
	// UtilityApps binds every utility app a chosen permission names, in the
	// order the list first names them.
	UtilityApps []UtilityAppChoice `json:"utility_apps"`
	// Credentials maps every credential a chosen item needs, in the order of
	// the file's own list.
	Credentials []CredentialChoice `json:"credentials"`
}

// Approved is a chosen list that passed every check, with the bytes an
// approval signs. There is no other way to those bytes: they are made only
// after the list was checked, the acknowledgements included.
type Approved struct {
	list  Approval
	bytes []byte
}

// List is the chosen list, as a copy: nothing done to it changes what was
// approved, which is Bytes.
func (a *Approved) List() Approval {
	var out Approval
	raw, _ := json.Marshal(a.list)
	_ = json.Unmarshal(raw, &out)
	return out
}

// Bytes are the canonical bytes of the chosen list: the JSON of the list in
// the JSON Canonicalization Scheme (RFC 8785), by the core's one writer of
// it. They are the body of the request the approver signs.
func (a *Approved) Bytes() []byte { return bytes.Clone(a.bytes) }

// Digest is the digest of Bytes, as the signed-request form carries a body's.
func (a *Approved) Digest() string { return iacrypto.Blake3QB64Must(a.bytes) }

// Pick is one item the owner chose, and the permissions of it they
// acknowledged.
type Pick struct {
	Index        int
	Acknowledged []Permission
}

// Choice is what the owner chose from a file that was read. The Identity Agent
// keeps it with the proposal, and builds the list from the two again when the
// approval arrives.
type Choice struct {
	IdentityAgent string
	Proposal      string
	Nonce         string
	// Seal is what CheckSeal found of this same file.
	Seal  SealOutcome
	Items []Pick
	// UtilityApps maps the name of a utility app a chosen permission is on to
	// the identifier of the utility app the importing Identity Agent already
	// has by that name. A name not here must be a utility-app item of the
	// choice.
	UtilityApps map[string]string
	// Credentials maps a needed credential's name to a stored credential's
	// name. A name not here is entered afterwards.
	Credentials map[string]string
}

// Approve builds the chosen list from a file and a choice, checks it, and
// gives it its bytes. It is how the Identity Agent makes the list when the
// choice is fixed, and how it makes it again, from what it kept, when an
// approval arrives: it never takes a list from the approver.
//
// The list is built in one order, so one choice has one list: the items in
// the file's order, each item's acknowledgements in the order of its
// permissions, the utility apps in the order the list first names them, and
// the credentials in the order of the file's own list.
//
// needsAcknowledging says which permissions the importing Identity Agent has
// the owner acknowledge one by one. It is required: a list is never made
// without that check.
func (r *Result) Approve(c Choice, needsAcknowledging func(Permission) bool) (*Approved, error) {
	bad := func(where, text string, args ...any) (*Approved, error) {
		return nil, refuse(BadApproval, where, text, args...)
	}
	if !c.Seal.of(r) {
		return bad("source", "the seal was checked on another file, or not at all")
	}
	a := Approval{Format: ApprovalFormat, IdentityAgent: c.IdentityAgent, Proposal: c.Proposal, Nonce: c.Nonce,
		Source:      Source{Contents: r.Contents, Seal: c.Seal.state, SealedBy: c.Seal.by},
		Items:       []ChosenItem{},
		UtilityApps: []UtilityAppChoice{}, Credentials: []CredentialChoice{}}
	picks := slices.Clone(c.Items)
	slices.SortStableFunc(picks, func(x, y Pick) int { return x.Index - y.Index })
	needed := map[string]bool{}
	for i, p := range picks {
		if p.Index < 0 || p.Index >= len(r.Items) {
			return bad("items", "the file has no item %d", p.Index)
		}
		if i > 0 && picks[i-1].Index == p.Index {
			return bad("items", "item %d is chosen twice", p.Index)
		}
		it := r.Items[p.Index]
		if it.State != Ready {
			return bad("items", "item %d is %s, and only an item that is ready can be chosen", p.Index, it.State)
		}
		acknowledged := []Permission{}
		for _, held := range it.Permissions {
			if slices.ContainsFunc(p.Acknowledged, func(x Permission) bool { return x.key() == held.key() }) {
				acknowledged = append(acknowledged, held)
			}
		}
		for _, x := range p.Acknowledged {
			if !slices.ContainsFunc(it.Permissions, func(held Permission) bool { return x.key() == held.key() }) {
				return bad("items", "an acknowledgement on item %d is of a permission it does not ask for", p.Index)
			}
		}
		if len(acknowledged) != len(p.Acknowledged) {
			return bad("items", "an acknowledgement on item %d is made twice", p.Index)
		}
		for _, n := range it.Credentials {
			needed[foldName(n)] = true
		}
		named := it.NamedByFields
		if named == nil {
			named = []string{}
		}
		a.Items = append(a.Items, ChosenItem{Item: p.Index, Operation: Create, Kind: it.Kind, Name: it.Name, Permissions: it.Permissions,
			Limits: it.Limits, GrantEnd: it.GrantEnd, Rest: it.Rest, Acknowledged: acknowledged, UtilityApps: named})
	}
	// Which utility app each named permission means: a utility-app item of
	// this list, or one this Identity Agent has, by its identifier. Never
	// whatever happens to have the name when the list is applied.
	// Two keys that are one name would leave which was meant to the order a
	// map happens to be read in: such a choice gives no list.
	mapped := map[string]string{}
	for name, identifier := range c.UtilityApps {
		if _, twice := mapped[foldName(name)]; twice {
			return bad("utility_apps", "a utility app is mapped twice, under two spellings of one name")
		}
		mapped[foldName(name)] = identifier
	}
	for _, name := range a.namedUtilityApps() {
		identifier, existing := mapped[foldName(name)]
		delete(mapped, foldName(name))
		chosen := slices.ContainsFunc(picks, func(p Pick) bool {
			return r.Items[p.Index].IsUtilityApp && SameName(r.Items[p.Index].Name, name)
		})
		switch {
		case chosen && existing:
			return bad("utility_apps", "a utility app an item names is both chosen here and mapped to one already here")
		case chosen:
			a.UtilityApps = append(a.UtilityApps, UtilityAppChoice{Name: name, Is: AnItem})
		case existing:
			a.UtilityApps = append(a.UtilityApps, UtilityAppChoice{Name: name, Is: Existing, Identifier: identifier})
		default:
			return bad("utility_apps", "an item names a utility app, in a permission or in a field of its own, that is neither a chosen utility-app item nor mapped to one already here")
		}
	}
	if len(mapped) != 0 {
		return bad("utility_apps", "a utility app is mapped that no chosen item names")
	}
	uses := map[string]string{}
	for name, use := range c.Credentials {
		if _, twice := uses[foldName(name)]; twice {
			return bad("credentials", "a credential is mapped twice, under two spellings of one name")
		}
		uses[foldName(name)] = use
	}
	for _, need := range r.Needs {
		if needed[foldName(need.Name)] {
			a.Credentials = append(a.Credentials, CredentialChoice{Name: need.Name, Use: uses[foldName(need.Name)]})
		}
		delete(uses, foldName(need.Name))
	}
	if len(uses) != 0 {
		return bad("credentials", "a credential is mapped that the file does not name")
	}
	return a.approved(needsAcknowledging)
}

// namedUtilityApps are the utility apps the list names, each once, in the
// order the list first names them: item by item, those its permissions are on
// and then those its own fields name.
func (a Approval) namedUtilityApps() []string {
	var names []string
	for _, c := range a.Items {
		for _, p := range c.Permissions {
			if p.onApp() {
				names = append(names, p.UtilityApp)
			}
		}
		names = append(names, c.UtilityApps...)
	}
	return unique(names)
}

var (
	proposalShape = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
	nonceShape    = regexp.MustCompile(`^[A-Za-z0-9_-]{22,128}$`)
)

// approved checks the list and, only then, gives it bytes.
func (a Approval) approved(needsAcknowledging func(Permission) bool) (*Approved, error) {
	if needsAcknowledging == nil {
		return nil, refuse(BadApproval, "", "a list is not made without being told which permissions must be acknowledged")
	}
	if err := a.check(needsAcknowledging); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return nil, refuse(BadApproval, "", "the list cannot be written")
	}
	canonical, err := update.Canonicalize(raw)
	if err != nil {
		return nil, refuse(BadApproval, "", "the list cannot be written in its canonical form")
	}
	// The list kept is read back from the bytes, so it shares nothing with
	// the file it was chosen from or with the caller.
	kept := &Approved{bytes: canonical}
	if err := json.Unmarshal(canonical, &kept.list); err != nil {
		return nil, refuse(BadApproval, "", "the list cannot be read back")
	}
	return kept, nil
}

func (a Approval) check(needsAcknowledging func(Permission) bool) error {
	bad := func(where, text string, args ...any) error { return refuse(BadApproval, where, text, args...) }
	verified := a.Source.Seal == Sealed || a.Source.Seal == SealedByAnEarlierKey
	switch {
	case a.Format != ApprovalFormat:
		return bad("format", "this is not a chosen list of version 1")
	case !iacrypto.IsIdentifierQB64(a.IdentityAgent):
		return bad("identity_agent", "the list names the Identity Agent it is for")
	case !proposalShape.MatchString(a.Proposal):
		return bad("proposal", "the list names the proposal it was chosen from")
	case !nonceShape.MatchString(a.Nonce):
		return bad("nonce", "the list carries a nonce of at least 22 characters")
	case !isQB64("E", a.Source.Contents):
		return bad("source.contents", "the list names the digest of the file it came from")
	case !verified && a.Source.Seal != Unsealed && a.Source.Seal != Changed && a.Source.Seal != Broken && a.Source.Seal != Unchecked:
		return bad("source.seal", "the list says what the file's seal was found to be")
	case verified != (a.Source.SealedBy != "") || verified && !iacrypto.IsIdentifierQB64(a.Source.SealedBy):
		return bad("source.sealed_by", "the list names who sealed the file when its seal holds over these contents, and nobody otherwise")
	case len(a.Items) == 0 || len(a.Items) > MaxItems:
		return bad("items", "the list holds 1 to %d items", MaxItems)
	case a.UtilityApps == nil || a.Credentials == nil:
		return bad("", "the list writes its utility apps and credentials even when it has none")
	}
	names := map[string]bool{}
	for i, c := range a.Items {
		where := fmt.Sprintf("items[%d]", i)
		switch c.Operation {
		case Create:
		case Change, Remove:
			return refuse(NotBuilt, where, "this version performs creations only: it does not %s", c.Operation)
		default:
			return bad(where, "an item is created, changed or removed")
		}
		if c.Item < 0 || i > 0 && a.Items[i-1].Item >= c.Item {
			return bad(where, "the items are in the file's order, each once")
		}
		if c.Permissions == nil || c.Limits == nil || c.Acknowledged == nil || c.UtilityApps == nil {
			return bad(where, "an item writes its permissions, limits, acknowledgements and utility apps even when it has none")
		}
		for n, name := range c.UtilityApps {
			if CheckName(name) != nil || slices.ContainsFunc(c.UtilityApps[:n], func(x string) bool { return SameName(x, name) }) {
				return bad(where, "the utility apps an item's fields name are names, each once")
			}
		}
		for _, p := range slices.Concat(c.Permissions, c.Acknowledged) {
			if p.onApp() && (p.Capability != "" || p.UtilityApp == "" || p.Word == "") {
				return bad(where, "a permission is a capability, or a permission on a named utility app, and never both")
			}
		}
		// An item of a chosen list is held to what a file's item is held to,
		// by the same reader.
		probe := Item{State: Ready, Common: Common{Kind: c.Kind, Name: c.Name}}
		limits, _ := json.Marshal(c.Limits)
		permissions, _ := json.Marshal(c.Permissions)
		members := map[string]json.RawMessage{"permissions": permissions, "limits": limits}
		if c.GrantEnd != "" {
			members["grant_end"], _ = json.Marshal(c.GrantEnd)
		}
		probe.readCommon(members, Options{})
		code, _ := checkName(c.Name)
		switch {
		case !AKind(c.Kind) || code != "":
			return bad(where, "an item names its kind and its name")
		case probe.State != Ready:
			return bad(where, "%s", probe.Findings[0].Text)
		case names[foldName(c.Name)]:
			return bad(where, "the list names this item twice")
		case !isQB64("E", c.Rest):
			return bad(where, "an item carries the digest of the rest of it")
		}
		names[foldName(c.Name)] = true
		// The acknowledgements are some of the permissions, in their order.
		next := 0
		for _, p := range c.Acknowledged {
			for next < len(c.Permissions) && c.Permissions[next].key() != p.key() {
				next++
			}
			if next == len(c.Permissions) {
				return bad(where, "an acknowledgement is of a permission the item asks for, made once, in the order the item asks")
			}
			next++
		}
		for _, p := range c.Permissions {
			needs := needsAcknowledging(p)
			has := slices.ContainsFunc(c.Acknowledged, func(x Permission) bool { return x.key() == p.key() })
			if needs && !has {
				return refuse(NotAcknowledged, where, "a permission of this item must be acknowledged before the item can be approved")
			}
		}
	}
	named := a.namedUtilityApps()
	if len(named) != len(a.UtilityApps) {
		return bad("utility_apps", "the list says which utility app each named permission means, once each")
	}
	for i, u := range a.UtilityApps {
		where := fmt.Sprintf("utility_apps[%d]", i)
		switch {
		case u.Name != named[i]:
			return bad(where, "the utility apps are those the permissions name, in the order the list first names them")
		case u.Is == AnItem && (u.Identifier != "" || !names[foldName(u.Name)]):
			return bad(where, "a utility app that is an item of the list is one of its items, and carries no identifier")
		case u.Is == Existing && (!iacrypto.IsIdentifierQB64(u.Identifier) || names[foldName(u.Name)]):
			return bad(where, "a utility app already here is named by its identifier, and is not also an item of the list")
		case u.Is != AnItem && u.Is != Existing:
			return bad(where, "a utility app is an item of the list or one already here")
		}
	}
	seen := map[string]bool{}
	for i, c := range a.Credentials {
		if CheckName(c.Name) != nil || c.Use != "" && CheckName(c.Use) != nil || seen[foldName(c.Name)] {
			return bad(fmt.Sprintf("credentials[%d]", i), "a credential is named once, and mapped to a stored credential's name or to nothing")
		}
		seen[foldName(c.Name)] = true
	}
	return nil
}

// approvalDoc is a chosen list as it is read: its permissions unread, since
// each is a string or an object.
type approvalDoc struct {
	Format        string `json:"format"`
	IdentityAgent string `json:"identity_agent"`
	Proposal      string `json:"proposal"`
	Nonce         string `json:"nonce"`
	Source        Source `json:"source"`
	Items         []struct {
		Item         int               `json:"item"`
		Operation    Operation         `json:"operation"`
		Kind         string            `json:"kind"`
		Name         string            `json:"name"`
		Permissions  []json.RawMessage `json:"permissions"`
		Limits       Limits            `json:"limits"`
		GrantEnd     string            `json:"grant_end"`
		Rest         string            `json:"rest"`
		Acknowledged []json.RawMessage `json:"acknowledged"`
		UtilityApps  []string          `json:"utility_apps"`
	} `json:"items"`
	UtilityApps []UtilityAppChoice `json:"utility_apps"`
	Credentials []CredentialChoice `json:"credentials"`
}

// ReadApproval reads the bytes of a chosen list, as a device that is asked to
// approve one receives them, and holds them to every rule a list is held to:
// every member present and no other, no null, and the bytes exactly the
// list's canonical bytes, so that what is shown is what is signed.
//
// It cannot check an item's other members, which the list carries only as a
// digest. A device that shows them fetches them and checks each against the
// item's rest digest (RestOf) first.
func ReadApproval(raw []byte, needsAcknowledging func(Permission) bool) (*Approved, error) {
	notOne := refuse(BadApproval, "", "this is not a chosen list, written the one way a list is")
	var doc approvalDoc
	if len(raw) > MaxFileBytes || strictjson.Decode(raw, &doc) != nil || hasNull(decodeAny(raw)) {
		return nil, notOne
	}
	a := Approval{Format: doc.Format, IdentityAgent: doc.IdentityAgent, Proposal: doc.Proposal, Nonce: doc.Nonce, Source: doc.Source,
		UtilityApps: doc.UtilityApps, Credentials: doc.Credentials}
	for _, d := range doc.Items {
		c := ChosenItem{Item: d.Item, Operation: d.Operation, Kind: d.Kind, Name: d.Name, Limits: d.Limits, GrantEnd: d.GrantEnd, Rest: d.Rest, UtilityApps: d.UtilityApps}
		for list, into := range map[*[]json.RawMessage]*[]Permission{&d.Permissions: &c.Permissions, &d.Acknowledged: &c.Acknowledged} {
			if *list != nil {
				*into = []Permission{}
			}
			for _, one := range *list {
				var p Permission
				if p.UnmarshalJSON(one) != nil {
					return nil, notOne
				}
				*into = append(*into, p)
			}
		}
		a.Items = append(a.Items, c)
	}
	approved, err := a.approved(needsAcknowledging)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(approved.bytes, raw) {
		return nil, notOne
	}
	return approved, nil
}
