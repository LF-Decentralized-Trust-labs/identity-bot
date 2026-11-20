package setupfile

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"identity-agent-core/endpointrecord"
	"identity-agent-core/iacrypto"
)

// Row is one labelled line of what an item is, as a person is shown it.
type Row struct{ Label, Value string }

// References are what an item's own fields refer to outside themselves.
type References struct {
	// Credentials are the names of the credentials the item will need, each
	// of which the file's list of credentials must name.
	Credentials []string
	// UtilityApps are the names of the utility apps the item's own fields
	// name. A chosen list carries them, and binds each to one utility app, as
	// it does a permission's.
	UtilityApps []string
	// Identifiers are the members, as paths from the kind's own fields
	// ("policy.required_cred_issuer"), that hold an identifier from elsewhere.
	// Such a member holds "", "self" or an identifier and nothing else, and an
	// identifier there is flagged. Text shaped like an identifier anywhere
	// else blocks the item.
	Identifiers []string
	// Prose are the members, as paths, that hold text a person wrote for a
	// reader: instructions, a note. Text shaped like an identifier there (a
	// commit, a record number) is flagged and does not block. Text that may
	// be a secret blocks wherever it is.
	Prose []string
}

// Fields are a kind's own fields, or an extension's, once read.
type Fields interface {
	// Check says what is wrong with the fields, or worth telling the person,
	// given what every item carries: for each, a code and a place. The words
	// shown are the ones the kind declared for that code (Declarer), never
	// words made here, so no text of the file reaches a person through a kind.
	Check(c Common) []Finding
	// Describe is the fields as a person is shown them. Text from the file is
	// shown as text from the file, never interpreted.
	Describe() []Row
	// Refers is what the fields refer to outside themselves.
	Refers() References
}

// Kind reads the items of one kind. This package ships the kinds published
// in docs/set-up-file.md; an add-on holds its own and adds them to a Registry.
// A kind that finds faults of its own declares what it may say (Declarer).
type Kind interface {
	// Name is the kind, as an item writes it.
	Name() string
	// Parse reads the kind's own members strictly: every member of the item
	// but those every item carries and "extensions". A member it does not know
	// is an error (a FieldError with the code UnknownField), which blocks the
	// item; it never drops one.
	Parse(own map[string]json.RawMessage) (Fields, error)
}

// UtilityAppKind is a Kind that may say its items are utility apps, which a
// permission on a utility app may name. A permission never resolves to an item
// of any other kind, whatever that item is called.
type UtilityAppKind interface {
	Kind
	IsUtilityApp() bool
}

// A kind's Fields may also say what makes two items of the kind the same
// thing, by a method Same() string: a website's origin. Of two items of a kind
// with one such key, the later is blocked.

// Extension reads one namespace of an item's "extensions": fields an add-on
// carries on an item of a kind that is not its own.
type Extension interface {
	// Namespace is the member of "extensions" this reads.
	Namespace() string
	// Parse reads the namespace's value on an item of the kind given, as
	// strictly as a Kind reads its own.
	Parse(kind string, raw json.RawMessage) (Fields, error)
}

// FieldError is why a kind or an extension could not read a field.
type FieldError struct {
	Code  string
	Where string
	Text  string
}

func (e *FieldError) Error() string { return e.Text }

func codeOr(err error, otherwise string) string {
	var f *FieldError
	if errors.As(err, &f) && f.Code != "" {
		return f.Code
	}
	return otherwise
}

func whereOf(err error) string {
	var f *FieldError
	if errors.As(err, &f) {
		return f.Where
	}
	return ""
}

// Members reads raw as an object holding only the members allowed, and says
// which member it does not know. It is how a kind refuses a field it does not
// know instead of dropping it.
func Members(raw json.RawMessage, where string, allowed ...string) (map[string]json.RawMessage, error) {
	m, ok := strictObject(raw)
	if !ok {
		return nil, &FieldError{Code: BadField, Where: where, Text: "this is an object"}
	}
	return m, OnlyMembers(m, where, allowed...)
}

// OnlyMembers says which member of m is not one of those allowed.
func OnlyMembers(m map[string]json.RawMessage, where string, allowed ...string) error {
	known := map[string]bool{}
	for _, a := range allowed {
		known[a] = true
	}
	for i, k := range sorted(m) {
		if !known[k] {
			return &FieldError{Code: UnknownField, Where: at(where, k, i, nil), Text: "this version does not know this field"}
		}
	}
	return nil
}

// The format itself defines an AI agent and a utility app, from the fields
// the core's own asset model holds (ADR-088, decision 14). Their one-word
// names are reserved here. Their fields are published, and this package reads
// them, in the change that follows this one: until then an item of either
// kind is a kind this version does not yet understand, listed and skipped, and
// nothing else may take either name.
const (
	KindAIAgent    = "ai_agent"
	KindUtilityApp = "utility_app"
)

// Registry holds the kinds and extensions a reader knows.
type Registry struct {
	kinds      map[string]Kind
	extensions map[string]Extension
}

// NewRegistry is a registry holding the kinds this version of the reader
// ships: a website.
func NewRegistry() *Registry {
	r := &Registry{kinds: map[string]Kind{}, extensions: map[string]Extension{}}
	r.kinds[KindWebsite] = websiteKind{}
	return r
}

// AddKind adds a kind. It refuses a name that is not written as a kind is, one
// already held, and any one-word name: one word is the format's own, for the
// kinds docs/set-up-file.md publishes or reserves, and a kind of anybody
// else's carries its maker's namespace before a dot.
func (r *Registry) AddKind(k Kind) error {
	name := k.Name()
	switch {
	case !AKind(name):
		return fmt.Errorf("%q is not written as a kind is", name)
	case r.kinds[name] != nil:
		return fmt.Errorf("the kind %q is already held", name)
	case !strings.Contains(name, "."):
		return fmt.Errorf("the kind %q is one word, which is kept for the kinds the format itself defines: write it after a namespace and a dot", name)
	}
	r.kinds[name] = k
	return nil
}

// AddExtension adds an extension. Its namespace is always written after a
// dot, since no extension's fields are the core's.
func (r *Registry) AddExtension(e Extension) error {
	ns := e.Namespace()
	switch {
	case !AKind(ns) || !strings.Contains(ns, "."):
		return fmt.Errorf("%q is not written as an extension's namespace is: lower-case words joined by dots, at least two", ns)
	case r.extensions[ns] != nil:
		return fmt.Errorf("the extension %q is already held", ns)
	}
	r.extensions[ns] = e
	return nil
}

// Kinds are the kinds the registry holds, sorted.
func (r *Registry) Kinds() []string { return sorted(r.kinds) }

// KindWebsite is a website people sign in to with their own Identity Agents:
// a relying party.
const KindWebsite = "website"

// MaxOrigin is the longest origin of a website, in bytes.
const MaxOrigin = 300

// The ways a website admits people. They are the core's enrolment modes
// (asset.EnrollmentMode), which a test holds them to.
const (
	ModeOpen    = "open"
	ModeRequest = "request"
	ModeInvite  = "invite"
)

// Website is a website's own fields.
type Website struct {
	// Origin is the website's origin in its one spelling: a lower-case scheme
	// and host, the port only when it is not the scheme's own, and nothing
	// after it.
	Origin string        `json:"origin"`
	Policy WebsitePolicy `json:"policy"`
}

// WebsitePolicy is who may sign in to a website. Its members are those of the
// core's enrolment policy (asset.EnrollmentPolicy) under the same names, less
// the three gates the core cannot check and so never stores.
type WebsitePolicy struct {
	Mode string `json:"mode"`
	// MembershipSource is whose list of members is consulted: "" or "asset"
	// for the website's own, or the name of a list the importing Identity
	// Agent must already keep.
	MembershipSource string `json:"membership_source,omitempty"`
	// RequiredCredSchema is the identifier of the schema of a credential a
	// person must present, or "".
	RequiredCredSchema string `json:"required_cred_schema,omitempty"`
	// RequiredCredIssuer is who must have issued that credential: "" for
	// anybody, "self" for the importing organisation, or another identity's
	// identifier.
	RequiredCredIssuer string `json:"required_cred_issuer,omitempty"`
}

type websiteKind struct{}

func (websiteKind) Name() string { return KindWebsite }

// Declares is every sentence a website's check may say, each for one place.
func (websiteKind) Declares() Declaration {
	return Declaration{Says: map[string]string{
		BadField + "@permissions":                    "a website is signed in to and asks nothing of the Identity Agent: it holds no permissions, limits or grant",
		BadField + "@origin":                         "a website's origin is http or https, a lower-case host, the port only when it is not the scheme's own, and nothing after it",
		BadField + "@policy.mode":                    "a website admits people by open, request or invite",
		BadField + "@policy.membership_source":       "a membership source is a short lower-case name",
		BadField + "@policy.required_cred_schema":    "a credential's schema is named by its identifier",
		BadField + "@policy.required_cred_issuer":    `an issuer is "self" or another identity's identifier, and is required only of a credential that is required`,
		NeedsSetUpHere + "@policy.membership_source": "this website admits the members of a list this Identity Agent must already keep",
	}}
}

func (websiteKind) Parse(own map[string]json.RawMessage) (Fields, error) {
	if err := OnlyMembers(own, "", "origin", "policy"); err != nil {
		return nil, err
	}
	var w Website
	var ok bool
	if w.Origin, ok = Text(own["origin"]); !ok || w.Origin == "" {
		return nil, &FieldError{Code: BadField, Where: "origin", Text: "a website has an origin"}
	}
	policy, err := Members(own["policy"], "policy", "mode", "membership_source", "required_cred_schema", "required_cred_issuer")
	if err != nil {
		return nil, err
	}
	for member, into := range map[string]*string{"mode": &w.Policy.Mode, "membership_source": &w.Policy.MembershipSource,
		"required_cred_schema": &w.Policy.RequiredCredSchema, "required_cred_issuer": &w.Policy.RequiredCredIssuer} {
		if raw, has := policy[member]; has {
			if *into, ok = Text(raw); !ok {
				return nil, &FieldError{Code: BadField, Where: "policy." + member, Text: "this is text"}
			}
		}
	}
	return w, nil
}

var sourceShape = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

// Check holds a website to what the core can keep for one.
func (w Website) Check(c Common) []Finding {
	var out []Finding
	block := func(where string) { out = append(out, Finding{Code: BadField, Where: where, Blocks: true}) }
	if len(c.Permissions) > 0 || len(c.Limits) > 0 || c.GrantEnd != "" {
		block("permissions")
	}
	if CheckWebOrigin(w.Origin) != nil {
		block("origin")
	}
	p := w.Policy
	if p.Mode != ModeOpen && p.Mode != ModeRequest && p.Mode != ModeInvite {
		block("policy.mode")
	}
	switch {
	case p.MembershipSource == "" || p.MembershipSource == "asset":
	case !sourceShape.MatchString(p.MembershipSource):
		block("policy.membership_source")
	default:
		out = append(out, Finding{Code: NeedsSetUpHere, Where: "policy.membership_source"})
	}
	if p.RequiredCredSchema != "" && !isQB64("E", p.RequiredCredSchema) {
		block("policy.required_cred_schema")
	}
	if p.RequiredCredIssuer != "" && (p.RequiredCredSchema == "" || p.RequiredCredIssuer != Self && !iacrypto.IsIdentifierQB64(p.RequiredCredIssuer)) {
		block("policy.required_cred_issuer")
	}
	return out
}

// Describe is the website as a person is shown it.
func (w Website) Describe() []Row {
	rows := []Row{{"Origin", w.Origin}, {"People are admitted by", w.Policy.Mode}}
	if s := w.Policy.MembershipSource; s != "" && s != "asset" {
		rows = append(rows, Row{"Members are taken from", s})
	}
	if w.Policy.RequiredCredSchema != "" {
		rows = append(rows, Row{"A credential is required, of schema", w.Policy.RequiredCredSchema})
		switch w.Policy.RequiredCredIssuer {
		case "":
			rows = append(rows, Row{"Issued by", "anybody"})
		case Self:
			rows = append(rows, Row{"Issued by", "this organisation"})
		default:
			rows = append(rows, Row{"Issued by", w.Policy.RequiredCredIssuer})
		}
	}
	return rows
}

// Refers names the two members of a website that hold an identifier.
func (Website) Refers() References {
	return References{Identifiers: []string{"policy.required_cred_schema", "policy.required_cred_issuer"}}
}

// Same is what makes two websites one website: the origin, which is the
// core's own key for one.
func (w Website) Same() string { return w.Origin }

// CheckWebOrigin refuses a website's origin that is not in its one spelling:
// http or https, a host as the core spells one in an address
// (endpointrecord.CheckOrigin), the port only when it is not the scheme's
// own, and nothing after it. One spelling, because origins are compared as
// text.
func CheckWebOrigin(o string) error {
	// The reason is said without the origin: it came from a file.
	notOne := errors.New("a website's origin is http or https, a lower-case host, the port only when it is not the scheme's own, and nothing after it")
	scheme, rest, _ := strings.Cut(o, "://")
	own := map[string]string{"https": "443", "http": "80"}[scheme]
	if own == "" || len(o) > MaxOrigin {
		return notOne
	}
	if i := strings.LastIndex(rest, ":"); i > strings.LastIndex(rest, "]") {
		if rest[i+1:] == own {
			return notOne
		}
	} else {
		o += ":" + own
	}
	if endpointrecord.CheckOrigin(o) != nil {
		return notOne
	}
	return nil
}
