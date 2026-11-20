package setupfile_test

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"identity-agent-core/asset"
	"identity-agent-core/permission"
	"identity-agent-core/setupfile"
)

// This package is pure: it reads a file and holds no store. The package that
// keeps assets brings the store and the KERI engine with it, so this one does
// not import it, and mirrors the few things of it a file writes.
// These tests hold each mirror to what it mirrors, so neither can change
// alone.

// For names in plain letters, one name here is one name to the core. Other
// spellings of the same letters are one name here and two to the core, which
// is why an import compares by both (ADR-088, decision 11).
func TestNamesInPlainLettersAreOneNameExactlyWhenTheCoreSaysSo(t *testing.T) {
	// Inner spaces and hyphens are part of a name to the core: were it to
	// start ignoring them, these pairs would tell.
	names := []string{"Reader", "reader", " READER ", "Reader 2", "Stra\u00dfe", "STRASSE", "Kelvin K", "kelvin \u212a", "\u017f", "s", "", " ",
		"Reader One", "ReaderOne", "Reader  One", "reader-one", "Reader_One", "reader one", "\u0130stanbul", "istanbul", "i\u0307stanbul"}
	for _, a := range names {
		for _, b := range names {
			if setupfile.SameName(a, b) != asset.SameAgentName(a, b) {
				t.Errorf("%q and %q: this package says %v and the core says %v", a, b, setupfile.SameName(a, b), asset.SameAgentName(a, b))
			}
		}
	}
}

func TestAWebsitesPolicyIsTheCoresEnrolmentPolicyLessTheGatesItCannotCheck(t *testing.T) {
	core := map[string]reflect.Type{}
	ct := reflect.TypeOf(asset.EnrollmentPolicy{})
	for i := 0; i < ct.NumField(); i++ {
		name, _, _ := strings.Cut(ct.Field(i).Tag.Get("json"), ",")
		core[name] = ct.Field(i).Type
	}
	mine := map[string]bool{}
	mt := reflect.TypeOf(setupfile.WebsitePolicy{})
	for i := 0; i < mt.NumField(); i++ {
		name, _, _ := strings.Cut(mt.Field(i).Tag.Get("json"), ",")
		mine[name] = true
		if core[name] == nil || core[name].Kind() != mt.Field(i).Type.Kind() {
			t.Errorf("a website's policy has %q, which is not a member of the core's policy of the same type", name)
		}
	}
	// What is left out is exactly what the core refuses to store when set.
	for name := range core {
		if mine[name] {
			continue
		}
		p := reflect.New(ct).Elem()
		f, _ := ct.FieldByNameFunc(func(n string) bool {
			sf, _ := ct.FieldByName(n)
			tag, _, _ := strings.Cut(sf.Tag.Get("json"), ",")
			return tag == name
		})
		switch f.Type.Kind() {
		case reflect.Int:
			p.FieldByIndex(f.Index).SetInt(1)
		case reflect.String:
			p.FieldByIndex(f.Index).SetString("x")
		}
		if p.Interface().(asset.EnrollmentPolicy).UnsupportedGate() == "" {
			t.Errorf("the core stores %q and a set-up file has no place for it", name)
		}
	}
	for mode, want := range map[string]asset.EnrollmentMode{
		setupfile.ModeOpen: asset.EnrollmentOpen, setupfile.ModeRequest: asset.EnrollmentRequest, setupfile.ModeInvite: asset.EnrollmentInvite,
	} {
		if mode != string(want) {
			t.Errorf("the mode %q is %q in the core", mode, want)
		}
	}
}

// The core's modes are constants, which a program cannot list, so the test
// reads them from the source: a mode added to the core and not to this
// package fails here.
func TestEveryEnrolmentModeOfTheCoreIsAModeOfAWebsite(t *testing.T) {
	parsed, err := parser.ParseFile(token.NewFileSet(), "../asset/types.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	mine := map[string]bool{setupfile.ModeOpen: true, setupfile.ModeRequest: true, setupfile.ModeInvite: true}
	found := 0
	ast.Inspect(parsed, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok || len(spec.Values) != 1 {
			return true
		}
		typ, _ := spec.Type.(*ast.Ident)
		lit, _ := spec.Values[0].(*ast.BasicLit)
		if typ == nil || lit == nil || typ.Name != "EnrollmentMode" {
			return true
		}
		found++
		if mode, _ := strconv.Unquote(lit.Value); !mine[mode] {
			t.Errorf("the core has the enrolment mode %q, which a website in a set-up file cannot have", mode)
		}
		return true
	})
	if found != len(mine) {
		t.Errorf("the core has %d enrolment modes and a website has %d", found, len(mine))
	}
}

func TestLimitsAreReadAsTheCoreReadsAGrantsConstraints(t *testing.T) {
	// asset.Asset.GrantConstraints is capability, then argument, then the
	// values allowed: the shape of Limits, with every value a string.
	f, ok := reflect.TypeOf(asset.Asset{}).FieldByName("GrantConstraints")
	if !ok || f.Type.Kind() != reflect.Map || f.Type.Key().Kind() != reflect.String {
		t.Fatal("the core no longer keeps a grant's constraints by capability")
	}
	l := reflect.TypeOf(setupfile.Limits{})
	if l.Key().Kind() != reflect.String || l.Elem().Key().Kind() != reflect.String || l.Elem().Elem().Elem().Kind() != reflect.String {
		t.Fatal("limits are no longer capability, argument, values")
	}
	// Limits the reader accepts mean to the core's one reading of a grant's
	// constraints what they say: the values named are let through, and no
	// other.
	file := []byte(`{"format":"identity-agent-set-up/1","items":[{"kind":"example.worker","name":"Reader",
		"permissions":["code.repository.read"],
		"limits":{"code.repository.read":{"repository":["example/handbook","example/site"],"branch":["main"]}}}]}`)
	reg := setupfile.NewRegistry()
	if err := reg.AddKind(anyKind{}); err != nil {
		t.Fatal(err)
	}
	r, err := setupfile.Read(file, setupfile.Options{Registry: reg})
	if err != nil || r.Items[0].State != setupfile.Ready {
		t.Fatalf("the limits were not read: %v %+v", err, r)
	}
	raw, _ := json.Marshal(r.Items[0].Limits)
	var constraints map[string]interface{}
	_ = json.Unmarshal(raw, &constraints)
	for args, allowed := range map[string]bool{
		`{"repository":"example/handbook","branch":"main"}`: true,
		`{"repository":"example/site","branch":"main"}`:     true,
		`{"repository":"example/secret","branch":"main"}`:   false,
		`{"repository":"example/site","branch":"other"}`:    false,
		`{"repository":"example/site"}`:                     false,
	} {
		if err := permission.CheckResourceConstraints(constraints, "code.repository.read", []byte(args)); (err == nil) != allowed {
			t.Errorf("under the limits read, the core says of %s: %v", args, err)
		}
	}
	if err := permission.CheckResourceConstraints(constraints, "code.repository.write", []byte(`{"repository":"example/secret"}`)); err != nil {
		t.Errorf("a limit reached a capability it is not on: %v", err)
	}
}

type anyKind struct{}

func (anyKind) Name() string                                               { return "example.worker" }
func (anyKind) Parse(map[string]json.RawMessage) (setupfile.Fields, error) { return nothing{}, nil }

type nothing struct{}

func (nothing) Check(setupfile.Common) []setupfile.Finding { return nil }
func (nothing) Describe() []setupfile.Row                  { return nil }
func (nothing) Refers() setupfile.References               { return setupfile.References{} }
