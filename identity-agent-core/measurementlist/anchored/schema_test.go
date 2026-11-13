package anchored

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/measurementlist"
)

func TestTheSchemaIsItsOwnIdentifier(t *testing.T) {
	said, err := SchemaSAID()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(said, "E") || len(said) != 44 {
		t.Fatalf("not a SAID: %q", said)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(SchemaDocument(), &doc); err != nil {
		t.Fatal(err)
	}
	if string(doc["$id"]) != `"`+said+`"` {
		t.Fatalf("$id %s is not %s", doc["$id"], said)
	}
	// any change to the document is another identifier
	changed := bytes.Replace(bytesTrimNL(SchemaDocument()), []byte(`"minimum":1`), []byte(`"minimum":0`), 1)
	if _, err := keri.VerifySchema(changed); err == nil {
		t.Fatal("a changed schema still matches its identifier")
	}
	// and a build's pin names it, with no way to name another
	if _, err := Pinned(); err == nil || !strings.Contains(err.Error(), "pins no software publisher") {
		t.Fatalf("a build with no publisher: %v", err)
	}
}

// The schema's property names are the reader's field names, so the document
// cannot drift from what the reader accepts without this noticing.
func TestTheSchemaNamesExactlyTheFieldsTheReaderReads(t *testing.T) {
	var doc struct {
		Properties struct {
			A struct {
				OneOf []struct {
					Properties map[string]json.RawMessage `json:"properties"`
					Required   []string                   `json:"required"`
				} `json:"oneOf"`
			} `json:"a"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(SchemaDocument(), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Properties.A.OneOf) != 2 {
		t.Fatalf("expected the plain and the handover block, got %d", len(doc.Properties.A.OneOf))
	}
	keys := func(m map[string]json.RawMessage) []string {
		var o []string
		for k := range m {
			o = append(o, k)
		}
		sort.Strings(o)
		return o
	}
	for i, want := range [][]string{
		{"d", "dt", "expires_at", "images", "published_at", "sequence"},
		{"d", "dt", "expires_at", "images", "list_version", "published_at", "sequence"},
	} {
		if got := keys(doc.Properties.A.OneOf[i].Properties); !reflect.DeepEqual(got, want) {
			t.Fatalf("block %d: the schema lists %v, the reader reads %v", i, got, want)
		}
	}
	for i, want := range []int{6, 7} {
		if n := len(doc.Properties.A.OneOf[i].Required); n != want {
			t.Fatalf("block %d: %d required", i, n)
		}
	}
}

type conformanceFile struct {
	Now        string `json:"now"`
	Attributes []struct {
		Name       string          `json:"name"`
		Expect     string          `json:"expect"`
		Attributes json.RawMessage `json:"attributes"`
	} `json:"attributes"`
	Credential struct {
		Issuer     string `json:"issuer"`
		Registry   string `json:"registry"`
		Credential string `json:"credential"`
		SAID       string `json:"said"`
	} `json:"credential"`
}

func readConformance(t *testing.T) conformanceFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/schema_conformance.json")
	if err != nil {
		t.Fatal(err)
	}
	var f conformanceFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

// Every vector is read by the same code the checker uses for a list's content,
// and must come out as the file says. Another implementation holds its own
// reading of the schema to the same file.
func TestTheSchemaConformanceVectors(t *testing.T) {
	f := readConformance(t)
	now, err := time.Parse(time.RFC3339, f.Now)
	if err != nil {
		t.Fatal(err)
	}
	var accepted, refused int
	for _, v := range f.Attributes {
		c, err := measurementlist.ContentOfAttributes(v.Attributes)
		if err == nil {
			_, err = measurementlist.FromContent(c, "Edigest", measurementlist.Rules{Now: now})
		}
		switch v.Expect {
		case "accept":
			accepted++
			if err != nil {
				t.Errorf("%s: refused: %v", v.Name, err)
			}
		case "refuse":
			refused++
			if err == nil {
				t.Errorf("%s: ACCEPTED", v.Name)
			}
		default:
			t.Fatalf("%s: expect %q", v.Name, v.Expect)
		}
	}
	if accepted < 5 || refused < 20 {
		t.Fatalf("the vectors shrank: %d accepted, %d refused", accepted, refused)
	}
}

// A whole credential, as an issuer builds it, names this schema and is read.
func TestTheCredentialVectorNamesTheSchemaOfThisPackage(t *testing.T) {
	f := readConformance(t)
	c, err := keri.VerifyCredential([]byte(f.Credential.Credential))
	if err != nil {
		t.Fatal(err)
	}
	said, _ := SchemaSAID()
	if c.SchemaSAID != said || c.SAID != f.Credential.SAID || c.Issuer != f.Credential.Issuer || c.Registry != f.Credential.Registry {
		t.Fatalf("the credential vector is %+v, not under %s", c, said)
	}
	if _, err := measurementlist.ContentOfAttributes(c.Attributes); err != nil {
		t.Fatalf("its attributes are not a list: %v", err)
	}
}
