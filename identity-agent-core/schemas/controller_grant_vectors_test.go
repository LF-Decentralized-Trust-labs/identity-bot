package schemas

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The Controller Grant vectors (controller-grant-vectors.json) say which
// attribute blocks each version admits: 1.2.0 names the app its machine is the
// back end of, 1.1.0 does not, and both keep the identifiers they were
// published under.
func TestTheControllerGrantVectorsHold(t *testing.T) {
	raw, err := os.ReadFile("controller-grant-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Schemas map[string]struct{ File, Said string }
		Cases   []struct {
			Name       string
			Version    string
			Attributes map[string]interface{}
			Accepted   bool
			Because    string
			ValueFault bool `json:"value_fault"`
		}
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	kinds := map[string]*AssetGrant{"1.2.0": ControllerGrant, "1.1.0": ControllerGrantV11}
	for version, g := range kinds {
		s, ok := v.Schemas[version]
		if !ok || s.Said != g.Schema.SAID {
			t.Fatalf("the vectors give %+v for %s, this package builds %s", s, version, g.Schema.SAID)
		}
		file, err := os.ReadFile("../contracts/asset-grants/" + s.File)
		if err != nil || string(file) != g.Schema.JSON {
			t.Fatalf("%s is not the %s schema this package builds (%v)", s.File, version, err)
		}
	}
	if len(v.Cases) == 0 {
		t.Fatal("the vectors have no cases")
	}
	for _, c := range v.Cases {
		t.Run(c.Name, func(t *testing.T) {
			err := kinds[c.Version].CheckAttributes(c.Attributes)
			if c.ValueFault {
				return // refused for a value, which the schema file decides: see the independent checker
			}
			if c.Accepted && err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !c.Accepted && (err == nil || !strings.Contains(err.Error(), c.Because)) {
				t.Fatalf("admitted, or refused for another reason than %q: %v", c.Because, err)
			}
		})
	}
}
