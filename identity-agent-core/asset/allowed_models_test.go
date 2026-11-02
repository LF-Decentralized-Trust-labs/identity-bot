package asset

import (
	"encoding/json"
	"reflect"
	"testing"
)

// Models extends Model and never replaces it: a record with only Model reads
// and writes as it always did, and Model is allowed whether or not it is listed.
func TestAllowedModelsAreTheDefaultThenTheList(t *testing.T) {
	for name, c := range map[string]struct {
		brain BrainConfig
		want  []string
	}{
		"only Model":           {BrainConfig{Model: "a"}, []string{"a"}},
		"no model":             {BrainConfig{}, nil},
		"list without default": {BrainConfig{Model: "a", Models: []string{"b", "c"}}, []string{"a", "b", "c"}},
		"default repeated":     {BrainConfig{Model: "a", Models: []string{"b", "a", "b"}}, []string{"a", "b"}},
		"list with no default": {BrainConfig{Models: []string{"b"}}, []string{"b"}},
	} {
		if got := c.brain.AllowedModels(); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: %v, want %v", name, got, c.want)
		}
	}
	b, _ := json.Marshal(BrainConfig{Model: "a"})
	if string(b) != `{"model":"a"}` {
		t.Errorf("a brain with only Model is written as %s", b)
	}
}
