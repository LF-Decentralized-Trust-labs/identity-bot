package login

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// The action registry's login request schema names every field a challenge
// carries, so a reader of the registry is not told less than the signed body holds.
// (The schema had stopped at browser_key while front_end, rid and api were added.)
func TestTheRegistryListsEveryFieldOfAChallenge(t *testing.T) {
	raw, err := os.ReadFile("../actions/registry.json")
	if err != nil {
		t.Fatal(err)
	}
	var reg struct {
		Actions []struct {
			Key           string                     `json:"key"`
			RequestSchema map[string]json.RawMessage `json:"request_schema"`
		} `json:"actions"`
	}
	if err := json.Unmarshal(raw, &reg); err != nil {
		t.Fatal(err)
	}
	var schema map[string]json.RawMessage
	for _, a := range reg.Actions {
		if a.Key == "login" {
			schema = a.RequestSchema
		}
	}
	if schema == nil {
		t.Fatal("the registry has no login action")
	}
	// The envelope's own fields and the signature are not the request.
	notRequest := map[string]bool{"v": true, "t": true, "sig": true}
	ty := reflect.TypeOf(ChallengeBundle{})
	for i := 0; i < ty.NumField(); i++ {
		name := strings.Split(ty.Field(i).Tag.Get("json"), ",")[0]
		if name == "" || name == "-" || notRequest[name] {
			continue
		}
		if _, ok := schema[name]; !ok {
			t.Errorf("a challenge carries %q and the registry's login schema does not name it", name)
		}
	}
}
