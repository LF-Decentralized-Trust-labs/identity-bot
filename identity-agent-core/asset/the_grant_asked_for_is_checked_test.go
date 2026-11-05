package asset

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// The same three refusals bind an app and an AI agent, and each is made before
// anything is minted: the handler here has no root identity and no engine, so
// reaching either of those checks would be a different error.
func TestAGrantThatShouldNotBeIssuedIsRefusedForAnAppAndAnAIAgent(t *testing.T) {
	h, _ := newAgentForTest(t, nil)
	past := time.Now().Add(-time.Hour)
	future := time.Now().Add(time.Hour)
	cases := []struct {
		name        string
		caps        []string
		until       *time.Time
		constraints map[string]interface{}
		want        func(error) bool
	}{
		{"no capabilities", nil, nil, nil, func(e error) bool { return errors.Is(e, ErrNoCapabilities) }},
		{"only blank capabilities", []string{"  "}, nil, nil, func(e error) bool { return errors.Is(e, ErrNoCapabilities) }},
		{"an end in the past", []string{"a.b"}, &past, nil, func(e error) bool { return errors.Is(e, ErrGrantLapsed) }},
		{"a limit on a capability not given", []string{"a.b"}, &future, map[string]interface{}{"c.d": map[string]interface{}{"x": []interface{}{"y"}}},
			func(e error) bool { return e != nil && strings.Contains(e.Error(), "does not give") }},
		{"an empty limit", []string{"a.b"}, &future, map[string]interface{}{"a.b": map[string]interface{}{}},
			func(e error) bool { return e != nil && strings.Contains(e.Error(), "at least one argument") }},
		{"a limit that is not strings", []string{"a.b"}, &future, map[string]interface{}{"a.b": map[string]interface{}{"x": []interface{}{1.0}}},
			func(e error) bool { return e != nil && strings.Contains(e.Error(), "must list strings") }},
	}
	for _, c := range cases {
		_, err := h.ProvisionAppAsset("An app "+c.name, c.caps, c.until, c.constraints)
		if !c.want(err) {
			t.Errorf("app, %s: %v", c.name, err)
		}
		_, err = h.ProvisionAgentAsset("An agent "+c.name, c.caps, nil, c.until, c.constraints)
		if !c.want(err) {
			t.Errorf("AI agent, %s: %v", c.name, err)
		}
	}
	if n := len(listAssets(t, h)); n != 1 { // only the fixture's agent
		t.Fatalf("a refused grant left %d assets, want the 1 that was there", n)
	}
}
