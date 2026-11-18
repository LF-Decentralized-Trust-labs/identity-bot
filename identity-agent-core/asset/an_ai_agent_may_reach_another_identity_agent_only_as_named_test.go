package asset

import "testing"

// The grant for messaging AI agents another Identity Agent holds is refused at
// issue when a constraint would be read as wider than it looks: an "agent" given
// as text or as an empty list is not a narrowing, and the same shapes are
// refused again when the grant is used (agentpeer.CheckPeerGrant).
func TestAPeerGrantsConstraintsAreRefusedWhenMisshapen(t *testing.T) {
	caps := []string{"agent.message.peer"}
	ok := map[string]interface{}{"agent.message.peer": map[string]interface{}{"contact": []interface{}{"EBETA"}, "agent": []interface{}{"EREVIEWER"}}}
	if err := CheckResourceConstraints(ok, caps); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]map[string]interface{}{
		"an agent given as text":           {"contact": []interface{}{"EBETA"}, "agent": "EREVIEWER"},
		"an agent given as empty list":     {"contact": []interface{}{"EBETA"}, "agent": []interface{}{}},
		"a contact given as an empty list": {"contact": []interface{}{}},
		"an agent list of numbers":         {"contact": []interface{}{"EBETA"}, "agent": []interface{}{1}},
	} {
		if CheckResourceConstraints(map[string]interface{}{"agent.message.peer": c}, caps) == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}
