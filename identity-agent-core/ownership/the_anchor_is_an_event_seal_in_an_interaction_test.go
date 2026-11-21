package ownership

import (
	"encoding/json"
	"testing"

	keri "github.com/grapeid/keri-go"

	"identity-agent-core/drivers"
)

// An owner identity's interaction is read as an anchor only where it
// carries exactly one event seal.
func TestTheAnchorIsTheOneEventSealOfAnInteraction(t *testing.T) {
	const owner = "EOwnerOwnerOwnerOwnerOwnerOwnerOwnerOwner000"
	const machine = "EMachineMachineMachineMachineMachineMachine0"
	seal := func(sn string) json.RawMessage {
		s, err := drivers.EventSeal(machine, sn, machine)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	interaction := func(seals ...json.RawMessage) []byte {
		raw, err := keri.BuildInteraction(keri.InteractionInput{Prefix: owner, PriorSAID: owner, SN: 1, Data: seals})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	got, err := TheAnchorIn(interaction(seal("0")))
	if err != nil || got.Identifier != machine || got.SN != 0 || got.SAID != machine {
		t.Fatalf("one event seal was read as %+v, %v", got, err)
	}
	for name, raw := range map[string][]byte{
		"no seal":          interaction(),
		"two event seals":  interaction(seal("0"), seal("1")),
		"another seal too": interaction(seal("0"), json.RawMessage(`{"d":"EOther"}`)),
	} {
		if got, err := TheAnchorIn(raw); err == nil {
			t.Errorf("%s was read as the anchor %+v", name, got)
		}
	}
}
