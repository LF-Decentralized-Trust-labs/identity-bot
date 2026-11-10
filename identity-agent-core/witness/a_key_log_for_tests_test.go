package witness

import (
	"encoding/json"
	"fmt"
)

// A key log in the bytes the witness service reads: only the fields the
// witnessing rule looks at, in the shape KERI writes them (sequence numbers
// and thresholds as lowercase hex strings).

func listOf(v []string) string {
	b, _ := json.Marshal(append([]string{}, v...))
	return string(b)
}

// inceptionOf is the first event of aid's log, naming witnesses and a threshold.
func inceptionOf(aid string, witnesses []string, toad int) []byte {
	return []byte(fmt.Sprintf(`{"t":"icp","d":"E%s0","i":%q,"s":"0","b":%s,"bt":"%x"}`,
		aid, aid, listOf(witnesses), toad))
}

// rotationOf is the event at sequence sn that cuts and adds witnesses, naming
// the event before it, and asks toad of the list that results.
func rotationOf(aid string, sn int, cut, add []string, toad int) []byte {
	return []byte(fmt.Sprintf(`{"t":"rot","d":"E%s%d","i":%q,"s":"%x","p":"E%s%d","br":%s,"ba":%s,"bt":"%x"}`,
		aid, sn, aid, sn, aid, sn-1, listOf(cut), listOf(add), toad))
}

// interactionOf is the event at sequence sn that changes nothing about witnesses.
func interactionOf(aid string, sn int) []byte {
	return []byte(fmt.Sprintf(`{"t":"ixn","d":"E%s%d","i":%q,"s":"%x","p":"E%s%d"}`,
		aid, sn, aid, sn, aid, sn-1))
}

// saidOf is the identifier of an event made by the functions above.
func saidOf(raw []byte) string {
	var ev struct {
		D string `json:"d"`
	}
	_ = json.Unmarshal(raw, &ev)
	return ev.D
}

// keyLog is a KeyLogOf that answers the given events for the identity they are
// of, and says there is no log for any other.
func keyLog(aid string, events ...[]byte) func(string) ([][]byte, error) {
	return func(asked string) ([][]byte, error) {
		if asked != aid {
			return nil, fmt.Errorf("no key log for %s", asked)
		}
		return events, nil
	}
}
