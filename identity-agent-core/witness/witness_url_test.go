package witness

import "testing"

// Where an event is sent depends on what kind of witness it is going to, and
// getting it wrong is silent: a witness that answers 404 is indistinguishable
// from one that is offline, and the broadcast tolerates offline witnesses by
// design. So every event sent to the commercial pool was refused and nothing
// said so.
func TestEachKindOfWitnessGetsThePathItServes(t *testing.T) {
	cases := []struct {
		name   string
		target witnessTarget
		event  string
		record string
	}{
		{
			// Another Identity Agent. Everything an agent serves is under /api.
			name:   "a contact witnessing for us",
			target: witnessTarget{URL: "https://friend.example/public/oobi/EFriend"},
			event:  "https://friend.example/api/witness/event",
			record: "https://friend.example/api/witness/endpoint",
		},
		{
			// A service built for the one job, which serves it at the root.
			name:   "a commercial witness",
			target: witnessTarget{URL: "https://witness1.grapeid.org", Commercial: true},
			event:  "https://witness1.grapeid.org/witness/event",
			record: "https://witness1.grapeid.org/witness/endpoint",
		},
		{
			name:   "a trailing slash does not double up",
			target: witnessTarget{URL: "https://witness2.grapeid.org/", Commercial: true},
			event:  "https://witness2.grapeid.org/witness/event",
			record: "https://witness2.grapeid.org/witness/endpoint",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := witnessEventURL(tc.target); got != tc.event {
				t.Errorf("event URL\n got %s\nwant %s", got, tc.event)
			}
			if got := witnessEndpointURL(tc.target); got != tc.record {
				t.Errorf("endpoint URL\n got %s\nwant %s", got, tc.record)
			}
		})
	}
}
