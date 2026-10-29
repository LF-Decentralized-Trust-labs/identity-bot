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
		{
			// A target recorded as an endpoint rather than an origin. The base
			// must be reduced to the origin first, or the path doubles up —
			// witnessBase not recognising this shape is the bug this change
			// fixes, and it reaches the event-submission path, not only health.
			name:   "an endpoint-shaped URL is reduced to its origin",
			target: witnessTarget{URL: "https://witness3.grapeid.org/witness/event", Commercial: true},
			event:  "https://witness3.grapeid.org/witness/event",
			record: "https://witness3.grapeid.org/witness/endpoint",
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

// The health probe must land on the witness's origin, not be appended to
// whatever endpoint path its OOBI happens to name.
//
// This is the regression that made every heartbeat 404: the trimming only
// recognised "/public/oobi/", which a witness service never publishes — their
// addresses are <base>/witness/event and <base>/public/kel-digest — so the
// base was never trimmed and the probe asked for
// https://witness1.grapeid.org/witness/event/api/health.
func TestTheHealthProbeIsBuiltFromTheOriginNotTheEndpoint(t *testing.T) {
	const want = "https://witness1.grapeid.org/api/health"
	for _, oobi := range addressShapes {
		if got := healthURL(oobi); got != want {
			t.Errorf("healthURL(%q) = %q, want %q", oobi, got, want)
		}
	}
}

// The same trimming decides where a witness request and its accept callback
// are sent, and those carried their own identical copies of it. A peer whose
// address is an endpoint path was being asked to enrol at
// <host>/witness/event/api/witness/request, so peer witnessing could not be
// set up at all between agents that publish themselves that way.
func TestEnrolmentURLsAreBuiltFromTheOriginToo(t *testing.T) {
	for _, oobi := range addressShapes {
		if got, want := witnessRequestURL(oobi), "https://witness1.grapeid.org/api/witness/request"; got != want {
			t.Errorf("witnessRequestURL(%q) = %q, want %q", oobi, got, want)
		}
		if got, want := witnessAcceptURL(oobi), "https://witness1.grapeid.org/api/witness/accept"; got != want {
			t.Errorf("witnessAcceptURL(%q) = %q, want %q", oobi, got, want)
		}
	}
}

// Every shape an Identity Agent may hold a witness's address in: bare origin, with a
// trailing slash, and each endpoint a witness or watcher advertises.
var addressShapes = []string{
	"https://witness1.grapeid.org",
	"https://witness1.grapeid.org/",
	"https://witness1.grapeid.org/witness/event",
	"https://witness1.grapeid.org/api/witness/event",
	"https://witness1.grapeid.org/public/kel-digest",
	"https://witness1.grapeid.org/api/public/kel-digest",
	"https://witness1.grapeid.org/public/oobi/BMtfjvi",
	"https://witness1.grapeid.org/oobi/BMtfjvi",
}
