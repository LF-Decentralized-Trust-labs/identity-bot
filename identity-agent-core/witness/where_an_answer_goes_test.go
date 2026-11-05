package witness

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"identity-agent-core/login"
	"identity-agent-core/store"
)

const answeringAID = "EWitness0000000000000000000000000000000000020"

func answerer(t *testing.T, contacts map[string]store.ContactRecord) (*Service, *memContacts, *capturePoster) {
	t.Helper()
	mc := &memContacts{contacts: contacts, identity: &store.IdentityState{AID: answeringAID}}
	cap := &capturePoster{}
	s := agentService(t, answeringAID, mc)
	s.PostEvent = cap.post
	return s, mc, cap
}

func declined(aid string) AcceptCallback {
	return AcceptCallback{RequesterAID: aid, Decision: "declined", Reason: "x", RequestID: "r"}
}

// An answer is posted only to the address in the contact's own recorded OOBI
// for that AID, whatever address the signed request names.
func TestAnAnswerGoesOnlyToTheAddressRecordedForTheRequester(t *testing.T) {
	const aid = "ERequester0000000000000000000000000000000000021"
	recorded := "https://peer.example/public/oobi/" + aid
	lookupHost = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("93.184.216.34")}, nil }
	t.Cleanup(func() { lookupHost = net.LookupIP })

	cases := map[string]struct {
		contact store.ContactRecord
		signed  string
		resolve []net.IP
		post    bool
	}{
		"the recorded address":          {store.ContactRecord{AID: aid, OobiURL: recorded}, recorded, nil, true},
		"the metadata address":          {store.ContactRecord{AID: aid, OobiURL: recorded}, "http://169.254.169.254/public/oobi/" + aid, nil, false},
		"localhost the request names":   {store.ContactRecord{AID: aid, OobiURL: recorded}, "http://localhost:8080/public/oobi/" + aid, nil, false},
		"no recorded address":           {store.ContactRecord{AID: aid}, recorded, nil, false},
		"an OOBI for somebody else":     {store.ContactRecord{AID: aid, OobiURL: "https://peer.example/public/oobi/EVictim"}, "https://peer.example/public/oobi/EVictim", nil, false},
		"a name that resolves inside":   {store.ContactRecord{AID: aid, OobiURL: "https://rebind.example/public/oobi/" + aid}, "https://rebind.example/public/oobi/" + aid, []net.IP{net.ParseIP("169.254.169.254")}, false},
		"a name that resolves to lo":    {store.ContactRecord{AID: aid, OobiURL: "https://rebind.example/public/oobi/" + aid}, "", []net.IP{net.ParseIP("127.0.0.1")}, false},
		"a name that resolves to 10.x":  {store.ContactRecord{AID: aid, OobiURL: "https://rebind.example/public/oobi/" + aid}, "", []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("10.0.0.5")}, false},
		"a local agent that is itself":  {store.ContactRecord{AID: aid, OobiURL: "http://127.0.0.1:5050/public/oobi/" + aid}, "http://127.0.0.1:5050/public/oobi/" + aid, nil, true},
		"a recorded address on 169.254": {store.ContactRecord{AID: aid, OobiURL: "http://169.254.169.254/public/oobi/" + aid}, "", nil, true},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if c.resolve != nil {
				lookupHost = func(string) ([]net.IP, error) { return c.resolve, nil }
				defer func() {
					lookupHost = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("93.184.216.34")}, nil }
				}()
			}
			s, _, cap := answerer(t, map[string]store.ContactRecord{aid: c.contact})
			err := s.SendAcceptCallback(context.Background(), c.signed, declined(aid))
			if c.post {
				if err != nil || len(cap.posts) != 1 || !strings.HasSuffix(cap.posts[0].URL, "/api/witness/accept") ||
					!strings.HasPrefix(cap.posts[0].URL, strings.SplitN(c.contact.OobiURL, "/public", 2)[0]) {
					t.Fatalf("err %v, posts %+v", err, cap.posts)
				}
				return
			}
			if err == nil || len(cap.posts) != 0 {
				t.Fatalf("an answer went where it must not: err %v, posts %+v", err, cap.posts)
			}
		})
	}
}

// A contact not yet accepted, such as a stranger left as pending by first
// contact, gets no task and no callback, however many signed requests it sends.
func TestAContactNotYetAcceptedGetsNoTaskAndNoCallback(t *testing.T) {
	const aid = "ERequester0000000000000000000000000000000000022"
	for _, status := range []string{"pending_inbound", "pending_outbound", ""} {
		t.Run("status "+status, func(t *testing.T) {
			pub, seed := identityKey(t)
			oobi := "https://peer.example/public/oobi/" + aid
			lookupHost = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("93.184.216.34")}, nil }
			t.Cleanup(func() { lookupHost = net.LookupIP })
			s, mc, cap := answerer(t, map[string]store.ContactRecord{aid: {AID: aid, Status: status, PublicKey: pub, OobiURL: oobi}})
			for i := 0; i < 3; i++ {
				stamp := time.Now().Add(time.Duration(i) * time.Second).UTC().Format(time.RFC3339Nano)
				sig, _ := login.SignString(RequestStatement(aid, s.Identity(), oobi, BackendDesktop, "r", false, stamp), seed)
				res := s.ProcessInboundRequest(context.Background(), WitnessRequest{
					RequesterAID: aid, RequesterOOBI: oobi, BackendType: BackendDesktop, RequestID: "r", Stamp: stamp, Signature: sig,
				})
				if res.Accepted || res.TaskID != "" || res.Reason != "contact_not_accepted" {
					t.Fatalf("request %d: %+v", i, res)
				}
			}
			time.Sleep(50 * time.Millisecond)
			if tasks, _ := mc.GetTasks(); len(tasks) != 0 {
				t.Fatalf("tasks were stored for a contact not accepted: %+v", tasks)
			}
			if len(cap.posts) != 0 {
				t.Fatalf("something was posted to %s", cap.posts[0].URL)
			}
		})
	}
}

type failingMetaStore struct {
	Store
	failDelete bool
}

func (f failingMetaStore) DeleteContactMeta(aid string) error {
	if f.failDelete {
		return errors.New("disk full")
	}
	return f.Store.DeleteContactMeta(aid)
}

// Undoing an enrolment where there was no earlier record leaves none, and an
// undo that fails says so.
func TestUndoingAnEnrolmentDeletesWhatWasNotThereBeforeAndReportsFailure(t *testing.T) {
	const aid = "EResponder000000000000000000000000000000000023"
	s, _, _ := answerer(t, map[string]store.ContactRecord{aid: {AID: aid, Status: "accepted", ContactCategory: "trusted"}})
	undo, err := s.enrollWitnessForUsUndoably(aid, BackendDesktop)
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := s.Store.GetContactMeta(aid); m == nil || m.EnrolledAt == "" {
		t.Fatalf("not enrolled: %+v", m)
	}
	if err := undo(); err != nil {
		t.Fatal(err)
	}
	if m, _ := s.Store.GetContactMeta(aid); m != nil {
		t.Fatalf("an empty or enrolled row was left behind: %+v", m)
	}
	if c, _ := s.Contacts.GetContact(aid); c == nil || c.IsWitness {
		t.Fatalf("the contact was not put back: %+v", c)
	}

	real := s.Store
	s.Store = failingMetaStore{Store: real, failDelete: true}
	undo, err = s.enrollWitnessForUsUndoably(aid, BackendDesktop)
	if err != nil {
		t.Fatal(err)
	}
	if err := undo(); err == nil {
		t.Fatal("an undo that could not delete reported success")
	}
}
