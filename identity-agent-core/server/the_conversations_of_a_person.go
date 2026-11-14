package server

import (
	"errors"
	"net/http"
	"sort"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/agentmessage"
	"identity-agent-core/internal/jsonreply"
)

// A person lists their own conversations, across every utility app that keeps
// one (ADR-072 Amendment 7).
//
// The route is for the one utility app an owner has chosen to be a person's
// central place. Its back end carries the person's own signed statement of kind
// list (agentmessage.PersonKindList), exactly as it carries a statement for the
// words a person says (an_app_speaks_for_a_person_who_signed.go), and the core
// lists for the person that statement names and for nobody else. The Identity
// Agent holds, for each conversation, the keeper, the head, the count, the
// parties and any open ask, and nothing else (ADR-068): so the listing carries
// no title, no change time and no words. Each utility app's back end serves its
// own title and last change.

// CapabilityConversationListRead is what a utility app's App Grant must hold to
// list a person's conversations across utility apps. The owner gives it only to
// the one utility app that is the central place, when the utility app is made.
const CapabilityConversationListRead = "conversation.list.read"

// ConversationOfAPerson is one conversation a person is a party to, as an
// add-on that keeps conversations says it.
type ConversationOfAPerson struct {
	Conversation string `json:"conversation"`
	// App is the asset id of the utility app that keeps the conversation, empty
	// when none does (its whole trail is in the Identity Agent).
	App string `json:"app"`
	// Head is the hash of the newest committed entry, empty when Count is 0.
	Head  string `json:"head"`
	Count int    `json:"count"`
	// OpenAsk says an ask in the conversation has not been answered.
	OpenAsk bool `json:"open_ask"`
}

// ThePeopleConversationsReply is the route's answer.
type ThePeopleConversationsReply struct {
	// ListedAt is the asset id of the utility app whose sign-in named the key
	// that signed the statement: the one party this answer is for, as the
	// person is known there (ADR-072 Amendment 8). One statement is one party:
	// the core never merges the answers for two.
	ListedAt      string                  `json:"listed_at"`
	Conversations []ConversationOfAPerson `json:"conversations"`
}

var errNoAddonKeepsConversations = errors.New("no add-on that keeps conversations can say which a person is in")

var errConversationsHeldTwice = errors.New("a conversation is held by two add-ons")

// theConversationsOf asks every add-on that keeps conversations for those the
// party (agentmessage.Person of the person's identifier) is in, in a fixed
// order. One that fails fails the answer: a list that silently left some out
// would be read as the whole of what the person has. A conversation two
// add-ons hold, or one whose head does not fit its count, is an error too, as
// for the head route (theHeadOf).
func (s *CoreServer) theConversationsOf(party string) ([]ConversationOfAPerson, error) {
	seen := map[string]bool{}
	out := []ConversationOfAPerson{}
	asked := 0
	for _, a := range registeredAddons() {
		if a.ConversationsOfAPerson == nil {
			continue
		}
		asked++
		held, err := a.ConversationsOfAPerson(s, party)
		if err != nil {
			return nil, err
		}
		for _, c := range held {
			switch {
			case c.Conversation == "" || c.Conversation == agentmessage.ListConversation:
				return nil, errors.New("an add-on listed a conversation with no usable id")
			case c.Count < 0 || (c.Count == 0) != (c.Head == ""):
				return nil, errors.New("an add-on listed a conversation whose head does not fit its count")
			case seen[c.Conversation]:
				return nil, errConversationsHeldTwice
			}
			seen[c.Conversation] = true
			out = append(out, c)
		}
	}
	// Nobody to ask is not an empty list: an empty list is read as "this person
	// has no conversations", which nobody has said.
	if asked == 0 {
		return nil, errNoAddonKeepsConversations
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Conversation < out[j].Conversation })
	return out, nil
}

// conversationListRoutes mounts the route. It is not an AI agent's. A utility
// app's back end, admitted with the capability above (coreAppRoutes), carries
// the person's own statement. A paired controller is read as the signer it
// belongs to, as on every route made for it (ADR-050), and lists that signer's
// conversations. Any other request has no person behind it, and
// thePersonAsking refuses it.
func (s *CoreServer) conversationListRoutes(r chi.Router) {
	r.Get("/people/me/conversations", s.handleConversationsOfAPerson)
}

func (s *CoreServer) handleConversationsOfAPerson(w http.ResponseWriter, r *http.Request) {
	// The person is the one whose own statement the request carries: the key,
	// the freshness, the one use and the request it is for are judged there.
	person, _, err := s.thePersonAsking(r)
	if err != nil {
		// No person is proved: not the gate's refusal of what a caller may reach
		// (403), so a route open to a controller by ADR-050 is never read as one
		// a handler closed again.
		jsonreply.Write(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	got, err := s.theConversationsOf(agentmessage.Person(person.AID))
	if errors.Is(err, errNoAddonKeepsConversations) {
		// Not a fault of the request, and not an answer: nothing here lists.
		jsonreply.Write(w, http.StatusNotImplemented, map[string]string{"error": err.Error()})
		return
	}
	if err != nil {
		jsonreply.Write(w, http.StatusInternalServerError, map[string]string{"error": "the conversations could not be listed"})
		return
	}
	jsonreply.Write(w, http.StatusOK, ThePeopleConversationsReply{ListedAt: person.Asset, Conversations: got})
}
