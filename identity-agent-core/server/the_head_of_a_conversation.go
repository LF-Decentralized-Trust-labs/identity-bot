package server

import (
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"identity-agent-core/conversationbundle"
	"identity-agent-core/didcomm"
	"identity-agent-core/internal/jsonreply"
)

// The head and count of a conversation an app keeps (ADR-068, contracts/trail).
//
// For such a conversation the Identity Agent keeps only the fingerprint of the
// trail: the head (the hash of the newest committed entry) and the count (how
// many are committed). The entries and the words are the app's, and a reader
// checks the app's copy against what this route answers. The store of the head
// and the count is an add-on's, as the rest of the trail is, so the core asks
// the add-ons (Addon.ConversationHead), serves who may be told, and signs the
// statement an export carries.

// CapabilityConversationHeadRead is what an app's App Grant must hold to ask the
// head of a conversation it keeps.
const CapabilityConversationHeadRead = "conversation.head.read"

// ConversationHead is what an add-on that keeps conversations says about one.
type ConversationHead struct {
	// Count is the number of committed entries, which equals the newest seq.
	Count int
	// Head is the hash of the newest committed entry, empty when Count is 0.
	Head string
	// App is the identifier of the app that keeps the conversation, empty for a
	// conversation no app keeps (its whole trail is in the Identity Agent).
	App string
}

// errConversationUnknown is every reason a caller is told nothing about a
// conversation: there is none, it is not this app's, or no add-on here keeps
// conversations. The words are the same for each, so the route does not say
// which conversations exist.
var errConversationUnknown = errors.New("there is no such conversation for this caller")

// theHeadOf asks the add-ons for conversation id. With none that keeps
// conversations, or none holding it, the conversation is unknown; one that fails
// makes the answer fail; and one more than one add-on says it holds fails
// rather than being answered by one of them.
func (s *CoreServer) theHeadOf(id string) (ConversationHead, error) {
	var found ConversationHead
	holders := 0
	for _, a := range registeredAddons() {
		if a.ConversationHead == nil {
			continue
		}
		h, held, err := a.ConversationHead(s, id)
		if err != nil {
			return ConversationHead{}, err
		}
		if held {
			holders++
			found = h
		}
	}
	switch {
	case holders == 0:
		return ConversationHead{}, errConversationUnknown
	case holders > 1:
		return ConversationHead{}, errConversationHeldTwice
	case found.Count < 0 || (found.Count == 0) != (found.Head == ""):
		return ConversationHead{}, errors.New("the add-on that keeps this conversation reported a head that does not fit its count")
	}
	return found, nil
}

// conversationHeadRoutes mounts the route. Owner-class: the owner's own keys
// and front end, and an app signing as the app (coreAppRoutes), which the
// handler holds to the conversation that app keeps.
func (s *CoreServer) conversationHeadRoutes(r chi.Router) {
	r.Get("/conversations/{id}/head", s.handleConversationHead)
}

// TheHeadReply is the route's answer.
type TheHeadReply struct {
	Conversation string `json:"conversation"`
	Count        int    `json:"count"`
	Head         string `json:"head"`
}

func (s *CoreServer) handleConversationHead(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	h, err := s.theHeadOf(id)
	if err == nil {
		// An app is told only of a conversation it keeps. The owner is told of any.
		if app, isApp := TheAppThatAsked(r); isApp && (h.App == "" || h.App != app.AID) {
			err = errConversationUnknown
		}
	}
	if errors.Is(err, errConversationUnknown) {
		jsonreply.Write(w, http.StatusNotFound, map[string]string{"error": errConversationUnknown.Error()})
		return
	}
	if err != nil {
		jsonreply.Write(w, http.StatusInternalServerError, map[string]string{"error": "the head of this conversation could not be read"})
		return
	}
	jsonreply.Write(w, http.StatusOK, TheHeadReply{Conversation: id, Count: h.Count, Head: h.Head})
}

// SignTheHeadOf is the Identity Agent's signed statement of a conversation's
// count and head as they stand now, for an export to carry
// (conversationbundle.HeadStatement). It is the same count and head the route
// answers, signed with the messaging key of the identity that countersigns a
// person's entries.
func (s *CoreServer) SignTheHeadOf(id string) (*didcomm.Envelope, error) {
	h, err := s.theHeadOf(id)
	if err != nil {
		return nil, err
	}
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil || identity.AID == "" {
		return nil, errors.New("this Identity Agent has no identity to sign a head statement as")
	}
	return conversationbundle.SignHead(identity.AID, func(m *didcomm.JWM) (*didcomm.Envelope, error) {
		return s.packSignedAs(identity.AID, m)
	}, conversationbundle.HeadStatement{
		Conversation: id, Count: h.Count, Head: h.Head,
		IATime: time.Now().UTC().Format(time.RFC3339Nano),
	})
}
