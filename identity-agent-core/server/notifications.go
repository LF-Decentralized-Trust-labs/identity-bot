package server

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"identity-agent-core/didcomm"
	"identity-agent-core/store"
)

// Notifications: what another agent has told this one.
//
// There was nowhere to put such a thing. /api/alerts computed itself on every
// request from pending contacts, pending requests and pending credentials — a
// view over three approval queues, owning no table. So the only party who could
// tell the user anything was one asking their permission, and anything else, at
// any urgency, could not be shown at all.
//
// The obvious shortcut would have been a fourth hard-coded case in that view,
// for whatever needed saying first. This is a general mechanism instead: any
// agent already in a relationship with this one can say something, and the core
// does not learn what any particular message means. The alternative ends as a
// list of special cases, each added by whoever needed it, none of them reusable.
//
// It also absorbs the DIDComm inbox, which was a second inbox with the same
// fields — from, to, type, body, verified — kept in a flat JSON file with no id,
// no read state and no pruning. Two inboxes with overlapping fields and
// different storage is the kind of duplication that is easy to add and very hard
// to remove later.

// notificationBody is what a sender puts in a notification message.
//
// Deliberately small. A sender that wants to say more puts it in the payload,
// which is stored verbatim and never interpreted here.
type notificationBody struct {
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Body     string `json:"body"`
	// ExpiresAt lets a sender say when a message stops being worth showing —
	// a deadline that has passed is noise.
	ExpiresAt string `json:"expires_at"`
}

// storeInboundAsNotification records a verified inbound message.
//
// Called only after the envelope has been unpacked and verified, so from and to
// are the AUTHENTICATED header values. They are passed in rather than read from
// the message body on purpose: a sender that could name itself in a field the
// core trusted could put anyone's identifier there.
func (s *CoreServer) storeInboundAsNotification(fromAID, toAID string, jwm *didcomm.JWM, verified bool) {
	n := store.Notification{
		ID:         jwm.ID,
		FromAID:    fromAID,
		ToAID:      toAID,
		Kind:       jwm.Type,
		Severity:   store.NotificationInfo,
		Status:     store.NotificationUnread,
		Verified:   verified,
		ReceivedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if len(jwm.Body) > 0 {
		n.Payload = string(jwm.Body)
	}

	// A message of the notification type carries text meant for a person. Any
	// other type is still recorded — it is still something that arrived — but
	// its title is the type, because the core cannot summarise a payload whose
	// meaning belongs to the sender.
	if jwm.Type == didcomm.TypeNotification {
		var b notificationBody
		if err := json.Unmarshal(jwm.Body, &b); err == nil {
			if b.Kind != "" {
				n.Kind = b.Kind
			}
			n.Title = strings.TrimSpace(b.Title)
			n.Body = strings.TrimSpace(b.Body)
			n.ExpiresAt = b.ExpiresAt
			switch b.Severity {
			case store.NotificationInfo, store.NotificationWarning, store.NotificationCritical:
				n.Severity = b.Severity
			}
		}
	}
	if n.Title == "" {
		n.Title = jwm.Type
	}

	// Logged rather than returned. The caller has already accepted the envelope
	// — it verified, it was fresh, it was not a replay — so failing the request
	// now would make the sender retry a message this agent has already taken
	// delivery of. Losing it is bad; losing it silently is what the log is for.
	if err := s.DataStore.SaveNotification(n); err != nil {
		log.Printf("[identity-agent-core] could not store a message from %s: %v", fromAID, err)
	}
}

// handleGetNotifications lists what has arrived, newest first.
func (s *CoreServer) handleGetNotifications(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		jsonError(w, "notifications are owner only", http.StatusForbidden)
		return
	}
	status := r.URL.Query().Get("status")
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))

	list, err := s.DataStore.GetNotifications(status, limit)
	if err != nil {
		jsonError(w, "failed to read notifications", http.StatusInternalServerError)
		return
	}
	if list == nil {
		list = []store.Notification{}
	}

	unread := 0
	for _, n := range list {
		if n.Status == store.NotificationUnread {
			unread++
		}
	}
	jsonResponse(w, map[string]any{
		"notifications": list,
		"unread":        unread,
	})
}

// handleSetNotificationStatus marks one read or dismissed.
func (s *CoreServer) handleSetNotificationStatus(w http.ResponseWriter, r *http.Request) {
	if !s.isOwner(r) {
		jsonError(w, "notifications are owner only", http.StatusForbidden)
		return
	}
	var req struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := s.DataStore.SetNotificationStatus(req.ID, req.Status); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonResponse(w, map[string]any{"status": req.Status})
}

// unreadNotifications is what /api/alerts adds to its response.
//
// Errors become an empty list rather than a failure, matching how that handler
// already treats its other two queries: an alert view that returns nothing at
// all because one of four sources is unavailable is worse than one missing a
// section.
func (s *CoreServer) unreadNotifications() []store.Notification {
	list, err := s.DataStore.GetNotifications(store.NotificationUnread, 0)
	if err != nil || list == nil {
		return []store.Notification{}
	}
	return list
}
