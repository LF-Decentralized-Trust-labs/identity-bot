package recovery

import (
	"fmt"

	"identity-agent-core/store"
)

// NotifyPartyKind identifies a member of the root-AID rotation notify set.
type NotifyPartyKind string

const (
	NotifyWitness NotifyPartyKind = "witness"
	NotifyWatcher NotifyPartyKind = "watcher"
	NotifyIssuer  NotifyPartyKind = "issuer"
)

// NotifyParty is one recipient that must learn about a new root AID and continuity anchor.
type NotifyParty struct {
	Kind  NotifyPartyKind `json:"kind"`
	AID   string          `json:"aid,omitempty"`
	URL   string          `json:"url,omitempty"`
	Alias string          `json:"alias,omitempty"`
}

// NotifySet aggregates witnesses, watchers, and issuers bound to the prior root AID.
type NotifySet struct {
	Witnesses []NotifyParty `json:"witnesses"`
	Watchers  []NotifyParty `json:"watchers"`
	Issuers   []NotifyParty `json:"issuers"`
}

// All returns every party in stable witness → watcher → issuer order.
func (n *NotifySet) All() []NotifyParty {
	if n == nil {
		return nil
	}
	out := make([]NotifyParty, 0, len(n.Witnesses)+len(n.Watchers)+len(n.Issuers))
	out = append(out, n.Witnesses...)
	out = append(out, n.Watchers...)
	out = append(out, n.Issuers...)
	return out
}

// NotifySetSource reads contacts, credentials, and optional watcher hints from the store layer.
type NotifySetSource interface {
	GetIdentity() (*store.IdentityState, error)
	GetContacts() ([]store.ContactRecord, error)
	GetCredentials() ([]store.CredentialRecord, error)
}

// BuildNotifySet collects witnesses (contacts), watcher URLs, and issuers whose
// credentials name the root AID as holder.
func BuildNotifySet(src NotifySetSource, rootAID string, watcherHints []string) (*NotifySet, error) {
	if src == nil {
		return nil, fmt.Errorf("notify set source is required")
	}
	if rootAID == "" {
		return nil, fmt.Errorf("root AID is required")
	}

	set := &NotifySet{
		Witnesses: []NotifyParty{},
		Watchers:  []NotifyParty{},
		Issuers:   []NotifyParty{},
	}

	contacts, err := src.GetContacts()
	if err != nil {
		return nil, fmt.Errorf("load contacts: %w", err)
	}
	for _, c := range contacts {
		if !c.IsWitness || c.Status != "accepted" {
			continue
		}
		set.Witnesses = append(set.Witnesses, NotifyParty{
			Kind:  NotifyWitness,
			AID:   c.AID,
			URL:   c.OobiURL,
			Alias: c.Alias,
		})
	}

	for _, url := range watcherHints {
		if url == "" {
			continue
		}
		set.Watchers = append(set.Watchers, NotifyParty{
			Kind: NotifyWatcher,
			URL:  url,
		})
	}

	creds, err := src.GetCredentials()
	if err != nil {
		return nil, fmt.Errorf("load credentials: %w", err)
	}
	seenIssuers := map[string]struct{}{}
	for _, cred := range creds {
		if cred.HolderAID != rootAID || cred.IssuerAID == "" {
			continue
		}
		if _, ok := seenIssuers[cred.IssuerAID]; ok {
			continue
		}
		seenIssuers[cred.IssuerAID] = struct{}{}
		alias := cred.IssuerName
		if alias == "" {
			alias = cred.IssuerAID
		}
		set.Issuers = append(set.Issuers, NotifyParty{
			Kind:  NotifyIssuer,
			AID:   cred.IssuerAID,
			Alias: alias,
		})
	}

	return set, nil
}

// FilterCarryForwardContacts keeps only accepted contacts whose AID is listed in carryForward.
// An empty carryForward list means no relationships are carried forward.
func FilterCarryForwardContacts(contacts []store.ContactRecord, carryForward []string) []store.ContactRecord {
	if len(carryForward) == 0 {
		return nil
	}
	allowed := make(map[string]struct{}, len(carryForward))
	for _, aid := range carryForward {
		if aid != "" {
			allowed[aid] = struct{}{}
		}
	}
	var out []store.ContactRecord
	for _, c := range contacts {
		if c.Status != "accepted" {
			continue
		}
		if _, ok := allowed[c.AID]; ok {
			out = append(out, c)
		}
	}
	return out
}
