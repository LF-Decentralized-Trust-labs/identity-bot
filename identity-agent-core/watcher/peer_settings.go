package watcher

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

// What the owner controls about peer cross-checks.
//
// Asking a peer about an identity tells that peer whom this agent is dealing
// with, so who is asked is the owner's call, held as two stored values in
// watcher_config:
//
//	peer_watch_enabled  "true" turns peer cross-checks on
//	                    (anything else, or nothing stored, leaves them off)
//	peer_watch_aids     a JSON list of the contacts the owner chose
//
// No contact is asked until the owner has chosen it, and never more than
// MaxChosenPeers of them. Registered watcher services are not chosen this way
// (they serve a large population and disclose little) but they are switched
// off by the same enabled value.
//
// peer_watch_aids is read and written by the owner through /api/watcher/peers.
// No owner route reads or writes peer_watch_enabled or public_watcher_service
// yet; until one does, they are set directly in the store.
//
// public_watcher_service "true" makes this agent answer /public/kel-digest
// truthfully to anybody, as a public watcher service does. It is off by default:
// an agent that answers it for every identity it holds lets anyone list whom its
// owner deals with and when.

const (
	configPeerWatchEnabled = "peer_watch_enabled"
	configPeerWatchAIDs    = "peer_watch_aids"
	configPublicWatcher    = "public_watcher_service"
)

// MaxChosenPeers bounds how many contacts an owner can have asked.
const MaxChosenPeers = 5

// PeerWatchEnabled reports whether peer cross-checks are on. Off unless the
// stored value is exactly true: asking a contact tells it whom this agent deals
// with, so it happens only when the owner has turned it on.
func (s *Service) PeerWatchEnabled() bool {
	if s.Store == nil {
		return false
	}
	v, _ := s.Store.GetConfig(configPeerWatchEnabled)
	on, err := strconv.ParseBool(strings.TrimSpace(v))
	return err == nil && on
}

// PublicWatcherService reports whether the owner opted this agent in as a public
// watcher service. Off unless the stored value is exactly true.
func (s *Service) PublicWatcherService() bool {
	if s.Store == nil {
		return false
	}
	v, _ := s.Store.GetConfig(configPublicWatcher)
	on, err := strconv.ParseBool(strings.TrimSpace(v))
	return err == nil && on
}

var errNoStore = errors.New("the watcher has no store to keep settings in")

// SetPeerWatchEnabled turns peer cross-checks on or off.
func (s *Service) SetPeerWatchEnabled(on bool) error {
	if s.Store == nil {
		return errNoStore
	}
	return s.Store.SetConfig(configPeerWatchEnabled, strconv.FormatBool(on))
}

// ChosenPeers is the contacts the owner chose to be asked, at most MaxChosenPeers.
func (s *Service) ChosenPeers() []string {
	if s.Store == nil {
		return nil
	}
	raw, _ := s.Store.GetConfig(configPeerWatchAIDs)
	var all []string
	if raw == "" || json.Unmarshal([]byte(raw), &all) != nil {
		return nil
	}
	if len(all) > MaxChosenPeers {
		all = all[:MaxChosenPeers]
	}
	return all
}

// SetChosenPeers records the contacts to ask. More than MaxChosenPeers is
// refused rather than trimmed, so the owner is never told a peer is chosen
// when it is not.
func (s *Service) SetChosenPeers(aids []string) error {
	if s.Store == nil {
		return errNoStore
	}
	if len(aids) > MaxChosenPeers {
		return errTooManyPeers
	}
	b, err := json.Marshal(aids)
	if err != nil {
		return err
	}
	return s.Store.SetConfig(configPeerWatchAIDs, string(b))
}
