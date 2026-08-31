package recovery

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"identity-agent-core/backup"
)

// Gathering shares, which is what a recovering machine spends the wait doing.
//
// It asks EVERY holder the bootstrap envelope names, and keeps whatever comes
// back.
//
// Every one, deliberately, rather than stopping at k. Stopping early tells
// fewer holders that a recovery is happening, which sounds like the more
// private thing — but the owner being told is the property this whole design
// has that no other configuration does, and it is the honest owner's only
// warning that somebody is using their words. A thief running this software
// can stop early whenever they like; we should not do it for them. It does not stop at the first
// refusal: a holder that is waiting, a holder whose owner has not approved
// yet, and a holder nobody can reach are all ordinary, and any of them would
// otherwise end a recovery that the remaining holders could have completed.
// That is what a threshold is for.

// AskedAHolder is what came back from one holder.
type AskedAHolder struct {
	HolderID string `json:"holder_id"`
	Kind     string `json:"kind"`
	// Released says the share came back.
	Released bool `json:"released"`
	// ReleaseAfter is when a holder that is waiting expects to release.
	ReleaseAfter string `json:"release_after,omitempty"`
	// Why is what to put on a screen when nothing came back.
	Why string `json:"why,omitempty"`
}

// WhereTheSharesGotTo is the state of gathering, for a screen to show.
type WhereTheSharesGotTo struct {
	Needed   int            `json:"needed"`
	Gathered int            `json:"gathered"`
	Holders  []AskedAHolder `json:"holders"`
}

// Enough reports whether the archive can be opened now.
func (w WhereTheSharesGotTo) Enough() bool { return w.Gathered >= w.Needed }

// GatherShares asks every holder in an envelope and returns what came back.
//
// The shares map is what to pass to OpenArchive. A caller may call this
// repeatedly across the days a wait takes; nothing here is stateful, because
// the state that matters — when each holder was first asked — belongs to the
// holders, and is deliberately not something a recovering machine can hold an
// opinion about.
func GatherShares(env *backup.WhatTheWordsOpen, client *http.Client) (map[string][]byte, WhereTheSharesGotTo, error) {
	if env == nil {
		return nil, WhereTheSharesGotTo{}, fmt.Errorf("there is no envelope to read holders from")
	}
	if client == nil {
		// Short, and deliberately so. Holders are asked one after another, so
		// a long timeout multiplies: five unreachable holders at twenty
		// seconds each is a hundred seconds of nothing on the screen of
		// somebody who has just lost their identity. A holder that has not
		// answered in six seconds is one to come back to, and coming back is
		// free — nothing here is stateful, and the clock that matters belongs
		// to the holders.
		client = &http.Client{Timeout: 6 * time.Second}
	}

	sealedBy := map[string]backup.SealedShare{}
	for _, s := range env.SealedShares {
		sealedBy[s.HolderID] = s
	}

	shares := map[string][]byte{}
	state := WhereTheSharesGotTo{Needed: env.Split.Needed}

	holders := append([]backup.ShareHolder{}, env.Split.Holders...)
	sort.Slice(holders, func(i, j int) bool { return holders[i].ID < holders[j].ID })

	for _, h := range holders {
		asked := AskedAHolder{HolderID: h.ID, Kind: h.Kind}

		sealed, ok := sealedBy[h.ID]
		if !ok {
			asked.Why = "this backup carries no share for that holder"
			state.Holders = append(state.Holders, asked)
			continue
		}
		if strings.TrimSpace(h.Address) == "" {
			// A passphrase has nowhere to be asked, and a holder with no
			// address is one the owner has to reach some other way.
			asked.Why = "there is nowhere to ask this holder"
			state.Holders = append(state.Holders, asked)
			continue
		}

		// What THIS holder knows the relationship by, never the identity's own
		// AID. A holder protects somebody without being told who they are.
		knownAs := h.KnownAs
		if knownAs == "" {
			knownAs = env.IdentityAID
		}
		share, releaseAfter, err := askOneHolder(client, h, knownAs, sealed)
		if err != nil {
			asked.Why = err.Error()
			asked.ReleaseAfter = releaseAfter
			state.Holders = append(state.Holders, asked)
			continue
		}
		shares[h.ID] = share
		asked.Released = true
		state.Holders = append(state.Holders, asked)
		state.Gathered++
	}
	return shares, state, nil
}

func askOneHolder(client *http.Client, h backup.ShareHolder, knownAs string,
	sealed backup.SealedShare) (share []byte, releaseAfter string, err error) {

	body, err := json.Marshal(map[string]interface{}{
		"identity_aid": knownAs,
		"holder_id":    h.ID,
		"sealed_share": sealed,
	})
	if err != nil {
		return nil, "", err
	}
	url := strings.TrimRight(h.Address, "/") + "/api/recovery/share-requests"
	resp, err := client.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		// Deliberately not the raw error: it carries the address, the port and
		// an errno, and this is read by somebody in the middle of losing their
		// identity.
		return nil, "", fmt.Errorf("this holder could not be reached")
	}
	defer resp.Body.Close()

	var answer struct {
		ShareB64     string `json:"share_b64"`
		Detail       string `json:"detail"`
		Error        string `json:"error"`
		ReleaseAfter string `json:"release_after"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&answer)

	if resp.StatusCode == http.StatusOK && answer.ShareB64 != "" {
		raw, derr := backup.DecodeB64(answer.ShareB64)
		if derr != nil {
			return nil, "", fmt.Errorf("this holder answered with something unreadable")
		}
		return raw, "", nil
	}
	// What a holder SAYS never reaches the screen.
	//
	// The reply comes from a machine somebody else runs, and it was being
	// copied verbatim into the field whose own job is to be shown to a person
	// mid-recovery. A compromised or malicious holder could therefore write
	// the text on the one screen where the reader is most likely to do as they
	// are told — "your recovery has been suspended for fraud, call this number
	// with your recovery words" is a sentence it could put in front of them.
	//
	// So the status decides the wording, and it is ours. A holder can refuse,
	// stall, or lie about which of those it is doing; it cannot choose the
	// words.
	return nil, sanitisedReleaseAfter(answer.ReleaseAfter), whyFromStatus(resp.StatusCode)
}

// whyFromStatus turns a holder's answer into wording of our own.
func whyFromStatus(status int) error {
	switch status {
	case http.StatusConflict:
		// Held, or waiting for a person. Both mean "not yet", which is what
		// somebody needs to know; which of the two is the holder's own screen
		// to explain, not this one's.
		return fmt.Errorf("this holder has not released its share yet")
	case http.StatusForbidden:
		return fmt.Errorf("this holder will not release a share for this backup")
	case http.StatusNotFound:
		return fmt.Errorf("this holder does not answer requests for shares")
	default:
		return fmt.Errorf("this holder did not release its share")
	}
}

// sanitisedReleaseAfter accepts a timestamp and nothing else.
//
// It is shown to somebody, so it must be a time rather than whatever a holder
// felt like sending. An unparseable value is dropped rather than displayed.
func sanitisedReleaseAfter(v string) string {
	if v == "" {
		return ""
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
