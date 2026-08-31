package server

import (
	"encoding/json"
	"net/http"
	"strconv"

	"identity-agent-core/backup"
	"identity-agent-core/recovery"
)

// Choosing who holds a share of your recovery.
//
// The mechanism for shares exists and until now there was no way to reach it:
// a caller could pass a set of holders to one export, and a person could set
// nothing. So every archive was still opened by the recovery words alone,
// which is the thing all of it was built to stop.
//
// Everything refused here is refused at the moment somebody CHOOSES it rather
// than during a recovery. A configuration that could never be satisfied does
// not protect an owner from an attacker; it protects the identity from its
// owner, and the worst possible moment to discover that is the one moment they
// need it.

// whoHoldsYourRecovery is what a screen shows and sets.
type whoHoldsYourRecovery struct {
	// Needed is how many shares must come back. Zero with no holders means
	// the recovery words alone, which is a real answer.
	Needed int `json:"needed"`
	// Holders is who has one.
	Holders []backup.ShareHolder `json:"holders"`
	// SayThis is what the screen must tell somebody about the choice they
	// have made, or is empty when there is nothing to say. Written here rather
	// than in the client so that both apps say the same thing and neither has
	// to work out what a configuration costs.
	SayThis string `json:"say_this,omitempty"`
}

func (s *CoreServer) handleGetWhoHoldsYourRecovery(w http.ResponseWriter, r *http.Request) {
	cfg, err := s.backupService().LoadConfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not read this setting", err.Error())
		return
	}
	writeJSONResponse(w, whoHoldsYourRecovery{
		Needed:  cfg.Split.Needed,
		Holders: cfg.Split.Holders,
		SayThis: whatThisChoiceCosts(cfg.Split),
	})
}

// handleSetWhoHoldsYourRecovery records who holds a share, and refuses a
// choice that cannot do what somebody picking it believes.
func (s *CoreServer) handleSetWhoHoldsYourRecovery(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxShareRequestBody)
	var req whoHoldsYourRecovery
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request", err.Error())
		return
	}

	split := backup.HowTheWayInIsSplit{Needed: req.Needed, Holders: req.Holders}

	// Turning it off is allowed and is not a failure. Somebody may have
	// decided the words alone suit them, and refusing to let them say so would
	// leave the setting one-way.
	if len(split.Holders) == 0 {
		if err := s.storeSplit(backup.HowTheWayInIsSplit{}); err != nil {
			writeError(w, http.StatusInternalServerError, "Could not save this setting", err.Error())
			return
		}
		writeJSONResponse(w, whoHoldsYourRecovery{SayThis: whatThisChoiceCosts(
			backup.HowTheWayInIsSplit{})})
		return
	}

	if err := split.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "That would not work", err.Error())
		return
	}
	if split.OnlyShareIsAPassphrase() {
		// An attacker holds the file and can try every short secret offline,
		// without asking anybody and without anything noticing. As the only
		// share that is a way in rather than a share.
		writeError(w, http.StatusBadRequest, "That would not protect this backup",
			"a passphrase cannot be the only thing protecting this backup besides the "+
				"recovery words: add a device or a person")
		return
	}

	if err := s.storeSplit(split); err != nil {
		writeError(w, http.StatusInternalServerError, "Could not save this setting", err.Error())
		return
	}

	// Answered with what was stored and what it costs, so the screen shows the
	// consequence of the choice rather than the request being echoed back.
	writeJSONResponse(w, whoHoldsYourRecovery{
		Needed:  split.Needed,
		Holders: split.Holders,
		SayThis: whatThisChoiceCosts(split),
	})
}

func (s *CoreServer) storeSplit(split backup.HowTheWayInIsSplit) error {
	cfg, err := s.backupService().LoadConfig()
	if err != nil {
		return err
	}
	cfg.Split = split
	return s.backupService().SaveConfig(cfg)
}

// whatThisChoiceCosts is what a screen must say about a configuration.
//
// In the core rather than in either app, so both say the same thing and
// neither has to work out for itself what a threshold of one means. A person
// choosing this is deciding what happens on the worst day of their year and
// should be told plainly, once, in the same words wherever they are standing.
func whatThisChoiceCosts(split backup.HowTheWayInIsSplit) string {
	if len(split.Holders) == 0 {
		return "Your recovery words alone open your backup. Anybody who gets hold of both " +
			"can read everything in it, and nothing will tell you it happened."
	}
	if split.Needed <= 1 {
		return "Any single one of these, plus your recovery words, opens your backup. " +
			"That is one thing to lose rather than several."
	}
	if said := recovery.AskForMorePeople(split.Holders); said != "" {
		return said
	}
	// Said even when everything is right, because the thing being given up is
	// real and somebody should learn it here rather than during a recovery.
	return "Your recovery words are no longer enough on their own. To get back in you " +
		"will need them and " + plural(split.Needed) + " — so keep them somewhere you " +
		"can still reach after losing everything else."
}

func plural(n int) string {
	if n == 1 {
		return "one of these"
	}
	return "any " + itoa(n) + " of these"
}

func itoa(n int) string { return strconv.Itoa(n) }
