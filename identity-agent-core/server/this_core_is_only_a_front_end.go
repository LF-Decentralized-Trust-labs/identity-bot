package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"identity-agent-core/secureenclave"

	"github.com/go-chi/chi/v5"
	"time"
)

// When this computer is only the front end, its own core stops answering about
// an identity it does not have.
//
// THE FAILURE THIS PREVENTS IS SILENT. A core with no identity answers every
// question correctly and about nobody: no credentials, an empty roster, nothing
// to recover. A screen that kept calling this machine after the app was pointed
// elsewhere would show that as the person's own, and nothing on either side
// would report a problem — the request succeeded, the answer was true, and it
// was about the wrong identity.
//
// So it refuses instead, and says why. A screen that reaches the wrong half
// fails where somebody can see it.
//
// AN ALLOW-LIST, WHICH IS THE OPPOSITE OF THE CONTROLLER RULES NEXT DOOR, and
// deliberately. There, a controller is the owner's own front end reaching a
// full agent, so a route added next month should work without anybody granting
// it. Here the question is which routes are about THIS COMPUTER rather than
// about an identity, and a route added next month is about an identity until
// somebody says otherwise. Getting that wrong in this direction is loud.

// AFrontEndFor records that this installation runs only the front half.
type AFrontEndFor struct {
	// AgentAID is which identity the app is a front end for. Recorded
	// alongside the address because an address is not an identity: a relay
	// allocation can be reassigned, and a machine answering at the expected
	// place is not the machine that was authorised.
	AgentAID string `json:"agent_aid"`
	// AgentURL is where that agent is reached.
	AgentURL string `json:"agent_url"`
	Since    string `json:"since"`
}

// Held in memory after the first read, because this is asked on EVERY request.
//
// It is checked before authorisation, so an unauthenticated caller drives it at
// whatever rate they like — and reading and parsing a file inside a
// process-wide lock on that path serialises the whole core behind one syscall,
// on installations that hold their own identity as much as on the front ends
// this is for. The answer changes only when something here writes it, so it is
// read once and remembered.
//
// The cost is that editing the file by hand no longer takes effect until this
// core restarts. That is the right trade: the supported way to change it is the
// route, which updates both, and a file somebody edited underneath a running
// process was never a state to design around.
var (
	frontEndLock  sync.RWMutex
	frontEndKnown bool
	frontEndValue *AFrontEndFor
	frontEndErr   error
	frontEndOf    string
)

func (s *CoreServer) frontEndFile() string {
	return filepath.Join(s.DataDir, "this-core-is-only-a-front-end.json")
}

// forgetTheCachedFrontEnd drops what is remembered, so the next ask reads.
//
// Called by both writers rather than having them update the cache directly: the
// file is what decides, and a cache written from what a caller MEANT to store
// would disagree with it the first time a write half-succeeded.
func forgetTheCachedFrontEnd() {
	frontEndKnown = false
	frontEndValue = nil
	frontEndErr = nil
	frontEndOf = ""
}

// whatThisCoreIsAFrontEndFor returns the record, or nil when this installation
// holds its own identity.
//
// An unreadable file is an ERROR, never "no record". Read as absent, a file
// that failed to parse would quietly restore this core to answering about
// identities — the exact state the record exists to leave.
func (s *CoreServer) whatThisCoreIsAFrontEndFor() (*AFrontEndFor, error) {
	file := s.frontEndFile()

	frontEndLock.RLock()
	if frontEndKnown && frontEndOf == file {
		v, err := frontEndValue, frontEndErr
		frontEndLock.RUnlock()
		return v, err
	}
	frontEndLock.RUnlock()

	frontEndLock.Lock()
	defer frontEndLock.Unlock()
	// Asked again under the write lock: another request may have read it while
	// this one waited, and reading the file twice is harmless but pointless.
	if frontEndKnown && frontEndOf == file {
		return frontEndValue, frontEndErr
	}
	// The path is part of what is remembered. One process can serve more than
	// one data directory in a test, and a cache that ignored which one it came
	// from would answer for the wrong machine.
	frontEndValue, frontEndErr = s.readFrontEnd()
	frontEndKnown = true
	frontEndOf = file
	return frontEndValue, frontEndErr
}

func (s *CoreServer) readFrontEnd() (*AFrontEndFor, error) {
	raw, err := os.ReadFile(s.frontEndFile())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("could not read whether this computer is only a front end: %w", err)
	}
	var f AFrontEndFor
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("the record of what this computer is a front end for "+
			"could not be read, so it is not being ignored: %w", err)
	}
	if f.AgentAID == "" || f.AgentURL == "" {
		// Half a record is not a record. It is the state the writer refuses to
		// create, so finding one means something else wrote the file.
		return nil, fmt.Errorf("the record names %q at %q — an agent needs both, "+
			"or this computer would trust whatever answers", f.AgentAID, f.AgentURL)
	}
	return &f, nil
}

// beAFrontEndFor records that this installation is the front half for an agent
// elsewhere.
func (s *CoreServer) beAFrontEndFor(f AFrontEndFor) error {
	if strings.TrimSpace(f.AgentAID) == "" || strings.TrimSpace(f.AgentURL) == "" {
		return fmt.Errorf("pointing this computer at an agent needs both where it is " +
			"and which identity it is — an address alone would mean trusting " +
			"whatever answers there")
	}
	frontEndLock.Lock()
	defer frontEndLock.Unlock()
	defer forgetTheCachedFrontEnd()

	// An identity here is not a thing to overwrite. This computer holding one
	// and being a front end for another are different installations, and
	// silently becoming the second would leave a real identity unreachable
	// through the software that holds it.
	if id, err := s.DataStore.GetIdentity(); err == nil && id != nil && id.AID != "" {
		return fmt.Errorf("this computer holds the identity %s, so it is not a front "+
			"end for another — leave that identity first", id.AID)
	}

	f.Since = time.Now().UTC().Format(time.RFC3339)
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	// Written beside and renamed over, never truncated in place. A crash, a
	// power loss or a full disk halfway through a plain write leaves half a
	// record, which reads back as unreadable — and this core then cannot tell
	// which half it is running. A rename is the one step that is all or nothing.
	tmp, err := os.CreateTemp(s.DataDir, filepath.Base(s.frontEndFile())+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), s.frontEndFile()); err != nil {
		return err
	}

	// ASKED AGAIN, AFTER THE WRITE. The guard above and an inception are two
	// owner-only operations on this machine, and nothing holds a lock across
	// both — so an identity founded in between would leave this computer holding
	// one AND carrying a record that makes it refuse every question about it.
	// That is the exact state the guard exists to prevent, and the only way out
	// of it is the route that removes the record.
	//
	// Narrow, because it needs both at once. Cheap to close, because the write
	// has just happened and undoing it is one call.
	if id, err := s.DataStore.GetIdentity(); err == nil && id != nil && id.AID != "" {
		if rerr := os.Remove(s.frontEndFile()); rerr != nil {
			return fmt.Errorf("an identity was founded here while this was being "+
				"recorded, and the record could not be undone (%v) — remove %s by "+
				"hand or this computer will refuse every question about %s",
				rerr, s.frontEndFile(), id.AID)
		}
		return fmt.Errorf("an identity was founded on this computer while this was " +
			"being recorded, so it is not a front end for another")
	}
	return nil
}

// stopBeingAFrontEnd returns this core to answering for itself.
func (s *CoreServer) stopBeingAFrontEnd() error {
	frontEndLock.Lock()
	defer frontEndLock.Unlock()
	defer forgetTheCachedFrontEnd()
	if err := os.Remove(s.frontEndFile()); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// whatAFrontEndAnswersFor is everything this core still serves once it is only
// the front half: what this COMPUTER is, never what an identity is.
//
// Written as patterns rather than paths so it is checked against the same
// strings the router matched, which is what stopped an escaped separator from
// making two matchers disagree elsewhere in this package.
var whatAFrontEndAnswersFor = map[string]string{
	// About this machine as a machine.
	"GET /api/health": "whether this computer's own core is running",
	"GET /api/info":   "what this computer's own core is",

	// The controller's own work, which is the whole reason this core is still
	// running at all.
	"GET /api/controller/this-machine": "what this computer would offer if it acted for an identity",
	"POST /api/controller/sign":        "signing this computer's own asking with its enclave key",
	"GET /api/controller/agent":        "which identity this computer is a front end for",

	// Saying what this installation is, and undoing it.
	"GET /api/controller/front-end-for":    "reading whether this computer is only a front end",
	"POST /api/controller/front-end-for":   "recording that this computer is only a front end",
	"DELETE /api/controller/front-end-for": "returning this computer to holding its own identity",

	// Software on THIS computer. An update installs here, so it is asked here.
	"GET /api/updates/manifest": "which software this computer may install",
	"GET /api/updates/status":   "which software this computer is running",
	"POST /api/updates/apply":   "installing software on this computer",
	"POST /api/updates/check":   "whether newer software exists for this computer",
	"GET /api/updates/settings": "how this computer updates itself",
	"PUT /api/updates/settings": "changing how this computer updates itself",
}

// refuseWhatBelongsToTheAgent answers anything about an identity with a refusal
// naming where the question should have gone — to the owner, and to nobody else.
//
// Placed before authorisation, because whether this core has any business
// answering does not depend on who is asking. WHAT THE REFUSAL SAYS does depend
// on it, and those are different questions: the first line is safe for anybody,
// and the identity and its address are told only to the owner.
//
// Getting that wrong made this worse than what it replaced. This listener is not
// loopback-only, so before the check existed a stranger on the same network
// asking about the identity got a flat refusal from authorisation; with the
// address in the body they got the owner's identifier and the address of the
// machine holding their keys, from one unauthenticated request. Which machines
// may act for an identity is deliberately gated a few files away for being a map
// of somebody's devices; this was the same linkage with no gate at all.
func (s *CoreServer) refuseWhatBelongsToTheAgent(routes chi.Routes) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Both forms, the same way authorize tests them. The decoded path
			// alone fails safe here — anything that routes under /api carries the
			// prefix once decoded — but this file already cites the escaped-
			// separator incident as its reason for matching on patterns, and
			// doing half of that fix invites somebody to re-derive the other half
			// the hard way.
			underTheAPI := strings.HasPrefix(r.URL.Path, "/api/") ||
				strings.HasPrefix(r.URL.EscapedPath(), "/api/")
			if r.Method == http.MethodOptions || !underTheAPI {
				next.ServeHTTP(w, r)
				return
			}

			// The cheap question first: is there anything to decide at all.
			//
			// Asking it is a read lock and two comparisons, with no allocation
			// and no syscall, because the answer is remembered. Working out
			// which route was matched allocates a routing context and walks the
			// trie — twice when the escaped and decoded paths differ — and the
			// authorisation middleware then does the identical work again one
			// step later. So on every installation that holds its own identity,
			// which is nearly all of them, that work was being done twice for
			// nothing, on a path an unauthenticated caller sets the rate of.
			front, err := s.whatThisCoreIsAFrontEndFor()
			if err == nil && front == nil {
				next.ServeHTTP(w, r)
				return
			}

			// Worked out above the unreadable branch on purpose: it is what
			// keeps health and the route that removes the record answerable
			// when the record cannot be read, which is the difference between a
			// machine that can be repaired and one that cannot.
			pattern := matchedRoutePattern(routes, r)
			answersFor := false
			if pattern != "" {
				_, answersFor = whatAFrontEndAnswersFor[r.Method+" "+pattern]
			}

			if err != nil {
				// UNREADABLE, AND THE WAY OUT STAYS OPEN.
				//
				// Refusing everything here bricked the machine: health answered
				// 503, so the app that starts this core decided it was dead and
				// began restarting a backend that was running fine — and the one
				// route that removes the record answered 503 too, so there was no
				// way back through the API at all. A record is written by a
				// request, so a full disk or a crash mid-write is enough to reach
				// this, and the only repair was deleting the file by hand.
				//
				// What this core is FOR still works, because none of it is about
				// an identity. Everything else is refused, which is the safe
				// direction: it cannot tell whether it is entitled to answer.
				if answersFor {
					next.ServeHTTP(w, r)
					return
				}
				writeError(w, http.StatusServiceUnavailable,
					"this computer cannot tell which half it is running", err.Error())
				return
			}
			if answersFor {
				next.ServeHTTP(w, r)
				return
			}

			// Where to ask instead is told to the owner only. To anybody else the
			// refusal is the first line and nothing more — enough to know this
			// machine will not answer, and nothing about whose it is.
			detail := ""
			if s.isOwner(r) {
				detail = fmt.Sprintf("the identity is %s at %s — ask it there. This core "+
					"holds no identity, and an answer from it would be true and about nobody",
					front.AgentAID, front.AgentURL)
			}
			// "Identity Agent", spelled out, because this line is read by a person
			// and the repository's terminology rule exists for exactly that: the
			// bare word is two different things and a reader has to guess which.
			writeError(w, http.StatusConflict,
				"this computer is the front end for an Identity Agent kept elsewhere, "+
					"so it cannot answer this", detail)
		})
	}
}

// --- routes -----------------------------------------------------------------

func (s *CoreServer) handleReadFrontEndFor(w http.ResponseWriter, r *http.Request) {
	front, err := s.whatThisCoreIsAFrontEndFor()
	if err != nil {
		writeError(w, http.StatusInternalServerError,
			"could not read which half this computer is running", err.Error())
		return
	}
	if front == nil {
		writeJSONResponse(w, map[string]interface{}{"front_end_for": nil})
		return
	}
	writeJSONResponse(w, map[string]interface{}{"front_end_for": front})
}

func (s *CoreServer) handleBeAFrontEndFor(w http.ResponseWriter, r *http.Request) {
	var f AFrontEndFor
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&f); err != nil {
		writeError(w, http.StatusBadRequest, "body must be JSON", err.Error())
		return
	}

	// REFUSED IF THIS MACHINE COULD NEVER SIGN, because every single thing a
	// front end does afterwards is signed.
	//
	// A front end holds no identity. It reaches the agent that does, and every
	// request it makes is signed per request with this machine's own key — the
	// route that signs returns 501 without hardware to hold that key, and does
	// not fall back, deliberately. So a machine with no hardware key could arm
	// itself into this mode cleanly and then fail every request it ever made,
	// with nothing having warned it.
	//
	// Not hypothetical on Linux, where the signer refuses by design because a
	// Linux desktop is not a supported place to run this — so such a machine
	// could only ever arrive here and then not work.
	//
	// Checked at the moment of arming rather than at first use, because this is
	// the only moment where the answer is still useful — afterwards the machine
	// is in a mode whose every operation is the one that fails.
	signer := secureenclave.NewPlatformSigner(s.DataDir)
	if !secureenclave.UsingHardware(signer) {
		found := secureenclave.HardwareRootStatus()
		writeError(w, http.StatusPreconditionFailed,
			"this computer cannot act for an identity, so it cannot be a front end for one",
			"a front end signs every request with a key this machine keeps to itself, and this "+
				"one has none — "+found.String())
		return
	}

	if err := s.beAFrontEndFor(f); err != nil {
		writeError(w, http.StatusConflict,
			"this computer cannot be made a front end for that agent", err.Error())
		return
	}
	front, err := s.whatThisCoreIsAFrontEndFor()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "recorded, but could not read it back", err.Error())
		return
	}
	writeJSONResponse(w, map[string]interface{}{"front_end_for": front})
}

func (s *CoreServer) handleStopBeingAFrontEnd(w http.ResponseWriter, r *http.Request) {
	if err := s.stopBeingAFrontEnd(); err != nil {
		writeError(w, http.StatusInternalServerError,
			"could not stop being a front end", err.Error())
		return
	}
	writeJSONResponse(w, map[string]interface{}{"front_end_for": nil})
}
