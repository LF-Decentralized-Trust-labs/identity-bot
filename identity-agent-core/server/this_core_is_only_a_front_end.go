package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

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

var frontEndLock sync.Mutex

func (s *CoreServer) frontEndFile() string {
	return filepath.Join(s.DataDir, "this-core-is-only-a-front-end.json")
}

// whatThisCoreIsAFrontEndFor returns the record, or nil when this installation
// holds its own identity.
//
// An unreadable file is an ERROR, never "no record". Read as absent, a file
// that failed to parse would quietly restore this core to answering about
// identities — the exact state the record exists to leave.
func (s *CoreServer) whatThisCoreIsAFrontEndFor() (*AFrontEndFor, error) {
	frontEndLock.Lock()
	defer frontEndLock.Unlock()
	return s.readFrontEnd()
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
	return os.WriteFile(s.frontEndFile(), raw, 0o600)
}

// stopBeingAFrontEnd returns this core to answering for itself.
func (s *CoreServer) stopBeingAFrontEnd() error {
	frontEndLock.Lock()
	defer frontEndLock.Unlock()
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
// naming where the question should have gone.
//
// Placed before authorisation rather than after: the point is that this core has
// no business answering, which does not depend on who is asking, and a caller
// should get the same clear answer whether or not they could have authenticated.
func (s *CoreServer) refuseWhatBelongsToTheAgent(routes chi.Routes) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodOptions || !strings.HasPrefix(r.URL.Path, "/api/") {
				next.ServeHTTP(w, r)
				return
			}

			front, err := s.whatThisCoreIsAFrontEndFor()
			if err != nil {
				// Unreadable. Refused rather than served: this core cannot tell
				// whether it is entitled to answer, and answering anyway is the
				// failure the record exists to prevent.
				writeError(w, http.StatusServiceUnavailable,
					"this computer cannot tell which half it is running", err.Error())
				return
			}
			if front == nil {
				next.ServeHTTP(w, r)
				return
			}

			pattern := matchedRoutePattern(routes, r)
			if pattern != "" {
				if _, ok := whatAFrontEndAnswersFor[r.Method+" "+pattern]; ok {
					next.ServeHTTP(w, r)
					return
				}
			}

			writeError(w, http.StatusConflict,
				"this computer is the front end for an identity kept elsewhere, so it "+
					"cannot answer this",
				fmt.Sprintf("the identity is %s at %s — ask it there. This core holds no "+
					"identity, and an answer from it would be true and about nobody",
					front.AgentAID, front.AgentURL))
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
