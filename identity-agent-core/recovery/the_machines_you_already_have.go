package recovery

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"identity-agent-core/backup"
	"identity-agent-core/store"
)

// The holders somebody already has, before they have named anybody.
//
// Nobody should be asked to nominate friends in order to found an identity,
// and a first backup should not be weaker than the identity it protects. So
// the machines already paired to this identity are offered as share holders,
// and day one is the recovery words plus any one of them.
//
// That is a genuine improvement over the words alone — an attacker with the
// backup and the phrase now also needs one of the owner's own machines — and
// it is honestly weaker than naming people, because losing every device loses
// every share. The screen has to say so, which is why AskForMorePeople exists
// rather than this quietly looking finished.

// DefaultThresholdWithPeople is the threshold when somebody chooses witnesses.
const DefaultThresholdWithPeople = 3

// CouldNotAsk says why one machine is not holding a share.
type CouldNotAsk struct {
	AID string `json:"aid"`
	Why string `json:"why"`
}

// HoldersFromPairedMachines asks each machine already paired to this identity
// to hold a share, and returns those that agreed.
//
// A machine that refuses or cannot be reached is left out rather than failing
// the backup: it is one holder fewer, which a threshold is built to survive,
// and refusing to back up at all because a laptop was closed would be the
// worse outcome by a distance.
//
// WHO CAN MAKE THIS CALL, which is not a detail.
//
// Agreeing to hold a share is an owner-only route, so a machine across a
// network wants proof that the request is the owner's. On the same computer
// there is none to give and none needed — a local request is recognised as the
// owner's outright.
//
// A remote one needs a signature, and THE AGENT CORE CANNOT PRODUCE IT. That
// is deliberate and long-standing: the root identity's key belongs to the
// controller, and signingSeedForAID refuses to sign as the root precisely so
// that a core cannot claim an authority it does not have. So this is not a
// missing piece of plumbing that a later change drops in. Whatever holds the
// root key — the app — has to sign these requests, and this function is given
// a way to sign rather than being taught to.
//
// Sign may be nil, and then only machines that trust a local request will
// agree. The rest come back in couldNotAsk saying so, because a holder
// silently missing from a backup is discovered during a recovery and not
// before.
type SignAsOwner func(method, path, timestamp string, body []byte) (signature string, err error)

func HoldersFromPairedMachines(machines []store.AdoptedAgent, identityAID string,
	policy HoldingPolicy, client *http.Client, sign SignAsOwner) ([]backup.ShareHolder, []CouldNotAsk) {

	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	var holders []backup.ShareHolder
	var couldNotAsk []CouldNotAsk

	for _, m := range machines {
		if strings.TrimSpace(m.URL) == "" || strings.TrimSpace(m.AID) == "" {
			couldNotAsk = append(couldNotAsk, CouldNotAsk{
				AID: m.AID, Why: "this machine has no address to reach it at"})
			continue
		}
		agreed, err := askAMachineToHold(client, m.URL, sign, AgreeToHold{
			// One of the owner's own machines files under the identity's own
			// AID: it already knows whose it is, so a pairwise identifier
			// would hide nothing from it. A witness belonging to somebody else
			// is the case that needs one.
			IdentityAID: identityAID,
			HolderID:    m.AID,
			Policy:      policy,
		})
		if err != nil {
			couldNotAsk = append(couldNotAsk, CouldNotAsk{AID: m.AID, Why: err.Error()})
			continue
		}
		holders = append(holders, backup.ShareHolder{
			ID:           m.AID,
			Kind:         "device",
			PublicKeyB64: agreed.PublicKeyB64,
			Address:      m.URL,
			KnownAs:      identityAID,
		})
	}
	return holders, couldNotAsk
}

// AskForMorePeople says whether a set of holders leaves the owner one bad day
// from losing everything.
//
// Every share on a machine the owner carries means a fire, a theft or a flood
// takes the identity with the devices — and the recovery words, which are
// meant to be the thing that survives exactly that, are no longer enough on
// their own. A person is the only holder that is not in the same building.
func AskForMorePeople(holders []backup.ShareHolder) string {
	if len(holders) == 0 {
		return "Nothing is protecting this backup except the recovery words. " +
			"Anybody who gets hold of both can read everything in it."
	}
	people := 0
	for _, h := range holders {
		if h.Kind == "witness" {
			people++
		}
	}
	if people == 0 {
		return "Every share is on a device you own. If you lose them all at once — " +
			"a fire, a theft, a flood — your recovery words will not be enough on their own. " +
			"Adding a person you trust is what survives that."
	}
	return ""
}

func askAMachineToHold(client *http.Client, url string, sign SignAsOwner,
	req AgreeToHold) (*AgreedToHold, error) {

	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	const path = "/api/recovery/holdings"
	httpReq, err := http.NewRequest(http.MethodPost,
		strings.TrimRight(url, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("that machine could not be reached")
	}
	httpReq.Header.Set("Content-Type", "application/json")

	if sign != nil {
		stamp := time.Now().UTC().Format(time.RFC3339)
		sig, serr := sign(http.MethodPost, path, stamp, body)
		if serr != nil {
			return nil, fmt.Errorf("this request could not be signed as the owner")
		}
		httpReq.Header.Set("X-IA-Owner-Sig", sig)
		httpReq.Header.Set("X-IA-Owner-Timestamp", stamp)
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("that machine could not be reached")
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		// Said precisely, because it is not that machine refusing to help — it
		// is this request not showing that the owner made it, and what to do
		// about that differs entirely.
		if sign == nil {
			return nil, fmt.Errorf(
				"that machine wants proof the owner asked, and this request was not signed")
		}
		return nil, fmt.Errorf(
			"that machine did not accept this owner's signature")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("that machine did not agree to hold a share")
	}
	var agreed AgreedToHold
	if err := json.NewDecoder(resp.Body).Decode(&agreed); err != nil {
		return nil, fmt.Errorf("that machine answered with something unreadable")
	}
	if agreed.PublicKeyB64 == "" {
		// Without a key there is nothing to seal a share to, and carrying on
		// would produce an archive naming a holder who can never take part.
		return nil, fmt.Errorf("that machine agreed but gave no key")
	}
	return &agreed, nil
}
