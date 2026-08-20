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

// HoldersFromPairedMachines asks each machine already paired to this identity
// to hold a share, and returns those that agreed.
//
// A machine that refuses or cannot be reached is left out rather than failing
// the backup: it is one holder fewer, which a threshold is built to survive,
// and refusing to back up at all because a laptop was closed would be the
// worse outcome by a distance.
func HoldersFromPairedMachines(machines []store.AdoptedAgent, identityAID string,
	policy HoldingPolicy, client *http.Client) ([]backup.ShareHolder, []string) {

	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	var holders []backup.ShareHolder
	var couldNotAsk []string

	for _, m := range machines {
		if strings.TrimSpace(m.URL) == "" || strings.TrimSpace(m.AID) == "" {
			couldNotAsk = append(couldNotAsk, m.AID)
			continue
		}
		agreed, err := askAMachineToHold(client, m.URL, AgreeToHold{
			// One of the owner's own machines files under the identity's own
			// AID: it already knows whose it is, so a pairwise identifier
			// would hide nothing from it. A witness belonging to somebody else
			// is the case that needs one.
			IdentityAID: identityAID,
			HolderID:    m.AID,
			Policy:      policy,
		})
		if err != nil {
			couldNotAsk = append(couldNotAsk, m.AID)
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

func askAMachineToHold(client *http.Client, url string, req AgreeToHold) (*AgreedToHold, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	resp, err := client.Post(strings.TrimRight(url, "/")+"/api/recovery/holdings",
		"application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("that machine could not be reached")
	}
	defer resp.Body.Close()
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
