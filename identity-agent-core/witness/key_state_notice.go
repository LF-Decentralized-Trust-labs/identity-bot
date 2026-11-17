package witness

import (
	"fmt"
	"time"

	"github.com/LF-Decentralized-Trust-labs/identity-bot/identity-agent-core/witnessproto"
)

// The key state notice and the witness location are built, signed and read in
// witnessproto, the one place a witness, a watcher and the core all read them.
// What is here is only this agent's service signing them.

// KeyStateNotice is this witness's signed key state notice for aid. When the
// asker may not read the log (see MayRead) the notice is the one for a log that
// is not held, signed all the same, so the two cannot be told apart.
func (s *Service) KeyStateNotice(aid string, mayRead bool) (witnessproto.SignedReply, error) {
	ours, err := s.witnessingKey()
	if err != nil {
		return witnessproto.SignedReply{}, err
	}
	rec := witnessproto.NoKeyState(aid)
	if mayRead {
		if kel, err := s.Store.GetKelEvents(aid); err == nil && len(kel) > 0 {
			logged := make([]witnessproto.LoggedEvent, len(kel))
			for i, e := range kel {
				logged[i] = witnessproto.LoggedEvent{SequenceNum: e.SequenceNum, RawBytesB64: e.RawBytesB64, StoredAt: e.StoredAt}
			}
			if rec, err = witnessproto.KeyStateRecordOf(aid, logged); err != nil {
				return witnessproto.SignedReply{}, err
			}
		}
	}
	return witnessproto.SignedKeyStateNotice(ours, rec, time.Now(), s.SignReceipt)
}

// WitnessLocationNotice is this witness's signed statement of where it is
// reached, at url.
func (s *Service) WitnessLocationNotice(url string) (witnessproto.SignedReply, error) {
	ours, err := s.witnessingKey()
	if err != nil {
		return witnessproto.SignedReply{}, err
	}
	return witnessproto.SignedWitnessLocation(ours, url, time.Now(), s.SignReceipt)
}

func (s *Service) witnessingKey() (string, error) {
	if s.SignReceipt == nil || s.OurWitnessAID == nil {
		return "", fmt.Errorf("this agent has no witnessing key")
	}
	return s.OurWitnessAID()
}
