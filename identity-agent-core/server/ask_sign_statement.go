package server

// t = 6 -> sign_statement. The PERSON's half of "a person signs a statement an app hands them"
// (a_person_signs_a_statement_for_an_app.go is the asker's). The person's Identity Agent shows the exact
// statement and who asks, and on their approval signs the envelope of docs/statement-signature.md with
// the root key in force and posts the signature to the asker.
//
// The first Ask whose answer is a root-key signature over text somebody else chose, so every defence is
// on this side (ADR-080): the statement is refused before any screen unless it meets the generic rules
// (statements.Show); the screen is built only from the checked statement, a checked title and the
// asker's verified identifier and plain origin; consent is asked every time (the approval is bound to
// the Ask's exact bytes by bindConsent, and nothing here is automatic); and the signed bytes name the
// asker, so a signature made for one verifier is refused by another.

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"identity-agent-core/iacrypto"
	"identity-agent-core/internal/boundedread"
	"identity-agent-core/login"
	"identity-agent-core/statements"
	"identity-agent-core/store"
)

func init() { registerAsk(ActionSignStatement, signStatementAsk{}) }

type signStatementAsk struct{}

func (signStatementAsk) Action() string { return "sign_statement" }

// AskAuth is the base layer's: the Ask carries sig and signer_oobi, and verifyAskSignature checks them
// against the key log the signer's OOBI serves. The handler then requires that signer to BE the site the
// Ask names, so an asker cannot name another's identifier inside what is signed.

// keyHeldElsewhere is said in plain words when this device does not hold the root key.
const keyHeldElsewhere = "This device does not hold your root key, so it cannot sign this. Open the request on the device that does."

type signStatementPayload struct {
	SiteAID    string `json:"site_aid"`
	SiteOOBI   string `json:"site_oobi"`
	SignerOOBI string `json:"signer_oobi"`
	Audience   string `json:"audience"`
	Nonce      string `json:"nonce"`
	Expiry     string `json:"expiry"`
	Statement  string `json:"statement"`
	Title      string `json:"title"`
}

// readSignStatement checks everything about the Ask that does not need a person, in one place for
// Preview and Execute, and returns what may be shown.
func (s *CoreServer) readSignStatement(ctx AskContext) (signStatementPayload, statements.Shown, string, error) {
	var p signStatementPayload
	if err := json.Unmarshal(ctx.AskBytes, &p); err != nil {
		return p, statements.Shown{}, "", errors.New("this request is not readable")
	}
	if p.SiteAID == "" || p.Nonce == "" {
		return p, statements.Shown{}, "", errors.New("this request does not say who is asking")
	}
	// The signer of the Ask is the asker the signed bytes will name.
	signerAID := strings.TrimRight(p.SignerOOBI, "/")
	if i := strings.LastIndex(signerAID, "/"); i >= 0 {
		signerAID = signerAID[i+1:]
	}
	if signerAID != p.SiteAID {
		return p, statements.Shown{}, "", errors.New("this request was not signed by the site it names")
	}
	if err := login.CheckExpiry(p.Expiry, time.Now()); err != nil {
		return p, statements.Shown{}, "", err
	}
	origin := p.Audience
	if err := shownAudience(origin); err != nil {
		return p, statements.Shown{}, "", errors.New("what is asking cannot be shown: " + err.Error())
	}
	if _, err := statements.Envelope(p.SiteAID, p.Statement); err != nil {
		return p, statements.Shown{}, "", err
	}
	shown, err := statements.Show(p.Statement, p.Title)
	if err != nil {
		return p, statements.Shown{}, "", err
	}
	return p, shown, origin, nil
}

func (signStatementAsk) Preview(s *CoreServer, ctx AskContext) (GenericPreview, error) {
	p, shown, origin, err := s.readSignStatement(ctx)
	if err != nil {
		return GenericPreview{}, err
	}
	// Nothing is offered to sign on a device that cannot sign it.
	if _, err := s.identitySigningSeed(); err != nil {
		if errors.Is(err, errKeyElsewhere) {
			return GenericPreview{}, errors.New(keyHeldElsewhere)
		}
		return GenericPreview{}, errors.New("this device cannot use your root key right now, so it cannot sign this")
	}
	// The page's name is the asker's own word; what is verified is its identifier, which is what the signed
	// bytes name. Whether this person has dealt with that identifier before is the one thing their own
	// agent knows about it, so it is said (a sign-in to an app makes the app a contact).
	known := false
	if c, err := s.DataStore.GetContact(p.SiteAID); err == nil && c != nil {
		known = true
	}
	rows := make([]PreviewDetail, 0, len(shown.Rows))
	for _, r := range shown.Rows {
		rows = append(rows, PreviewDetail{Label: r.Label, Value: r.Value})
	}
	return GenericPreview{
		T: ActionSignStatement, Action: "sign_statement", Title: "Sign a statement",
		Subtitle:         "Asked by " + origin,
		Counterparty:     p.SiteAID,
		CounterpartyName: origin,
		Statement: &PreviewStatement{
			Heading: shown.Heading, Form: shown.Form, Rows: rows, Verbatim: shown.Verbatim,
			SignerNote: "Only your signature makes " + origin + " count this as yours.",
		},
		Warning: askerStanding(known) + " Your signature is made with your root key and cannot be taken back. Approve only if you mean it.",
	}, nil
}

// askerStanding says what this person's own agent knows of whoever asks, in plain words. The name a
// page gives is its own, and the signature names the asker's identifier, not the name.
func askerStanding(known bool) string {
	if known {
		return "You have dealt with this asker before."
	}
	return "You have never dealt with this asker: the name it gives is its own word."
}

func (signStatementAsk) Execute(s *CoreServer, ctx AskContext, d ScanDecision) (map[string]interface{}, error) {
	p, _, _, err := s.readSignStatement(ctx)
	if err != nil {
		return nil, err
	}
	callback := strings.TrimRight(ctx.Base, "/") + "/api/statement/callback?session=" + ctx.Token
	if !d.Approved {
		// Told to the asker so its page can say so; advisory, and nothing is signed.
		_ = s.postStatementAnswer(callback, map[string]interface{}{"nonce": p.Nonce, "declined": true})
		return map[string]interface{}{"ok": true, "declined": true}, nil
	}
	env, err := statements.Envelope(p.SiteAID, p.Statement)
	if err != nil {
		return nil, err
	}
	seed, err := s.identitySigningSeed()
	if err != nil {
		if errors.Is(err, errKeyElsewhere) {
			return nil, errors.New(keyHeldElsewhere)
		}
		return nil, errors.New("this device cannot use your root key right now")
	}
	identity, err := s.DataStore.GetIdentity()
	if err != nil || identity == nil {
		return nil, errors.New("this agent has no identity to sign as")
	}
	events, err := s.DataStore.GetEvents(identity.AID)
	if err != nil {
		return nil, err
	}
	sn, err := latestEstablishmentSN(events)
	if err != nil {
		return nil, err
	}
	raw := ed25519.Sign(ed25519.NewKeyFromSeed(seed), env)
	sig, err := iacrypto.MatterIndexedSigQB64("A", 0, raw, 88)
	if err != nil {
		return nil, err
	}
	publicURL := ""
	if s.EndpointService != nil {
		publicURL = s.EndpointService.CurrentURL()
	}
	if publicURL == "" {
		return nil, errors.New("this agent has no public address, so the asker cannot check who signed")
	}
	answer := map[string]interface{}{
		"nonce": p.Nonce, "signature": sig, "signer_aid": identity.AID,
		"signer_oobi": fmt.Sprintf("%s/public/oobi/%s", publicURL, identity.AID), "kel_sn": sn,
	}
	if err := s.postStatementAnswer(callback, answer); err != nil {
		return nil, err
	}
	return map[string]interface{}{"ok": true, "signed": true, "signer_aid": identity.AID, "kel_sn": sn}, nil
}

// latestEstablishmentSN is the KERI sequence number of the latest establishment event (an inception or
// a rotation, delegated or not) of a key log, interaction events counted: the sn at which the key in
// force was set, which is what a verifier holding the key history indexes its keys by. The count of key
// changes minus one is the same number only until the first rotation that follows an interaction.
func latestEstablishmentSN(events []store.EventRecord) (int, error) {
	sn, found := 0, false
	for _, e := range events {
		switch e.EventType {
		case "icp", "rot", "dip", "drt":
			if !found || e.SequenceNumber > sn {
				sn, found = e.SequenceNumber, true
			}
		}
	}
	if !found {
		return 0, errors.New("this identity has no key events to say which key signed")
	}
	return sn, nil
}

func (s *CoreServer) postStatementAnswer(callback string, answer map[string]interface{}) error {
	b, _ := json.Marshal(answer)
	resp, err := siteClient(15*time.Second, callback).Post(callback, "application/json", bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("could not reach the asker: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		why := strings.TrimSpace(boundedread.Snippet(resp.Body))
		if why == "" {
			why = fmt.Sprintf("status %d", resp.StatusCode)
		}
		return fmt.Errorf("the asker did not accept the signature: %s", why)
	}
	return nil
}
