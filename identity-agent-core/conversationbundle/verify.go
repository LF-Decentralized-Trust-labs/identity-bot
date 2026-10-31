package conversationbundle

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"identity-agent-core/activitylog"
	"identity-agent-core/agentbody"
	"identity-agent-core/agentmessage"
	"identity-agent-core/authorisation"
	"identity-agent-core/didcomm"
	"identity-agent-core/drivers"
	"identity-agent-core/iacrypto"
	"identity-agent-core/login"
	"identity-agent-core/permission"
	"identity-agent-core/schemas"

	keri "github.com/grapeid/keri-go"
)

// decode reads the bundle's base64. Strictly: an encoding whose unused bits
// are set reads as the same bytes, so accepting one would let a bundle be
// changed without anything it proves changing, and a check meant to catch
// every edit would pass it. Line breaks are the same hole, since the standard
// decoder skips them even in strict mode, so they are refused.
func decode(s string) ([]byte, error) {
	if strings.ContainsAny(s, "\r\n") {
		return nil, fmt.Errorf("a line break inside base64")
	}
	return base64.StdEncoding.Strict().DecodeString(s)
}

// canonicalURL reports whether s is the one unpadded base64url encoding of
// the bytes it decodes to.
func canonicalURL(s string) bool {
	_, err := iacrypto.DecodeBase64URL(s)
	return err == nil
}

// Report is what Verify found.
type Report struct {
	Conversation string `json:"conversation"`
	// Root is the organisation the bundle was checked against. A bundle can
	// name any root, so it means something only if it is the organisation
	// the reader expected (VerifyAgainst).
	Root string `json:"root"`
	// Verified is true when every check held. Entries and rows no anchor
	// fixes yet do not stop it; they are listed, never reported as anchored.
	Verified bool    `json:"verified"`
	Faults   []Fault `json:"faults,omitempty"`
	// Messages is every entry, in order, with what was checked about it.
	Messages []Message `json:"messages"`
	// AnchoredThrough is the newest entry of the conversation an anchor
	// fixes; UnanchoredEntries are the entries after it.
	AnchoredThrough   int   `json:"anchored_through"`
	UnanchoredEntries []int `json:"unanchored_entries,omitempty"`
	// LogRows is how many rows of the governance log the bundle carries;
	// UnanchoredRows are those no anchor fixes yet.
	LogRows        int     `json:"log_rows"`
	UnanchoredRows []int64 `json:"unanchored_rows,omitempty"`
	// Trusts is exactly what the result rests on. CannotRuleOut is what the
	// check could not exclude, given that.
	Trusts        []string `json:"trusts"`
	CannotRuleOut []string `json:"cannot_rule_out"`
}

// Fault is one thing that did not hold.
type Fault struct {
	Where string `json:"where"`
	Why   string `json:"why"`
}

// Message is one entry as checked.
type Message struct {
	Seq       int    `json:"seq"`
	MessageID string `json:"message_id"`
	Kind      string `json:"kind"`
	From      string `json:"from"`
	To        string `json:"to"`
	// Sender is whose own signature the entry carries: "body" for an AI
	// agent's machine, "controller" for the app a person spoke from.
	Sender string `json:"sender"`
	// Grade is how strongly the body's key is held, as the body credential
	// records it.
	Grade string `json:"grade,omitempty"`
	// Person is the person a controller acted for, as its grant names them.
	Person   string `json:"person,omitempty"`
	Anchored bool   `json:"anchored"`
	Holds    bool   `json:"holds"`
}

// keyLog is one key log as checked.
type keyLog struct {
	raws    [][]byte
	events  []map[string]interface{}
	current string
	// witnesses is how many witnesses the log names at its end, and witnessed
	// whether every event has the receipts it asks for.
	witnesses int
	witnessed bool
}

// credential is one credential as checked.
type credential struct {
	said    string
	raw     []byte
	log     [][]byte
	schema  string
	issuer  string
	holder  string
	attrs   map[string]json.RawMessage
	rests   authorisation.RestsOn
	issued  time.Time
	revoked *time.Time
	// why is set when the credential itself does not hold; nothing resting
	// on it holds either.
	why string
}

func (c *credential) attr(name string) string {
	var s string
	_ = json.Unmarshal(c.attrs[name], &s)
	return strings.TrimSpace(s)
}

// liveAt says why the credential was not in force at t, or "" when it was.
func (c *credential) liveAt(t time.Time) string {
	return c.liveBetween(t, t)
}

// liveBetween says why the credential was not in force for something asked
// for at asked and acted on at taken, or "" when it was: issued by the time it
// was asked for, and neither revoked nor lapsed by the time it was acted on.
func (c *credential) liveBetween(asked, taken time.Time) string {
	switch {
	case c.why != "":
		return c.why
	case asked.Before(c.issued):
		return fmt.Sprintf("it was not issued until %s", c.issued.Format(time.RFC3339Nano))
	case c.revoked != nil && !taken.Before(*c.revoked):
		return fmt.Sprintf("it was revoked at %s", c.revoked.Format(time.RFC3339Nano))
	}
	if until := c.attr("valid_until"); until != "" {
		if u, err := time.Parse(time.RFC3339, until); err != nil || !taken.Before(u) {
			return "it had lapsed"
		}
	}
	return ""
}

type verifier struct {
	b       *Bundle
	r       *Report
	kels    map[string]*keyLog
	regs    map[string]bool
	creds   map[string]*credential
	dids    map[string]*didcomm.DID
	entries map[string]agentmessage.Record
	hashes  map[int]string
	notes   map[string]bool
	// signedOnce is every sender's signature seen, by the entry it is in: a
	// signed statement or request stands for one entry, never two.
	signedOnce map[string]int
}

func (v *verifier) fault(where, format string, args ...any) {
	v.r.Faults = append(v.r.Faults, Fault{Where: where, Why: fmt.Sprintf(format, args...)})
}

func (v *verifier) cannotRuleOut(s string) {
	if !v.notes[s] {
		v.notes[s] = true
		v.r.CannotRuleOut = append(v.r.CannotRuleOut, s)
	}
}

// VerifyAgainst checks a bundle and that it is the organisation root's the
// reader expects. Without an expected root, the result says that the root was
// taken from the bundle itself: a bundle made up from nothing, with its own
// root, holds together as well as a genuine one.
func VerifyAgainst(b *Bundle, root string) Report {
	r := Verify(b)
	switch {
	case b == nil:
	case root == "":
		r.CannotRuleOut = append([]string{"That this is the organisation you think it is: the root identity " + b.Root +
			" was taken from the bundle, not checked against one you named."}, r.CannotRuleOut...)
	case root != b.Root:
		r.Faults = append(r.Faults, Fault{Where: "root", Why: "the bundle is checked against root identity " + b.Root + ", not " + root + ", the organisation expected"})
		r.Verified = false
	}
	return r
}

// Verify checks a bundle with nothing but what is in it.
func Verify(b *Bundle) Report {
	r := Report{}
	if b == nil {
		r.Faults = []Fault{{Where: "bundle", Why: "there is no bundle"}}
		return r
	}
	r.Conversation, r.Root = b.Conversation, b.Root
	v := &verifier{b: b, r: &r, kels: map[string]*keyLog{}, regs: map[string]bool{}, creds: map[string]*credential{},
		dids: map[string]*didcomm.DID{}, entries: map[string]agentmessage.Record{}, hashes: map[int]string{}, notes: map[string]bool{}, signedOnce: map[string]int{}}
	r.Trusts = []string{
		"The organisation's root key log, as the bundle gives it: its inception and every key it puts in force. Every other identity, credential and anchor is checked back to it.",
		"The times the Identity Agent stamped on each message and on each credential's issuance and revocation, which decide whether a credential was in force when a message was sent. A body's own signed time must agree with the stamp to within " + agentbody.RequestWindow.String() + ", and a person's signed request to within " + authorisation.Skew.String() + ".",
	}
	if b.Format != Format {
		v.fault("bundle", "this is %q, not a %s bundle", b.Format, Format)
		return r
	}
	if b.Conversation == "" || b.Root == "" {
		v.fault("bundle", "the bundle names no conversation or no root identity")
		return r
	}
	v.checkKeyLogs()
	v.checkRegistries()
	v.checkCredentials()
	v.checkCountersigners()
	v.checkEntries()
	rows := v.checkLog()
	v.checkAnchors(rows)
	v.cannotRuleOut("The Identity Agent holds every AI agent's identity key, so a compromised Identity Agent could countersign words nobody sent. It cannot make the signature of a machine key it does not hold. An entry whose sender's own signature holds is the strong claim, and every entry here is checked for one, but that claim rests on the body credential or Controller Grant naming that key having been issued honestly: whoever holds the root key can issue one to a key of its own.")
	// An entry holds when nothing found anywhere in the bundle is about it.
	for i := range r.Messages {
		where := fmt.Sprintf("entry %d", r.Messages[i].Seq)
		r.Messages[i].Holds = true
		for _, f := range r.Faults {
			if f.Where == where {
				r.Messages[i].Holds = false
			}
		}
	}
	r.Verified = len(r.Faults) == 0
	return r
}

// ── Key logs ────────────────────────────────────────────────────────────────

func (v *verifier) checkKeyLogs() {
	for _, kl := range v.b.KeyLogs {
		where := "key log of " + kl.AID
		if _, dup := v.kels[kl.AID]; dup {
			v.fault(where, "the bundle carries two key logs for this identity")
			continue
		}
		in := drivers.ValidateKELInput{AID: kl.AID, Receipts: map[string][]drivers.WitnessReceipt{}}
		out := &keyLog{}
		ok := true
		for i, ev := range kl.Events {
			raw, err := decode(ev.Raw)
			if err != nil || len(raw) == 0 {
				v.fault(where, "event %d is unreadable", i)
				ok = false
				break
			}
			var parsed map[string]interface{}
			if err := json.Unmarshal(raw, &parsed); err != nil {
				v.fault(where, "event %d is not an event", i)
				ok = false
				break
			}
			in.RawEvents = append(in.RawEvents, raw)
			in.CesrSignatures = append(in.CesrSignatures, ev.Signature)
			said, _ := parsed["d"].(string)
			for _, rc := range ev.Receipts {
				// A receipt that does not verify is not a missing receipt: it is
				// one that was changed.
				if err := drivers.VerifyReceipt(rc.Witness, said, rc.Signature); err != nil {
					v.fault(where, "a witness receipt for event %d does not verify: %v", i, err)
					continue
				}
				in.Receipts[said] = append(in.Receipts[said], drivers.WitnessReceipt{WitnessAID: rc.Witness, CesrSignature: rc.Signature})
			}
			out.raws = append(out.raws, raw)
			out.events = append(out.events, parsed)
		}
		if !ok {
			continue
		}
		res, err := drivers.ValidateKELFromBytes(in)
		switch {
		case err != nil:
			v.fault(where, "it cannot be read: %v", err)
			continue
		case !res.KelVerified:
			why := "not every event is signed by the key in force"
			if len(res.ValidationErrors) > 0 {
				why = strings.Join(res.ValidationErrors, "; ")
			} else if res.EventsUnsigned > 0 {
				why = fmt.Sprintf("%d of its events carry no signature", res.EventsUnsigned)
			}
			v.fault(where, "it does not verify: %s", why)
			continue
		}
		out.current = res.CurrentPublicKey
		out.witnesses = len(res.Witnesses)
		out.witnessed = res.Witnessed
		v.kels[kl.AID] = out
	}
	root, ok := v.kels[v.b.Root]
	if !ok {
		v.fault("root", "the bundle carries no verified key log for the root identity %s", v.b.Root)
		return
	}
	if t, _ := root.events[0]["t"].(string); t != "icp" {
		v.fault("root", "the root identity's key log opens with a %q, not its own inception", t)
	}
	if root.witnesses == 0 {
		v.cannotRuleOut("The root identity names no witnesses, so nobody outside the Identity Agent holds its key log: whoever holds the root key could show another auditor a different history.")
	} else if !root.witnessed {
		v.cannotRuleOut("Not every event of the root identity's key log carries the witness receipts it asks for.")
	} else {
		v.r.Trusts = append(v.r.Trusts, fmt.Sprintf("The %d witnesses the root identity names, whose receipts the bundle carries for every event of its key log.", root.witnesses))
	}
}

// delegatedFromRoot says why aid is not an identity the root delegated, or ""
// when it is: its key log opens with a delegated inception naming the root,
// which the root's key log approves, and every later delegated rotation is
// approved there too.
func (v *verifier) delegatedFromRoot(aid string) string {
	kl, ok := v.kels[aid]
	if !ok {
		return "the bundle carries no verified key log for " + aid
	}
	root, ok := v.kels[v.b.Root]
	if !ok {
		return "the root identity's key log does not verify"
	}
	if t, _ := kl.events[0]["t"].(string); t != "dip" || kl.events[0]["di"] != v.b.Root {
		return aid + " is not delegated from the root identity"
	}
	for i, raw := range kl.raws {
		t, _ := kl.events[i]["t"].(string)
		if t != "dip" && t != "drt" {
			continue
		}
		if err := keri.ValidateDelegation(raw, root.raws); err != nil {
			return fmt.Sprintf("the root identity's key log does not approve event %d of %s: %v", i, aid, err)
		}
	}
	return ""
}

// anchoredInRoot is the place in the root's key log of the event that seals
// subject's event sn with digest said, and whether there is one.
func (v *verifier) anchoredInRoot(subject string, sn int, said string) (int, bool) {
	root, ok := v.kels[v.b.Root]
	if !ok {
		return 0, false
	}
	for i, raw := range root.raws {
		ev, err := keri.ParseEvent(raw)
		if err != nil {
			continue
		}
		seals, _ := ev.Seals()
		for _, s := range seals {
			if s.Identifier == subject && s.SN == uint64(sn) && s.SAID == said {
				return i, true
			}
		}
	}
	return 0, false
}

// ── Registries and credentials ─────────────────────────────────────────────

func (v *verifier) checkRegistries() {
	for _, reg := range v.b.Registries {
		where := "registry " + reg.SAID
		raw, err := decode(reg.Inception)
		if err != nil {
			v.fault(where, "its inception is unreadable")
			continue
		}
		ev, err := keri.VerifyTELEvent(raw)
		if err != nil || ev.Ilk != "vcp" || ev.Subject != reg.SAID {
			v.fault(where, "its inception is not the inception of this registry")
			continue
		}
		var vcp struct {
			II string `json:"ii"`
		}
		if json.Unmarshal(raw, &vcp) != nil || vcp.II != v.b.Root {
			v.fault(where, "the registry is not the root identity's")
			continue
		}
		if _, ok := v.anchoredInRoot(reg.SAID, 0, ev.SAID); !ok {
			v.fault(where, "its inception is not anchored in the root identity's key log")
			continue
		}
		v.regs[reg.SAID] = true
	}
}

// telTime reads the time a transaction event states.
func telTime(s string) (time.Time, error) {
	for _, layout := range []string{"2006-01-02T15:04:05.000000-07:00", time.RFC3339Nano} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("%q is not a time", s)
}

func (v *verifier) checkCredentials() {
	for _, bc := range v.b.Credentials {
		c := &credential{said: bc.SAID}
		if _, dup := v.creds[bc.SAID]; dup {
			v.fault("credential "+bc.SAID, "the bundle carries it twice")
			continue
		}
		v.creds[bc.SAID] = c
		c.why = v.readCredential(bc, c)
		if c.why != "" {
			v.fault("credential "+bc.SAID, "%s", c.why)
		}
	}
	// What authorised each one, once every credential it may name is read.
	for _, bc := range v.b.Credentials {
		c := v.creds[bc.SAID]
		if c == nil || c.why != "" {
			continue
		}
		if why := v.checkAuthority(bc, c); why != "" {
			c.why = why
			v.fault("credential "+bc.SAID, "%s", why)
		}
	}
}

// readCredential checks one credential and its log, and says why it does not
// hold, or "".
func (v *verifier) readCredential(bc Credential, c *credential) string {
	raw, err := decode(bc.Raw)
	if err != nil {
		return "it is unreadable"
	}
	cred, err := keri.VerifyCredential(raw)
	if err != nil {
		return "it does not verify: " + err.Error()
	}
	if cred.SAID != bc.SAID {
		return "it is " + cred.SAID + ", not the credential named"
	}
	if cred.Issuer != v.b.Root {
		return "it was issued by " + cred.Issuer + ", not the root identity"
	}
	if !v.regs[cred.Registry] {
		return "it is in a registry the bundle does not show is the root identity's"
	}
	c.raw, c.schema, c.issuer, c.holder = raw, cred.SchemaSAID, cred.Issuer, cred.Recipient
	if err := json.Unmarshal(cred.Attributes, &c.attrs); err != nil {
		return "its attributes are unreadable"
	}
	if c.rests, err = authorisation.WhatItRestsOn(cred); err != nil {
		return "what it rests on cannot be read: " + err.Error()
	}
	for i, e := range bc.Log {
		b, err := decode(e)
		if err != nil {
			return fmt.Sprintf("event %d of its log is unreadable", i)
		}
		c.log = append(c.log, b)
	}
	if _, err := keri.CredentialStatus(bc.SAID, c.log); err != nil {
		return "its log does not hold together: " + err.Error()
	}
	for _, b := range c.log {
		ev, _ := keri.VerifyTELEvent(b)
		if ev.Registry != cred.Registry {
			return "its log is kept in another registry than the one it names"
		}
		if _, ok := v.anchoredInRoot(bc.SAID, ev.SN, ev.SAID); !ok {
			return fmt.Sprintf("its %s is not anchored in the root identity's key log", ev.Ilk)
		}
		at, err := telTime(ev.DateTime)
		if err != nil {
			return fmt.Sprintf("its %s states no readable time", ev.Ilk)
		}
		if ev.Ilk == "rev" {
			c.revoked = &at
		} else {
			c.issued = at
		}
	}
	// Every event of its log the root's key log anchors must be carried: a
	// revocation left out would read as a credential never revoked.
	if root, ok := v.kels[v.b.Root]; ok {
		for _, raw := range root.raws {
			ev, err := keri.ParseEvent(raw)
			if err != nil {
				continue
			}
			seals, _ := ev.Seals()
			for _, seal := range seals {
				if seal.Identifier == bc.SAID && seal.SN >= uint64(len(c.log)) {
					return fmt.Sprintf("the root identity's key log anchors event %d of its log, which the bundle does not carry", seal.SN)
				}
			}
		}
	}
	return ""
}

// checkAuthority applies authorisation.Check to a credential that carries the
// request that asked for it.
func (v *verifier) checkAuthority(bc Credential, c *credential) string {
	in := authorisation.Input{Credential: c.raw, CredentialLog: c.log}
	if root, ok := v.kels[v.b.Root]; ok {
		in.IssuerKEL = root.raws
	}
	if bc.RequestBody != nil {
		in.Body, in.HaveBody = *bc.RequestBody, true
	}
	g, ownerSigned := c.rests.Grant, c.rests.OwnerSigned
	if g != "" {
		grant, ok := v.creds[g]
		if !ok || grant.raw == nil {
			return "it names the machine grant " + g + " as having authorised it, and the bundle does not carry that grant"
		}
		in.Grant, in.GrantLog = grant.raw, grant.log
	}
	if ownerSigned {
		if why := v.ownerKey(&in); why != "" {
			return why
		}
	}
	err := authorisation.Check(in)
	switch {
	case err == nil:
		return ""
	case errors.Is(err, authorisation.ErrNoRequest):
		v.cannotRuleOut("Some credentials carry no request: the identity issued them on its own key, from the device that holds it, so who asked for them is the identity's word.")
		return ""
	case errors.Is(err, authorisation.ErrBodyWithheld):
		v.cannotRuleOut("For some credentials the request's body was not kept, so what was asked for is tied to what was signed only through the credential's own account of it.")
		return ""
	}
	return "it does not rest on the request that authorised it: " + err.Error()
}

// ownerKey sets the key an owner-signed request is checked against: the
// owner's key as the Identity Agent holds it, for the owner the root's
// inception names — or, where it names none, the root's own key.
func (v *verifier) ownerKey(in *authorisation.Input) string {
	root, ok := v.kels[v.b.Root]
	if !ok {
		return "the root identity's key log does not verify, so the owner it names cannot be read"
	}
	named, err := authorisation.OwnerFromKEL(root.events)
	if err != nil {
		return "the owner the root identity names cannot be read: " + err.Error()
	}
	o := v.b.Owner
	switch {
	case o == nil:
		return "it rests on the owner's signed request, and the bundle names no owner"
	case named == "" && o.AID == v.b.Root:
		if o.Key != root.current {
			return "the owner's key given is not the root identity's current key"
		}
	case named == "" || o.AID != named:
		return "the owner given is not the one the root identity's inception names"
	default:
		v.cannotRuleOut("The owner's current key is the Identity Agent's word: the bundle does not carry the owner's own key log.")
	}
	in.OwnerKey = o.Key
	return ""
}

// ── Countersigners ──────────────────────────────────────────────────────────

func (v *verifier) checkCountersigners() {
	for i := range v.b.Countersigners {
		did := v.b.Countersigners[i]
		where := "messaging keys of " + did.AID
		kl, ok := v.kels[did.AID]
		if !ok {
			v.fault(where, "the bundle carries no verified key log for this identity")
			continue
		}
		if _, err := didcomm.CheckKeysBelongTo(&did, kl.events, kl.current); err != nil {
			v.fault(where, "they are not tied to the identity's key log: %v", err)
			continue
		}
		v.dids[did.AID] = &did
	}
}

// ── Entries ────────────────────────────────────────────────────────────────

func (v *verifier) checkEntries() {
	if len(v.b.Entries) == 0 {
		v.fault("conversation", "the bundle carries no entries")
		return
	}
	prev := ""
	opener := ""
	for i, e := range v.b.Entries {
		seq := i + 1
		where := fmt.Sprintf("entry %d", seq)
		m := Message{Seq: seq}
		rec, ok := v.checkEntry(where, seq, prev, e, &m)
		if ok {
			if seq == 1 {
				opener = rec.OpenedBy
				if rec.ControllerProof == nil || rec.Kind != agentmessage.KindAsk || rec.From != rec.OpenedBy {
					v.fault(where, "a conversation is opened by a person's ask, and this is not one")
				}
			} else if rec.OpenedBy != opener {
				v.fault(where, "it names %s as having opened the conversation, where the first entry names %s", rec.OpenedBy, opener)
			}
		}
		if e.Envelope != nil {
			prev = agentmessage.Hash(e.Envelope)
			v.hashes[seq] = prev
		}
		v.r.Messages = append(v.r.Messages, m)
	}
}

// checkEntry checks one entry: the countersignature, its place in the chain,
// its words, the sender's own signature, and that whatever the sender spoke
// under was in force when it spoke.
func (v *verifier) checkEntry(where string, seq int, prev string, e Entry, m *Message) (agentmessage.Record, bool) {
	if e.Envelope == nil {
		v.fault(where, "it carries no countersigned entry")
		return agentmessage.Record{}, false
	}
	claimed, err := agentmessage.Read(e.Envelope)
	if err != nil {
		v.fault(where, "it is unreadable")
		return agentmessage.Record{}, false
	}
	signer := agentmessage.Countersigner(claimed.From, v.b.Root)
	did, ok := v.dids[signer]
	if !ok {
		v.fault(where, "the bundle carries no messaging keys tied to %s, who countersigned it", signer)
		return agentmessage.Record{}, false
	}
	// Only the entry and its two signatures are signed. Anything else an
	// envelope can carry is refused, so nothing in the bundle goes unchecked.
	exact := didcomm.Envelope{Mode: "signed", Protected: didcomm.ProtectedHeader{Alg: "none", Enc: "none", Skid: signer},
		Plain: e.Envelope.Plain, EdSig: e.Envelope.EdSig, DsaSig: e.Envelope.DsaSig}
	if !reflect.DeepEqual(*e.Envelope, exact) {
		v.fault(where, "the envelope carries more than the countersigned entry and its signatures")
	}
	if !canonicalURL(e.Envelope.Plain) || !canonicalURL(e.Envelope.EdSig) || !canonicalURL(e.Envelope.DsaSig) {
		v.fault(where, "the countersigned entry is not encoded as it was signed")
	}
	rec, err := agentmessage.Open(did, e.Envelope)
	if err != nil {
		v.fault(where, "it is not countersigned as %s: %v", signer, err)
		return agentmessage.Record{}, false
	}
	m.MessageID, m.Kind, m.From, m.To = rec.MessageID, rec.Kind, rec.From, rec.To
	if _, dup := v.entries[rec.MessageID]; dup {
		v.fault(where, "message %s appears twice", rec.MessageID)
	}
	v.entries[rec.MessageID] = rec
	switch {
	case rec.Conversation != v.b.Conversation:
		v.fault(where, "it belongs to conversation %s", rec.Conversation)
	case rec.Seq != seq:
		v.fault(where, "it says it is entry %d, so an entry before it is missing or out of place", rec.Seq)
	case rec.PrevHash != prev:
		v.fault(where, "it does not follow from the entry before it")
	}
	body, err := decode(e.Body)
	if err != nil || len(body) > agentmessage.MaxBody || agentmessage.HashBody(body) != rec.BodyHash {
		v.fault(where, "the words carried are not the words it was signed over")
	}
	if err := rec.CheckSenderProof(); err != nil {
		v.fault(where, "the sender's own signature does not hold: %v", err)
		return rec, true
	}
	once := []string{}
	if rec.Statement != nil {
		once = append(once, "signature "+rec.HostSignature, "nonce "+rec.Statement.Host+" "+rec.Statement.HostNonce)
	} else {
		once = append(once, "signature "+rec.ControllerProof.Signature)
	}
	for _, k := range once {
		if first, seen := v.signedOnce[k]; seen {
			v.fault(where, "it carries the same signed %s as entry %d: one signed message was recorded twice", strings.SplitN(k, " ", 2)[0], first)
		} else {
			v.signedOnce[k] = seq
		}
	}
	at, err := time.Parse(time.RFC3339Nano, rec.IATime)
	if err != nil {
		v.fault(where, "the time the Identity Agent stamped on it is unreadable")
		return rec, true
	}
	if rec.Statement != nil {
		v.checkBodySpoke(where, rec, body, at, m)
	} else {
		v.checkPersonSpoke(where, rec, at, m)
	}
	if t := rec.To; t != "" {
		if _, person := agentmessage.IsPerson(t); !person {
			if why := v.delegatedFromRoot(t); why != "" {
				v.fault(where, "it is addressed to %s: %s", t, why)
			}
		}
	}
	return rec, true
}

// checkBodySpoke checks an entry an AI agent's body sent: its machine key is
// the one a body credential bound to that AI agent, in force when it spoke,
// and the AI agent's grant was in force and allowed what it did.
func (v *verifier) checkBodySpoke(where string, rec agentmessage.Record, body []byte, at time.Time, m *Message) {
	st := rec.Statement
	m.Sender = "body"
	if why := v.delegatedFromRoot(rec.From); why != "" {
		v.fault(where, "%s", why)
	}
	if hostAt, err := time.Parse(time.RFC3339, st.HostTime); err != nil || absDuration(at.Sub(hostAt)) > agentbody.RequestWindow {
		v.fault(where, "the body's own signed time is not within %s of when the Identity Agent took it", agentbody.RequestWindow)
	}
	bc, ok := v.creds[rec.BodyCredential]
	switch {
	case !ok:
		v.fault(where, "the bundle does not carry the body credential %s it names", rec.BodyCredential)
	case bc.schema != schemas.AIAgentBody.Schema.SAID && bc.schema != schemas.AIAgentBodyV1.Schema.SAID:
		v.fault(where, "%s is not a body credential", rec.BodyCredential)
	case bc.holder != rec.From:
		v.fault(where, "the body credential binds a machine to %s, not to %s", bc.holder, rec.From)
	case bc.attr("host") != st.Host || bc.attr("verkey") != rec.HostVerkey:
		v.fault(where, "the machine key it is signed with is not the one the body credential binds")
	default:
		m.Grade = bc.attr("grade")
		if rec.BodyGrade != m.Grade {
			v.fault(where, "it is stamped with grade %q, where the body credential records %q", rec.BodyGrade, m.Grade)
		}
		if why := bc.liveAt(at); why != "" {
			v.fault(where, "the body credential was not in force when it was sent: %s", why)
		}
	}
	grant, ok := v.creds[rec.GrantSAID]
	switch {
	case !ok:
		v.fault(where, "the bundle does not carry the grant %s it was sent under", rec.GrantSAID)
	case grant.schema != schemas.AIAgentGrant.Schema.SAID && grant.schema != schemas.AIAgentGrantV1.Schema.SAID:
		v.fault(where, "%s is not an AI agent's grant", rec.GrantSAID)
	case grant.holder != rec.From:
		v.fault(where, "the grant it was sent under is %s's, not %s's", grant.holder, rec.From)
	default:
		if why := grant.liveAt(at); why != "" {
			v.fault(where, "the AI agent's grant was not in force when it was sent: %s", why)
		} else if rec.Kind == agentmessage.KindAsk {
			v.checkAskAllowed(where, grant, rec, body)
		}
	}
	v.checkThread(where, rec)
}

// checkAskAllowed applies the grant's limits to an ask, as the Identity Agent
// does before it countersigns one.
func (v *verifier) checkAskAllowed(where string, grant *credential, rec agentmessage.Record, body []byte) {
	var caps []string
	_ = json.Unmarshal(grant.attrs["capabilities"], &caps)
	allowed := false
	for _, c := range caps {
		allowed = allowed || c == agentmessage.CapabilityMessageAgent
	}
	if !allowed {
		v.fault(where, "the AI agent's grant does not let it ask another AI agent")
		return
	}
	var limits map[string]interface{}
	if raw, ok := grant.attrs["resource_constraints"]; ok {
		_ = json.Unmarshal(raw, &limits)
	}
	args := agentmessage.AskArgs(rec.To, string(body))
	if err := permission.CheckResourceConstraints(limits, agentmessage.CapabilityMessageAgent, args); err != nil {
		v.fault(where, "the AI agent's grant does not let it ask %s: %v", rec.To, err)
	}
}

// checkThread checks that a body spoke only about a message it was given, and
// answered only whoever asked it.
func (v *verifier) checkThread(where string, rec agentmessage.Record) {
	prompt, ok := v.entries[rec.InReplyTo]
	if !ok || prompt.MessageID == rec.MessageID {
		v.fault(where, "it acts on message %s, which is not earlier in this conversation", rec.InReplyTo)
		return
	}
	switch rec.Kind {
	case agentmessage.KindReceipt:
		if prompt.To != rec.From || rec.To != prompt.From {
			v.fault(where, "a receipt goes from a message's recipient to its sender, and this does not")
		}
	case agentmessage.KindReply, agentmessage.KindFailure:
		if prompt.Kind != agentmessage.KindAsk || prompt.To != rec.From || rec.To != prompt.From {
			v.fault(where, "an answer goes only to the sender of an ask addressed to the one answering, and this does not")
		}
	case agentmessage.KindAsk:
		if prompt.To != rec.From {
			v.fault(where, "an AI agent asks only while handling a message given to it, and this one was not")
		}
	}
}

// checkPersonSpoke checks an entry a person sent from a paired app: the app's
// key is the one its Controller Grant names, that grant was issued by the root
// and in force when the request was signed, and it names this person.
func (v *verifier) checkPersonSpoke(where string, rec agentmessage.Record, at time.Time, m *Message) {
	p := rec.ControllerProof
	m.Sender = "controller"
	aid, person := agentmessage.IsPerson(rec.From)
	switch {
	case !person:
		v.fault(where, "an AI agent's entry carries a controller's request instead of its body's signature")
		return
	case rec.Person == nil || rec.Person.AID != aid:
		v.fault(where, "it does not name the person it is from")
		return
	}
	m.Person = aid
	// What the person signed names the conversation it speaks in, once there
	// is one, and the message it answers, which must have been addressed to
	// them: so a request signed for one place cannot be recorded in another.
	var req agentmessage.PersonMessage
	if signed, err := p.SignedRequest(); err == nil {
		_ = json.Unmarshal(signed, &req)
	}
	if rec.Seq > 1 && req.Conversation != rec.Conversation {
		v.fault(where, "the person's signed request does not name this conversation")
	}
	if rec.InReplyTo != "" {
		if prompt, ok := v.entries[rec.InReplyTo]; !ok || prompt.MessageID == rec.MessageID || prompt.To != rec.From {
			v.fault(where, "it answers message %s, which is not an earlier message addressed to this person", rec.InReplyTo)
		}
	}
	cr, err := authorisation.ReadControllerRequest(p.SignedString)
	if err != nil || cr.Controller != p.Controller || cr.Method != "POST" || !strings.HasSuffix(cr.Path, "/conversations") {
		v.fault(where, "what the app signed is not a request to speak in a conversation")
		return
	}
	switch {
	case cr.NamesIdentityAgent && cr.IdentityAgent != v.b.Root:
		v.fault(where, "the app signed its request for %q, not for this organisation %s", cr.IdentityAgent, v.b.Root)
	case !cr.NamesIdentityAgent:
		v.cannotRuleOut("Some openings were signed in the first form, which names no Identity Agent, so which Identity Agent the app meant them for is the Identity Agent's word.")
	}
	signedAt, err := time.Parse(time.RFC3339, cr.Stamp)
	if err != nil || absDuration(at.Sub(signedAt)) > authorisation.Skew {
		v.fault(where, "the request was not signed within %s of when the Identity Agent took it", authorisation.Skew)
	}
	if p.ControllerGrant == "" {
		v.fault(where, "the app %s it was sent from has no Controller Grant, so nothing shows it was authorised", p.Controller)
		return
	}
	g, ok := v.creds[p.ControllerGrant]
	switch {
	case !ok:
		v.fault(where, "the bundle does not carry the Controller Grant %s of the app it was sent from", p.ControllerGrant)
	case g.schema != schemas.ControllerGrant.Schema.SAID:
		v.fault(where, "%s is not a Controller Grant", p.ControllerGrant)
	case g.holder != p.Controller || g.attr("public_key") != strings.TrimSpace(p.PublicKey):
		v.fault(where, "the request is signed by a key the Controller Grant does not name")
	default:
		// A request's time is stated to the second, and an app's grant is
		// re-issued while its first request is handled, to name the person it
		// acts for: the grant may be issued up to authorisation.Skew after the
		// request was signed, as authorisation.Check allows. It must not have
		// been revoked by the time the Identity Agent took the request.
		issuedBy := signedAt.Add(authorisation.Skew)
		if at.Before(issuedBy) {
			issuedBy = at
		}
		if why := g.liveBetween(issuedBy, at); why != "" {
			v.fault(where, "the app's Controller Grant was not in force when the request was signed: %s", why)
		}
		switch signer := g.attr("signer"); {
		case signer == "":
			v.cannotRuleOut("Some apps' Controller Grants name no signer, so which person spoke from them is the Identity Agent's word.")
		case signer != aid:
			v.fault(where, "the app's Controller Grant names %s as the person it acts for, not %s", signer, aid)
		}
	}
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// ── The governance log ──────────────────────────────────────────────────────

// checkLog checks the stretch of the log: every row signed by the log's
// signer, each linked to the one before, no id skipped, and a row for every
// entry. It returns each row's hash by id.
func (v *verifier) checkLog() map[int64]string {
	rows := v.b.Log.Rows
	v.r.LogRows = len(rows)
	hashes := map[int64]string{}
	if len(rows) == 0 {
		v.fault("governance log", "the bundle carries none of it")
		return hashes
	}
	kl, ok := v.kels[v.b.Log.Signer]
	var pub ed25519.PublicKey
	if !ok {
		v.fault("governance log", "the bundle carries no verified key log for its signer %s", v.b.Log.Signer)
	} else if p, err := login.DecodeVerkey(kl.current); err != nil {
		v.fault("governance log", "its signer's key is unreadable")
	} else {
		pub = p
	}
	keys := func(aid string) (ed25519.PublicKey, error) {
		if aid != v.b.Log.Signer || pub == nil {
			return nil, fmt.Errorf("%s is not the log's signer", aid)
		}
		return pub, nil
	}
	recorded := map[string]bool{}
	exported := false
	for i, row := range rows {
		where := fmt.Sprintf("log row %d", row.ID)
		ev, why, err := activitylog.CheckStoredRow(row, keys)
		if err != nil {
			why = err.Error()
		}
		if why != "" {
			v.fault(where, "%s", why)
		}
		if i > 0 {
			if row.ID != rows[i-1].ID+1 {
				v.fault(where, "the rows before it, from %d, are missing", rows[i-1].ID+1)
			} else if ev.PrevHash != activitylog.HashRecord([]byte(rows[i-1].Record)) {
				v.fault(where, "it does not follow from the row before it")
			}
		}
		hashes[row.ID] = activitylog.HashRecord([]byte(row.Record))
		if ev.CapabilityID == activitylog.CapabilityRecordAnchoring && len(v.b.Anchors) == 0 {
			v.fault(where, "it records that the record was anchored, and the bundle carries no anchors")
		}
		if ev.WorkItem == v.b.Conversation && ev.ResultStatus == "ok" {
			if ev.CapabilityID == "agent.conversation.export" && ev.CallerAID == v.b.ExportedBy && ev.TS == v.b.ExportedAt {
				exported = true
			}
			if kind, ok := strings.CutPrefix(ev.CapabilityID, "agent.message."); ok {
				for _, w := range strings.Fields(ev.Reason) {
					recorded[kind+" "+w] = true
				}
			}
		}
	}
	for _, m := range v.r.Messages {
		if m.MessageID != "" && !recorded[m.Kind+" "+m.MessageID] {
			v.fault(fmt.Sprintf("entry %d", m.Seq), "the governance log has no row recording it")
		}
	}
	if !exported {
		v.fault("governance log", "it carries no row recording this export, by %s at %s", v.b.ExportedBy, v.b.ExportedAt)
	}
	return hashes
}

// ── Anchors ────────────────────────────────────────────────────────────────

// checkAnchors checks every interaction of the record identity against the
// statement it seals, and that every entry and row a statement fixes is in
// the bundle unchanged. What no anchor fixes is listed.
func (v *verifier) checkAnchors(rowHashes map[int64]string) {
	anchoredSeq := 0
	var anchoredRow int64
	defer func() {
		v.r.AnchoredThrough = anchoredSeq
		for _, m := range v.r.Messages {
			if m.Seq > anchoredSeq {
				v.r.UnanchoredEntries = append(v.r.UnanchoredEntries, m.Seq)
			}
		}
		for i := range v.r.Messages {
			v.r.Messages[i].Anchored = v.r.Messages[i].Seq <= anchoredSeq
		}
		for _, row := range v.b.Log.Rows {
			if row.ID > anchoredRow {
				v.r.UnanchoredRows = append(v.r.UnanchoredRows, row.ID)
			}
		}
	}()
	if v.b.RecordIdentity == "" {
		if len(v.b.Anchors) > 0 {
			v.fault("anchors", "the bundle carries anchors and names no record identity")
		}
		v.cannotRuleOut("The bundle carries no anchors. Either nothing was anchored or they were removed, so entries or rows at the end of the record could have been removed without trace.")
		v.cannotRuleOut("Nothing ties the governance log's signer to the organisation, so the log rows carried rest on a signer anybody could have made.")
		return
	}
	where := "record identity " + v.b.RecordIdentity
	if why := v.delegatedFromRoot(v.b.RecordIdentity); why != "" {
		v.fault(where, "%s", why)
		return
	}
	kl := v.kels[v.b.RecordIdentity]
	if kl.witnesses == 0 {
		v.cannotRuleOut("The record identity names no witnesses, so its anchors are held by the Identity Agent alone: one in full control of it could rewrite the record and anchor it again.")
	} else if !kl.witnessed {
		v.cannotRuleOut("Not every anchor carries the witness receipts the record identity asks for.")
	} else {
		v.r.Trusts = append(v.r.Trusts, fmt.Sprintf("The %d witnesses the record identity names, whose receipts the bundle carries for every anchor.", kl.witnesses))
	}
	v.cannotRuleOut("Anchors newer than the record identity's key log as the bundle gives it: offline, a key log cut short looks like a shorter one, unless its witnesses are asked.")
	v.cannotRuleOut("Entries and rows written after the newest anchor rest on their signatures alone: the newest of them could be removed without trace.")
	statements := map[int]string{}
	for _, a := range v.b.Anchors {
		if _, dup := statements[a.Seq]; dup {
			v.fault(where, "the bundle carries two statements for anchor %d", a.Seq)
		}
		statements[a.Seq] = a.Statement
	}
	signerNamed := false
	firstRow, lastRow := int64(0), int64(0)
	if n := len(v.b.Log.Rows); n > 0 {
		firstRow, lastRow = v.b.Log.Rows[0].ID, v.b.Log.Rows[n-1].ID
	}
	for sn := 1; sn < len(kl.events); sn++ {
		aw := fmt.Sprintf("anchor %d", sn)
		ev := kl.events[sn]
		statement, ok := statements[sn]
		delete(statements, sn)
		if t, _ := ev["t"].(string); t != "ixn" {
			v.fault(aw, "the record identity's key log holds a %q, where it holds only anchors", t)
			continue
		}
		if !ok {
			v.fault(aw, "the bundle does not carry the statement this anchor seals")
			continue
		}
		digest, err := iacrypto.Blake3QB64([]byte(statement))
		if err != nil || !sealsDigest(ev, digest) {
			v.fault(aw, "the statement carried is not the one this anchor seals")
			continue
		}
		var st activitylog.AnchorStatement
		if err := json.Unmarshal([]byte(statement), &st); err != nil {
			v.fault(aw, "the statement it seals is unreadable")
			continue
		}
		switch st.Signer {
		case "":
		case v.b.Log.Signer:
			signerNamed = true
		default:
			v.fault(aw, "it names %s as the governance log's signer, not %s, who signed the rows the bundle carries", st.Signer, v.b.Log.Signer)
		}
		for _, c := range st.Conversations {
			if c.ID != v.b.Conversation {
				continue
			}
			if h, ok := v.hashes[c.Seq]; !ok || c.Seq > len(v.b.Entries) || h != c.Head {
				v.fault(aw, "it fixes entry %d of this conversation, which the bundle does not carry unchanged", c.Seq)
				continue
			}
			if c.Seq > anchoredSeq {
				anchoredSeq = c.Seq
			}
		}
		switch row := st.Log.Row; {
		case row == 0 || row < firstRow:
			// Before the stretch the bundle carries; nothing here to compare.
		case row > lastRow:
			v.fault(aw, "it fixes log row %d, which the bundle does not carry: rows the anchor fixes have been removed", row)
		case rowHashes[row] != st.Log.Head:
			v.fault(aw, "it fixes log row %d, which the bundle does not carry unchanged", row)
		default:
			if row > anchoredRow {
				anchoredRow = row
			}
		}
	}
	switch {
	case signerNamed:
		v.r.Trusts = append(v.r.Trusts, "The governance log's signer, which the record identity's anchors name.")
	case len(v.b.Log.Rows) > 0:
		v.cannotRuleOut("No anchor names the governance log's signer, so only the rows an anchor fixes are tied to the organisation; the rest rest on a signer anybody could have made.")
	}
	extra := make([]int, 0, len(statements))
	for sn := range statements {
		extra = append(extra, sn)
	}
	sort.Ints(extra)
	for _, sn := range extra {
		v.fault(fmt.Sprintf("anchor %d", sn), "the bundle carries a statement no interaction of the record identity seals")
	}
}

// sealsDigest reports whether an interaction's seals include digest.
func sealsDigest(ev map[string]interface{}, digest string) bool {
	seals, _ := ev["a"].([]interface{})
	for _, raw := range seals {
		if seal, ok := raw.(map[string]interface{}); ok && seal["d"] == digest {
			return true
		}
	}
	return false
}

// ── Reading the report ───────────────────────────────────────────────────────

// Text is the report as a person reads it.
func (r Report) Text() string {
	var b strings.Builder
	if r.Verified {
		fmt.Fprintf(&b, "VERIFIED: conversation %s\n", r.Conversation)
	} else {
		fmt.Fprintf(&b, "NOT VERIFIED: conversation %s — %d check(s) failed\n", r.Conversation, len(r.Faults))
	}
	fmt.Fprintf(&b, "Organisation root identity: %s\n", r.Root)
	for _, f := range r.Faults {
		fmt.Fprintf(&b, "  FAILED  %s: %s\n", f.Where, f.Why)
	}
	b.WriteString("\nMessages:\n")
	for _, m := range r.Messages {
		state := "holds"
		if !m.Holds {
			state = "FAILS"
		}
		anchored := "anchored"
		if !m.Anchored {
			anchored = "NOT YET ANCHORED"
		}
		who := m.Sender
		if m.Grade != "" {
			who += ", " + m.Grade
		}
		if m.Person != "" {
			who += ", for " + m.Person
		}
		fmt.Fprintf(&b, "  %3d  %-8s %s -> %s  [%s]  %s, %s\n", m.Seq, m.Kind, m.From, m.To, who, state, anchored)
	}
	fmt.Fprintf(&b, "\nAnchored through entry %d of %d.", r.AnchoredThrough, len(r.Messages))
	if len(r.UnanchoredEntries) > 0 {
		fmt.Fprintf(&b, " Entries after the last anchor: %s.", joinInts(r.UnanchoredEntries))
	}
	fmt.Fprintf(&b, "\nGovernance log: %d row(s) carried, %d after the last anchor.\n", r.LogRows, len(r.UnanchoredRows))
	b.WriteString("\nThis result trusts:\n")
	for _, t := range r.Trusts {
		fmt.Fprintf(&b, "  - %s\n", t)
	}
	b.WriteString("\nIt cannot rule out:\n")
	for _, c := range r.CannotRuleOut {
		fmt.Fprintf(&b, "  - %s\n", c)
	}
	return b.String()
}

func joinInts(ns []int) string {
	parts := make([]string, len(ns))
	for i, n := range ns {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ", ")
}
