package witness

// Who witnesses an identity before it knows anybody.
//
// The design here is peer-to-peer: every Identity Agent is a witness for its
// contacts, so most people's witnesses are the people they already know, at no
// cost and with no third party involved. `enrolledWitnesses` reflects that — it
// draws entirely from contacts marked as witnesses.
//
// Which leaves one gap, and it is a gap of ordering rather than principle: a
// brand-new identity has no contacts. It must be witnessed by somebody before
// it has anybody, and the moment it is most worth witnessing — inception, when
// its keys are established — is the moment it has the fewest people to ask.
//
// So a small bootstrap pool covers the distance between inception and having
// contacts of one's own. It is deliberately not the network. An identity still
// relying only on these a year later has not been onboarded properly, and the
// intent is that contacts displace them as they accumulate.
//
// There is also a lasting reason to keep one or two beyond bootstrap, which is
// not about availability. A professionally operated witness is systematically
// run, and that makes it badly placed to do somebody a favour: bending the
// rules for one person would mean changing a process or opening a back door,
// and staking a business on it — a poor trade for a service given away free. A
// friend's agent offers a different assurance, held for different reasons.
// Having both is worth more than having either.

// BootstrapWitness is a service an identity can rely on before it has contacts.
type BootstrapWitness struct {
	// AID is what gets written into the inception event. The URL is how to
	// reach it; the AID is what it is, and it is the AID that the event names.
	AID string
	// URL is where events are submitted and receipts collected.
	URL string
	// Operator names who runs it, so somebody deciding whether to rely on it
	// knows whom they are relying on.
	Operator string
}

// BootstrapPool is what a freshly incepted identity uses until its own contacts
// can take over.
//
// Three services with three distinct identities. Verified live on 2026-07-29:
// each host serves both a witness and a watcher role under one AID, so the real
// count of independent operators is three rather than six — worth knowing,
// because a threshold above three would have nothing to draw on.
func BootstrapPool() []BootstrapWitness {
	return []BootstrapWitness{
		{AID: "EvRHjssG5WJjwq5c2AA8yOfY7VT3keG0XOtdRLz195P8", URL: "https://witness1.grapeid.org", Operator: "grapeid.org"},
		{AID: "EoO3LBQt1s_tot1yH1EFKMQ0Z4EMP2mp0jp3zw5u0Bn8", URL: "https://witness2.grapeid.org", Operator: "grapeid.org"},
		{AID: "EZEx_C9TEyy23To57F_r67Y5nvIe4KvrpXveyIpW4OFM", URL: "https://witness3.grapeid.org", Operator: "grapeid.org"},
	}
}

// withBootstrap tops a contact-derived witness list up to a workable size.
//
// Bootstrap witnesses are APPENDED rather than preferred, so an identity with
// enough contacts of its own leans on them and not on us. They fill in only
// while there are too few to reach a threshold worth having — which is the
// whole point of them, and also why this shrinks to nothing on its own as
// somebody accumulates contacts.
//
// `want` is the number of witnesses that would make a threshold meaningful. It
// is a floor rather than a target: a contact list that already exceeds it is
// left entirely alone.
func withBootstrap(contactWitnesses []witnessTarget, want int) []witnessTarget {
	if len(contactWitnesses) >= want {
		return contactWitnesses
	}

	have := make(map[string]bool, len(contactWitnesses))
	for _, w := range contactWitnesses {
		have[w.AID] = true
	}

	out := contactWitnesses
	for _, b := range BootstrapPool() {
		if len(out) >= want {
			break
		}
		// A contact who happens to be one of these is not two witnesses.
		// Counting it twice would inflate the threshold while adding no
		// independent observer, which is worse than a smaller honest pool
		// because it looks stronger than it is.
		if have[b.AID] {
			continue
		}
		out = append(out, witnessTarget{AID: b.AID, URL: b.URL, Commercial: true})
	}
	return out
}
