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
	// AID identifies the service as a contact. The URL is how to reach it.
	AID string
	// WitnessKey is the non-transferable identifier this service signs receipts
	// with, and it — not AID — is what an inception event designates.
	//
	// The distinction is not bookkeeping. A witness identifier has to BE its
	// verifying key, or checking a receipt means first resolving that witness's
	// key log and working out which key was in force when the receipt was
	// issued, for every receipt and every verifier, forever. Designating a
	// transferable AID produces receipts nobody can check cheaply, and a
	// witness that rotates leaves its old receipts unverifiable.
	//
	// Empty until each service publishes one. A witness with no published
	// witness key is NOT designated: writing it into an inception event would
	// name an observer whose receipts can never be verified, and the identifier
	// is permanent.
	WitnessKey string
	// URL is where events are submitted and receipts collected.
	URL string
	// Operator names who runs it, so somebody deciding whether to rely on it
	// knows whom they are relying on.
	Operator string
}

// BootstrapPool is what a freshly incepted identity uses until its own contacts
// can take over.
//
// One service today. That is a smaller pool than anyone would design, and it is
// what actually exists: a second and third operator are expected, and the moment
// they publish a witness key they belong here.
//
// Being a single operator at the start is not a flaw in the arrangement, it is
// the shape of the problem. An identity has to be witnessed at the moment its
// keys are established, and that is precisely the moment it knows nobody — which
// stays true no matter how large the network grows, because every new person
// still arrives with no contacts. Peers displace this as they accumulate;
// `withBootstrap` appends rather than prefers, so the pool shrinks out of use on
// its own.
//
// The identifier here is the WITNESS KEY, not the service's contact identifier.
// A witness is named in a permanent event and its receipts have to be checkable
// forever, which only a non-transferable identifier allows. Verified against the
// running service on 2026-08-10: a receipt it issued verifies against this key
// with nothing fetched.
func BootstrapPool() []BootstrapWitness {
	return []BootstrapWitness{
		{
			AID:        "BMtfjviEMpF2xWVW0CRPKoVPX1mOMzNurvUjD-0RN_Jl",
			WitnessKey: "BMtfjviEMpF2xWVW0CRPKoVPX1mOMzNurvUjD-0RN_Jl",
			URL:        "https://witness1.grapeid.org",
			Operator:   "grapeid.org",
		},
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
		out = append(out, witnessTarget{AID: b.AID, WitnessKey: b.WitnessKey, URL: b.URL, Commercial: true})
	}
	return out
}

// oneBootstrapFor picks a single bootstrap witness for a pairwise AID.
//
// A pairwise AID cannot be witnessed by contacts — a distinctive contact set
// shared across two pairwise AIDs would let an observer link them to one
// person, which is exactly what separate AIDs exist to prevent. Witness lists
// are public, so the set itself is a fingerprint. Commercial witnesses avoid
// this because they serve a large population: naming one says nothing about
// who you are.
//
// That leaves the question of WHICH one, and the honest answer is that using
// the same one for all of somebody's pairwise AIDs hands that operator the
// contact graph in its own logs. So the choice is spread across the pool by
// the AID itself: stable for a given AID (the same event always goes to the
// same place, and a receipt can be chased), uniform across the pool, and
// requiring no stored state.
//
// One rather than three because a pairwise AID needs an observer that will
// notice duplicity, not a quorum. Three would triple the correlation surface
// to buy availability that a single relationship does not need.
func oneBootstrapFor(aid string) (witnessTarget, bool) {
	pool := BootstrapPool()
	if len(pool) == 0 {
		return witnessTarget{}, false
	}
	// FNV-1a over the AID. Any stable spread does; this one needs no imports
	// beyond what the file already has and does not pretend to be a security
	// property — it is a bucketing function, not a secret.
	var h uint32 = 2166136261
	for i := 0; i < len(aid); i++ {
		h ^= uint32(aid[i])
		h *= 16777619
	}
	b := pool[int(h%uint32(len(pool)))]
	return witnessTarget{AID: b.AID, WitnessKey: b.WitnessKey, URL: b.URL, Commercial: true}, true
}

// DesignatableWitnesses returns the witnesses that can actually be written into
// an inception event, with the threshold to require of them.
//
// Only witnesses whose non-transferable witness key is known are returned. That
// filter is the whole function: a witness list is written into the inception
// event and is therefore permanent and public, so designating somebody whose
// receipts can never be verified is a mistake that cannot be taken back — the
// identifier is a digest of the event that names them.
//
// Returning nothing is a valid answer and an honest one. An identity with no
// witnesses is correctly reported as unwitnessed, which is a smaller problem
// than one that appears witnessed by observers who cannot corroborate anything.
func DesignatableWitnesses(candidates []witnessTarget) (keys []string, toad int) {
	for _, c := range candidates {
		if c.WitnessKey == "" {
			continue
		}
		keys = append(keys, c.WitnessKey)
	}
	if len(keys) == 0 {
		return nil, 0
	}
	// A simple majority: enough that a minority of unavailable or dishonest
	// witnesses can neither stall the identity nor corroborate a forgery.
	return keys, len(keys)/2 + 1
}
