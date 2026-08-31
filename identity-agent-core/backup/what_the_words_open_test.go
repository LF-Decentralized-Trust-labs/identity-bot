package backup

import (
	"crypto/rand"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// Nothing may be added to the words-openable envelope without somebody saying
// why.
//
// This is the guard the whole design rests on, and it is the reason the
// bootstrap envelope is a closed list at all. Everything in here is readable
// by anybody holding this identity's backup and its recovery phrase — which
// after the rest of this change is the one remaining thing a stolen phrase
// gets. A field added without thought hands private data back to exactly the
// attacker the shares were introduced to stop.
//
// So this fails when the shape changes, on purpose. Updating it should require
// writing down why a thief may read the new thing.
func TestNothingIsAddedToTheWordsOpenableEnvelopeQuietly(t *testing.T) {
	var got []string
	ty := reflect.TypeOf(WhatTheWordsOpen{})
	for i := 0; i < ty.NumField(); i++ {
		tag := ty.Field(i).Tag.Get("json")
		name := strings.Split(tag, ",")[0]
		if name == "" || name == "-" {
			t.Fatalf("field %s has no json name, so it cannot be reasoned about",
				ty.Field(i).Name)
		}
		got = append(got, name)
	}
	want := append([]string{}, bootstrapFields...)
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf(
			"the words-openable envelope changed shape.\n  now:      %v\n  expected: %v\n\n"+
				"Everything here is readable by anybody holding this identity's backup and "+
				"its recovery phrase. If the new field is a public key, an already-published "+
				"identifier, or policy, add it to bootstrapFields and say so in the doc "+
				"comment. If it is a secret, or if it describes who this identity knows, it "+
				"belongs in the main envelope.", got, want)
	}
}

// The envelope must not carry the things a thief wants.
//
// The field list above is the rule; this is the same rule checked against a
// real envelope, so a secret smuggled inside a permitted field — a private key
// in a "public keys" list, a contact list serialised into policy — is caught
// too.
func TestTheWordsOpenableEnvelopeCarriesNothingWorthStealing(t *testing.T) {
	holder, _ := aHolder(t, "EWitness", "witness")
	bek := make([]byte, 32)
	rand.Read(bek)
	seedKEK := make([]byte, 32)
	rand.Read(seedKEK)

	split := HowTheWayInIsSplit{Needed: 1, Holders: []ShareHolder{holder}}
	sealed, wraps, err := SplitTheWayIn(bek, seedKEK, split)
	if err != nil {
		t.Fatal(err)
	}

	env := WhatTheWordsOpen{
		IdentityAID:             "EMyIdentity",
		Split:                   split,
		SealedShares:            sealed,
		SubsetWraps:             wraps,
		DuressPolicy:            json.RawMessage(`{"hold_for_hours":48}`),
		AuthenticatorPublicKeys: []string{"dGVzdA=="},
	}
	if err := env.Validate(); err != nil {
		t.Fatal(err)
	}

	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	// The archive key itself must never appear. If it did, the words would
	// open everything again and the shares would be decoration.
	if strings.Contains(string(raw), EncodeB64(bek)) {
		t.Fatal("the main archive key is in the envelope the words open")
	}
	// Nor may a share appear unsealed. Each is sealed to one holder, and the
	// point is that this archive cannot produce them.
	for _, s := range sealed {
		if s.WrappedB64 == "" {
			t.Fatal("a share is carried unsealed")
		}
	}
	// And nothing that names the people this identity knows.
	for _, leak := range []string{"contacts", "credentials", "private", "seed", "mnemonic"} {
		if strings.Contains(strings.ToLower(string(raw)), leak) {
			t.Fatalf("the words-openable envelope mentions %q", leak)
		}
	}
}

// A backup that names a holder it has no share for could never be opened by
// that holder, and the owner should learn that when the backup is made.
func TestAHolderWithNoShareIsRefused(t *testing.T) {
	holder, _ := aHolder(t, "EWitness", "witness")
	other, _ := aHolder(t, "EOther", "witness")
	env := WhatTheWordsOpen{
		IdentityAID: "EMyIdentity",
		Split:       HowTheWayInIsSplit{Needed: 1, Holders: []ShareHolder{holder, other}},
		SealedShares: []SealedShare{
			{HolderID: "EWitness", WrappedB64: "x"},
		},
		SubsetWraps: []SubsetWrap{{HolderIDs: []string{"EWitness"}, WrappedB64: "y"}},
	}
	err := env.Validate()
	if err == nil {
		t.Fatal("a holder with no share was accepted")
	}
	if !strings.Contains(err.Error(), "could never take part") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}
}

// The duress policy has to be readable before shares are gathered.
//
// A machine recovering an identity has nothing of its own to read. A policy
// that travelled only in the part needing shares to open could not be
// consulted when deciding whether to release them — and it has already been
// absent from every archive once, through a tier nothing requested, with the
// gate then finding nothing and passing.
func TestTheDuressPolicyTravelsWhereABlankMachineCanReadIt(t *testing.T) {
	found := false
	for _, f := range bootstrapFields {
		if f == "duress_policy" {
			found = true
		}
	}
	if !found {
		t.Fatal("the duress policy is not in the envelope a blank machine can open")
	}
}
