package iacrypto

import "testing"

func TestTheBackupKeyIsInsideWhatTheHardwareVouchesFor(t *testing.T) {
	// Two offers differing only in the key backups are signed with must not
	// produce the same binding — otherwise anything terminating the connection
	// can swap that key and the hardware's statement still checks out.
	a, err := PairingOfferBinding("KEY-ONE", "KEY-TWO", "BACKUP-KEY-MINE")
	if err != nil {
		t.Fatal(err)
	}
	b, err := PairingOfferBinding("KEY-ONE", "KEY-TWO", "BACKUP-KEY-THEIRS")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("the key a machine signs its backups with is outside what its hardware " +
			"vouches for, so it can be substituted and every forgery afterwards verifies")
	}
	if _, err := PairingOfferBinding("KEY-ONE", "KEY-TWO", ""); err == nil {
		t.Fatal("an offer with no backup signing key was covered anyway")
	}
}
