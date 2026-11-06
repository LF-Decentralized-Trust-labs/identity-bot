package didcomm

import "identity-agent-core/messagingkeys"

// DeriveKeySet reproduces an identity's four messaging keys from a seed, as
// messagingkeys.Derive does, filed under aid.
func DeriveKeySet(aid string, seed []byte) (*KeySet, error) {
	k, err := messagingkeys.Derive(seed)
	if err != nil {
		return nil, err
	}
	return &KeySet{AID: aid, EdPub: k.EdPub, EdPriv: k.EdPriv, DsaPub: k.DsaPub, DsaPriv: k.DsaPriv,
		XPub: k.XPub, XPriv: k.XPriv, KemPub: k.KemPub, KemPriv: k.KemPriv}, nil
}

// Anchor is the seal a key log commits to this keyset with, as
// messagingkeys.Keys.Anchor writes it: the one construction of it.
func (k *KeySet) Anchor() (map[string]interface{}, error) {
	return (&messagingkeys.Keys{EdPub: k.EdPub, DsaPub: k.DsaPub, XPub: k.XPub, KemPub: k.KemPub}).Anchor()
}
