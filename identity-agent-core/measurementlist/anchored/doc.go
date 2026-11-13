// Package anchored checks an accepted-software list that is a credential
// issued under a pinned publisher identity and anchored in that identity's
// witnessed key history, instead of a document signed by a pinned key.
//
// What a build pins is the publisher's identifier, its inception event, its
// registry's identifier and the schema's SAID (Pin). It pins no key: the keys
// come from the publisher's own key history, so a rotation of them, from one
// key to several or to others, needs no new app.
//
// # The credential
//
// A list is an ACDC whose attribute block carries the list's content (sequence,
// published_at, expires_at, images) and no holder. It is issued by the
// publisher into a backerless registry (a "vcp" with the configuration trait
// "NB", no backers, bt "0"). The issuance ("iss", sequence 0) and, when a list
// is withdrawn, the revocation ("rev", sequence 1, naming the issuance) are
// transaction events of that registry. Each transaction event, the registry's
// inception included, is sealed in the publisher's key history by an event seal
// {i, s, d} in the "a" field of an interaction event: i is the credential's
// identifier (the registry's, for its inception), s the transaction event's
// sequence number in lowercase hex, d its SAID.
//
// Every event seal {i, s, d} in the publisher's history must be matched by a
// transaction event of the bundle (so a withheld "rev" is seen from its seal
// alone), and every transaction event must be sealed; Verify refuses the whole
// bundle otherwise. Other anchors in the history (the owner named at founding,
// the owners' record, a handover's steps) are not event seals and are not read:
// the publisher is a black box's identity and keeps them.
//
// # The bundle
//
//	{"bundle_version": 1, "publisher": "<aid>", "registry": "<id>",
//	 "kel": ["<base64url>", ...], "tel": ["<base64url>", ...],
//	 "credentials": ["<base64url>", ...]}
//
// kel is the publisher's events from inception, each as its raw KERI bytes
// followed by its CESR attachments (controller signatures, witness receipts).
// tel is every transaction event of the registry, credentials is every list
// credential, as raw bytes. The bundle has no signature of its own: everything
// in it is checked, and nothing is trusted for being there. At most
// MaxBundleBytes.
//
// # What Verify requires
//
//  1. Freshness. At least the witness threshold of the publisher's designated
//     witnesses answered a nonce this device sent with their signed tip, and
//     every answer names the same tip (AgreedTip). The bundle's history ends
//     at that tip. A bundle behind it is ErrBehind, and the caller fetches the
//     missing events. No clock is trusted for this.
//  2. The history is genuine: its inception is the pinned one and derives the
//     pinned identifier; keri.ValidateSignedKEL passes on the raw events and
//     signatures (the signing threshold in force at each event, and a rotation
//     meeting its prior next threshold by the keys it presents, whatever the
//     thresholds are, however many keys); it extends the history this device
//     already holds (Floors), else it is ErrDuplicity.
//  3. The anchor is real and complete, as above, and the credential is the
//     pinned publisher's, under the pinned schema, in the pinned registry, with
//     no holder.
//  4. Every event is signed at its threshold and carries receipts from enough
//     of the witnesses designated for it, and the identity has witnesses.
//  5. The list is not withdrawn.
//  6. It is the newest list sealed and not withdrawn.
//  7. Every rule of a signed list holds (measurementlist.FromContent): the
//     sequence floor, the same sequence with other content, expiry, entry
//     windows and shape.
//
// The check is pure: it reads nothing and calls nothing. The time and the
// witnesses' answers are inputs. A Resolver (resolver.go) is the network half.
package anchored
