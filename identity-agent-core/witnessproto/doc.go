// Package witnessproto holds the rules an Identity Agent and a witness or
// watcher service must apply identically, so that both import one
// implementation rather than each keeping a copy that can drift.
//
// Drift here is not a degraded feature. Each side computes the value the other
// compares against, so a difference in how a key log is read or digested makes
// an honest identity look as if it had published two histories, and the
// Identity Agent refuses it as duplicitous.
//
// What it holds today:
//
//   - [SequenceNumber]: reading a key event's sequence number, which KERI
//     writes in hexadecimal;
//   - [KelDigestAtSeq] and [CurrentSeq]: the digest of a key log up to a
//     sequence number, which a watcher publishes and a verifier compares.
//
// The digest is pinned by kel-digest-vectors.json, which is part of this
// package so that any other implementation can test itself against the same
// vectors.
package witnessproto
