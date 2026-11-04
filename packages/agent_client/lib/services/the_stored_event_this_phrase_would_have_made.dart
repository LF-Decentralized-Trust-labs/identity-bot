import 'dart:convert';
import 'dart:typed_data';

import '../crypto/keys.dart';
import 'the_key_events_this_device_makes.dart' show KeyPaths;
import 'key_math.dart';
import 'the_event_this_device_expects.dart';
import 'the_witnesses_of_this_devices_events.dart' show WitnessSet;

/// The event an earlier version stored unsigned, as this phrase would have
/// made it: the [ExpectedEvent] a stored, marked event must be before it is
/// signed late (ADR-061 section 3, "the signer").
///
/// Earlier versions made a rotation that commits to the next classical key
/// alone, with one key at a threshold of one, no post-quantum commitment and no
/// anchor, and changes no witness. Before 2026-10-31 /api/inception made a
/// founding that also anchored the messaging keyset (from 2026-08-09) and
/// committed to the post-quantum key (from 2026-08-18) whenever the key was one
/// the Identity Agent derived itself, and stored it unsigned: both are
/// recomputed from [seed] and accepted exactly
/// ([theStoredFoundingThisPhraseWouldHaveMade]). The keys and commitments come
/// from [seed]; where the event sits and what it follows from
/// the key state this device trusts ([prior] is the digest of the event it
/// follows, [toad] the witness threshold in force), never from fields or earlier
/// bytes the core reports beside the event. What the phrase cannot
/// say, the founding's witnesses and their threshold and an interaction's
/// anchors, is read from the stored event: an interaction is signed late only
/// as an event this device asked for or the person approved, and a founding's
/// witnesses are the core's choice.
///
/// [ixnAnchors] are the seals an interaction must carry: what this device asked
/// for, or, for an interaction the person approved after being shown it, what
/// it stores. Left null, the interaction is refused ([NotTheEventExpected]):
/// one this device did not ask for, or asked for without saying what it anchors
/// (a credential's), is shown to the person and signed only when they approve.
///
/// [t], [aid], [sn] and [digest] are what this device recorded when it asked
/// for the event (or, for one the person approved, what they were shown), never
/// what the stored bytes say: the bytes must be that event. [digest] is null
/// only where the core's answer never arrived.
///
/// [generation] is the key this event reveals (0 for the founding).
/// [ownerAid] is the owner the person named for the identity, whose seal a
/// founding made for one carries. It must come from this device's own record of
/// who the person named, never from a response of the core: whatever is passed
/// is what the founding may seal.
/// [witnesses] are the witnesses and threshold this device itself knows the
/// identity has, or null where it knows none; see
/// [theStoredFoundingThisPhraseWouldHaveMade].
Future<ExpectedEvent> theStoredEventThisPhraseWouldHaveMade(
  KeyMath km,
  Uint8List seed, {
  required String t,
  required String aid,
  required int sn,
  String? digest,
  required ParsedEvent stored,
  required String prior,
  required int toad,
  required int generation,
  String? ownerAid,
  List<Object?>? ixnAnchors,
  WitnessSet? witnesses,
}) async {
  Future<List<String>> next() async =>
      [await km.nextKeyDigest(KeyManager.publicKeyAt(seed, generation + 1))];
  ExpectedEvent known(ExpectedEvent e) => digest == null ? e : e.withDigest(digest);
  switch (t) {
    case 'icp':
      return known(await theStoredFoundingThisPhraseWouldHaveMade(km, seed, stored,
          ownerAid: ownerAid, witnesses: witnesses));
    case 'rot':
      return known(ExpectedEvent.rotation(
          aid: aid,
          sn: sn,
          prior: prior,
          keys: [KeyManager.publicKeyAt(seed, generation)],
          next: await next(),
          toad: toad));
    case 'ixn':
      // An interaction is signed late only with the seals this device asked
      // for or the person was shown. A seal of the form {i: x, s: "0", d: x}
      // is a credential's, and it is also what a delegator's approval of a
      // delegate looks like (keriengine approvalIn), so nothing about the
      // stored event can say which it is.
      if (ixnAnchors == null) {
        throw NotTheEventExpected('this device did not ask for the seals this '
            'interaction carries, and the person has not been shown them');
      }
      return known(ExpectedEvent.interaction(
          aid: aid, sn: sn, prior: prior, anchors: ixnAnchors));
    default:
      throw NotTheEventExpected('it is a $t, which this device does '
          'not sign late');
  }
}

/// The branches the Identity Agent allocated a founding's messaging keys on
/// before 2026-10-31, as the first allocation of the `messaging-keys` pool: its
/// base, 5000001 (PoolBase("messaging-keys") in identity-agent-core/store, which
/// a test pins to the Go side through test/support/legacy_founding_golden.json).
///
/// Branch 1 is not here. Every founding on it (9 to 12 August) predates the CESR
/// change of 9d760a24 and so cannot match a keyset computed now; accepting it
/// would only let a core get a founding anchoring keys from
/// m/44'/0'/0'/1'/0' (also the pairwise seed of contacts-pool index 1) signed.
const legacyMessagingBranches = [5000001];

/// The founding an earlier version stored, as this phrase would have made it.
///
/// Three shapes are accepted, each exactly, and nothing else:
///  - the plain one: key 0, a commitment to key 1, the owner seal if the person
///    named an owner ([ownerAid]), nothing more;
///  - what /api/inception made from 2026-08-09 (3869b873) for a key it derived
///    itself: the same, with the owner seal followed by the anchor of the
///    messaging keyset on the branch it allocated ([legacyMessagingBranches]);
///  - what it made from 2026-08-18 (f2bd7b7d): that, committing also to the
///    post-quantum key of KeyPaths.postQuantum(0) in `n`.
/// Every part is recomputed from [seed] and the stored event must hold exactly
/// that: the messaging keyset on the branch whose anchor it carries is derived
/// from the phrase, so a keyset the core made itself matches none.
///
/// Witnesses and their threshold are the core's designation
/// (WitnessesForNewIdentity). Where this device knows its identity's
/// [witnesses] the founding's `b` and `bt` must equal them. Where it knows none
/// they are read from [stored], as they always were: those foundings were the
/// core's choice, and there is nothing here to hold it to.
Future<ExpectedEvent> theStoredFoundingThisPhraseWouldHaveMade(
    KeyMath km, Uint8List seed, ParsedEvent stored,
    {String? ownerAid, WitnessSet? witnesses}) async {
  final owner = [
    if ((ownerAid ?? '').isNotEmpty) {'i': ownerAid, 's': '0', 'd': ownerAid}
  ];
  final a = stored['a'];
  final n = stored['n'];
  final key = KeyManager.publicKeyAt(seed, 0);
  final next = KeyManager.publicKeyAt(seed, 1);
  Future<ExpectedEvent> plain(List<Object?> anchors, List<String> alsoCommitTo) =>
      theStoredFoundingThisKeyWouldHaveMade(km, stored,
          key: key, next: next, anchors: anchors, alsoCommitTo: alsoCommitTo, witnesses: witnesses);
  // A founding with seals beyond the owner's carries the messaging keyset.
  if (a is! List || a.length <= owner.length) return plain(owner, const []);
  final alsoCommitTo = <String>[];
  if (n is List && n.length == 2) {
    final pq = KeyManager.slip10Ed25519(seed, KeyPaths.postQuantum(0));
    try {
      alsoCommitTo.add((await km.postQuantumNext(pq)).digest);
    } finally {
      pq.fillRange(0, pq.length, 0);
    }
  }
  ExpectedEvent? first;
  for (final branch in legacyMessagingBranches) {
    final child = KeyManager.slip10Ed25519(
        seed, KeyPaths.messagingOnAllocatedBranch(branch));
    final Map<String, dynamic> keyset;
    try {
      keyset = await km.messagingKeySet(child);
    } finally {
      child.fillRange(0, child.length, 0);
    }
    final candidate = await plain([...owner, keyset], alsoCommitTo);
    if (candidate.differenceFrom(stored) == null) return candidate;
    first ??= candidate;
  }
  return first!;
}

/// The founding an earlier version stored, as the key [key] committing to
/// [next] alone (and [alsoCommitTo]) would have made it: one key, [anchors] and
/// the witnesses the core chose, read from [stored].
Future<ExpectedEvent> theStoredFoundingThisKeyWouldHaveMade(
    KeyMath km, ParsedEvent stored,
    {required String key,
    required String next,
    List<Object?> anchors = const [],
    List<String> alsoCommitTo = const [],
    WitnessSet? witnesses}) async {
  final b = stored['b'];
  final inStored = b is List ? [for (final w in b) '$w'] : const <String>[];
  // The same witnesses in another order are the same set: the order is the
  // stored event's, and it is compared as it stands.
  final known = witnesses?.witnesses;
  final sameSet = known != null && known.length == inStored.length && known.toSet().containsAll(inStored);
  return ExpectedEvent.founding(
      keys: [key],
      next: [await km.nextKeyDigest(next), ...alsoCommitTo],
      witnesses: known == null || sameSet ? inStored : known,
      toad: witnesses?.toad ?? int.tryParse('${stored['bt']}', radix: 16) ?? -1,
      anchors: anchors);
}

/// Parses the stored bytes [rawB64] of an event with the core's parser. Bytes
/// that are not a well-formed event are a [NotTheEventExpected]: they are not
/// signed, and the person is shown them.
Future<ParsedEvent> parseTheStoredEvent(KeyMath km, String rawB64) async {
  try {
    return await km.parseEvent(base64Decode(rawB64));
  } on KeyMathRefused catch (e) {
    throw NotTheEventExpected(
        'the stored bytes are not a well-formed event: ${e.reason}');
  } on FormatException {
    throw NotTheEventExpected('the stored bytes are not base64');
  }
}
