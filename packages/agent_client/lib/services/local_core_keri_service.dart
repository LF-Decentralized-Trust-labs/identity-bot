import 'dart:convert';
import 'dart:typed_data';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:http/http.dart' as http;
import '../crypto/bip39.dart';
import '../crypto/keys.dart';
import 'key_math.dart';
import 'keri_service.dart';
import 'recovering_this_identity.dart';
import 'secure_key_store.dart';
import 'signing_an_event.dart';
import 'the_events_this_device_asked_for.dart';
import 'the_identity_this_device_holds.dart';
import 'the_key_events_this_device_makes.dart';
import 'the_key_state_this_device_reads.dart';
import 'the_witnesses_of_this_devices_events.dart';
import 'the_key_in_force.dart';
import 'the_key_is_not_held_by_the_core.dart';
import 'the_agent_this_app_talks_to.dart';

/// KERI against the Identity Agent core running on this machine.
///
/// Named for what it talks to rather than what kind of computer it is on,
/// because it turned out to be right for both. It was DesktopOnDeviceKeriService
/// while mobile had a KERI engine of its own — a Rust library that generated a
/// random key instead of deriving one from the recovery phrase it was given,
/// and held it in memory. Mobile now uses this, against the core running inside
/// the app, so there is one KERI implementation everywhere and the key comes
/// from the words on every platform.
class LocalCoreKeriService extends KeriService {
  final String _baseUrl;
  final http.Client _client;

  /// [keyMath] is how this app runs the core's key arithmetic (a phone's
  /// bridge, or the core binary on a desktop). Founding, rotating and
  /// interacting need it; without it they refuse rather than fall back.
  LocalCoreKeriService({String? baseUrl, http.Client? client, this.keyMath})
      // Where the KEYS are, which is not always this computer.
      //
      // Stateful KERI operations always run on the engine local to the keys —
      // that invariant is about the KEYS, not about this process. When the
      // identity lives on a sealed machine, that machine's engine is the local
      // one and this installation is only the front end.
      : _baseUrl = baseUrl ?? TheAgentThisAppTalksTo.origin,
        _client = client ?? TheAgentThisAppTalksTo.clientFor(baseUrl);

  /// Where this service sends, for a caller checking it is pointed at the
  /// identity rather than at whichever core happens to be on this machine.
  String get baseUrl => _baseUrl;

  final KeyMath? keyMath;

  /// How this device makes its identity's key events.
  TheKeyEventsThisDeviceMakes get _makes =>
      TheKeyEventsThisDeviceMakes(_client, _baseUrl, _km, held: _held);

  KeyMath get _km {
    final km = keyMath;
    if (km == null) {
      throw StateError(
          'this app has not given the client the core\'s key arithmetic (KeyMath), '
          'so it cannot check an event before signing it, and signs nothing');
    }
    return km;
  }

  final _held = TheIdentityThisDeviceHolds();

  /// How this device makes the events of [aid] after reading its key state:
  /// sending each to the witnesses whose addresses it holds, and reading the
  /// key state again from the copies when the log moves under it.
  Future<TheKeyEventsThisDeviceMakes> _makesFor(Uint8List seed) async {
    final h = await _held.read();
    return TheKeyEventsThisDeviceMakes(_client, _baseUrl, _km,
        held: _held,
        witnesses: TheWitnessesOfThisDevicesEvents(
            _client, _km, KnownWitnesses(h?.witnessAddresses ?? const {})),
        readTheKeyState: (_) async => (await _readTheCopies(seed)).now,
        // The stage, from the key state as this device reads it: its own record
        // where it made the newest establishment event, otherwise what the
        // copies of the log (or, for an identity founded before the record, its
        // core) say.
        readTheKeysInForce: (_) async => (await _keyState(seed)).now);
  }

  /// The key state of this device's identity for the phrase whose BIP39 seed
  /// is [seed], read without any owner route (ADR-061 section 9): from this
  /// device's own record, or from verified copies of the log.
  ///
  /// An identity whose establishment events this device has not recorded
  /// (one founded before it kept a record) is read as it was before, from the
  /// core that holds it, with any event an earlier version left unsigned
  /// finished first; then from verified copies where they can be read. Once
  /// this device records an establishment event of its own, its record
  /// answers.
  Future<VerifiedKeyState> _keyState(Uint8List seed) async {
    final h = await _held.read();
    if (h == null || h.establishment == null) {
      final legacy = await _keys.finishStrandedEvents(seed);
      if (h == null) await _held.holds(legacy.aid);
      try {
        return await _readTheCopies(seed);
      } on TheWitnessesDoNotSay {
        return VerifiedKeyState(
            aid: legacy.aid,
            establishment: (
              sn: int.parse('${legacy.establishment['s']}', radix: 16),
              digest: '${legacy.establishment['d']}'
            ),
            keyInForce: KeyManager.publicKeyAt(seed, legacy.index),
            keysInForce: [KeyManager.publicKeyAt(seed, legacy.index)],
            generation: legacy.index,
            tip: (sn: legacy.nextSequenceNumber - 1, digest: legacy.tipDigest),
            // The witnesses and threshold the identity has, as its core
            // keeps them; the threshold travels into the next rotation, so it
            // is never set to nothing because copies could not be read.
            witnesses: WitnessSet(
                [
                  for (final w
                      in (legacy.establishment['b'] as List? ?? const []))
                    '$w'
                ],
                int.tryParse('${legacy.establishment['bt'] ?? '0'}',
                        radix: 16) ??
                    0),
            fromItsOwnRecord: false,
            corroborated: false);
      }
    }
    try {
      return await TheKeyStateThisDeviceReads(_client, _km, _baseUrl,
              held: _held)
          .read(seed);
    } on TheWitnessesDoNotSay {
      // Read again taking the core's own copy only where no witness can be
      // asked at all; otherwise the witnesses' silence stands.
      if (h.witnessAddresses.isNotEmpty) rethrow;
      return _readTheCopies(seed);
    }
  }

  /// The key state read from the copies. Where this device knows no witness
  /// address (an identity founded before it kept them), the Identity Agent's
  /// own copy is all there is to read, and the result says it is not
  /// corroborated.
  Future<VerifiedKeyState> _readTheCopies(Uint8List seed) async {
    final h = await _held.read();
    return TheKeyStateThisDeviceReads(_client, _km, _baseUrl, held: _held)
        .readTheCopies(seed,
            acceptTheCoreAlone: h == null || h.witnessAddresses.isEmpty);
  }

  /// The key state of this device's identity, refusing one whose key in
  /// force is not yet this phrase's: only step 2 of a move to it may be
  /// signed then.
  Future<VerifiedKeyState> _keyInForce(Uint8List seed) async {
    final state = await _keyState(seed);
    if (state.movingToThisPhrase) {
      throw StateError('the identity is moving to this recovery phrase and the '
          'move is not finished, so nothing but its last step is signed');
    }
    return state;
  }

  late final TheKeyInForce _keys =
      TheKeyInForce(_client, _baseUrl, asked: _asked, keyMath: keyMath);
  final _asked = TheEventsThisDeviceAskedFor();

  /// The event the core says it added, read from the bytes it returned for
  /// signing, which are what is signed.
  static Map<String, dynamic> _eventIn(String rawBytesB64) {
    try {
      final e = jsonDecode(utf8.decode(base64Decode(rawBytesB64)));
      if (e is Map<String, dynamic>) return e;
    } catch (_) {}
    throw Exception('the core returned no readable event to sign');
  }

  static bool _same(Object? a, Object? b) => jsonEncode(a) == jsonEncode(b);

  @override
  AgentEnvironment get environment => AgentEnvironment.desktop;

  @override
  Future<InceptionResult> inceptAid({
    required String name,
    required String code,
  }) async {
    // Prepared by the core, checked here against the founding this phrase
    // makes, reserved, signed and committed: the core adds nothing this
    // device did not sign (TheKeyEventsThisDeviceMakes).
    final seed = Bip39.mnemonicToSeed(code.split(' '));
    try {
      final founded = await _makes.found(seed);
      return InceptionResult(
        aid: founded.aid,
        publicKey: KeyManager.publicKeyAt(seed, 0),
        kel: '',
        created: DateTime.now().toIso8601String(),
        cesrSignature: founded.signatures.first,
        rawBytesB64: founded.bytesB64,
      );
    } finally {
      seed.fillRange(0, seed.length, 0);
    }
  }

  /// The CESR form of a raw base64 signature that is handed back rather than
  /// recorded (a payload, a credential anchor, a presentation), or an empty
  /// string where the core could not encode it.
  Future<String> _cesrEncode(String rawSigB64) async {
    try {
      return await cesrEncodeSignature(
          _client, _baseUrl, base64Decode(rawSigB64));
    } catch (_) {
      return '';
    }
  }

  /// Moves this device's identity to the phrase [words] (ADR-061 section 10),
  /// for when the phrase in force may be in somebody else's hands.
  ///
  /// Two rotations. The first reveals the old phrase's next key and commits to
  /// the new phrase's keys; the second, made with the new phrase as a recovery
  /// rotation after the first, reveals the new phrase's first key and
  /// supersedes any interaction a holder of the old phrase signed in between.
  /// The new phrase is kept beside the old one once step 1 is prepared and
  /// checked and before it is signed, so a core that refuses step 1 leaves
  /// nothing kept and the identity signs as it did; it replaces the old only
  /// once the second rotation is in the log, so a move interrupted between the
  /// two is finished by [finishMovingToANewPhrase] and never strands the
  /// identity.
  ///
  /// The new phrase's messaging keys are not anchored by the move: the
  /// identity keeps the keyset it is reached on until its keys are replaced.
  Future<RotationResult> moveToANewPhrase({required List<String> words}) async {
    final old = await SecureKeyStore.loadMnemonic();
    if (old == null)
      throw Exception('No identity keys found in secure storage.');
    if (old.join(' ') == words.join(' ')) {
      throw ArgumentError('the new phrase is the phrase in force');
    }
    final pending = await SecureKeyStore.loadPhraseMovingTo();
    if (pending != null && pending.join(' ') != words.join(' ')) {
      throw StateError('a move to another phrase is under way; it is finished '
          'first');
    }
    return _finishMove(words);
  }

  /// Finishes a move to a new phrase, from wherever it stands: step 1 not
  /// yet in the log, step 2 not yet in it, or both in and only the phrase in
  /// force left to change. Anything this device signed and its core never
  /// acknowledged is committed first. Every signing path calls this first
  /// while a move is under way, so the old phrase signs nothing else meanwhile.
  ///
  /// Where the old phrase no longer controls the identity (somebody holding
  /// it moved first, to keys of their own), the move cannot happen: the record
  /// of it is dropped and [TheOldPhraseNoLongerControlsTheIdentity] is thrown.
  Future<RotationResult> finishMovingToANewPhrase() async {
    final words = await SecureKeyStore.loadPhraseMovingTo();
    if (words == null) throw StateError('no move to a new phrase is under way');
    return _finishMove(words);
  }

  Future<RotationResult> _finishMove(List<String> words) async {
    final old = await SecureKeyStore.loadMnemonic();
    if (old == null)
      throw Exception('No identity keys found in secure storage.');
    final oldSeed = Bip39.mnemonicToSeed(old);
    final newSeed = Bip39.mnemonicToSeed(words);
    try {
      return await _finishMoveWith(oldSeed, newSeed, words);
    } finally {
      oldSeed.fillRange(0, oldSeed.length, 0);
      newSeed.fillRange(0, newSeed.length, 0);
    }
  }

  Future<RotationResult> _finishMoveWith(
      Uint8List oldSeed, Uint8List newSeed, List<String> words) async {
    await _finishSignedDuringAMove();

    VerifiedKeyState state;
    try {
      state = await _keyState(newSeed);
    } on TheKeyInForceIsNotThisPhrases {
      // Step 1 is not in the log: the old phrase's keys are in force and
      // commit to its own next key. Step 1 is made now.
      await _stepOne(oldSeed, newSeed, words);
      state = await _keyState(newSeed);
    }

    String signature = '';
    if (state.movingToThisPhrase) {
      final makes = await _makesFor(newSeed);
      final step2 = await makes.rotate(newSeed,
          aid: state.aid,
          generation: 0,
          afterSn: state.establishment.sn,
          afterDigest: state.establishment.digest,
          toad: state.witnesses.toad,
          witnessedBy: state.witnesses,
          recovery: true,
          afterStepOneOfAMove: true);
      signature = step2.signatures.first;
    }
    // The messaging keys came from the old phrase, so whoever holds it can
    // read the identity's messages: they are replaced with the new phrase's
    // first keyset before the move counts as finished, so a replacement that
    // fails leaves the move under way, and the next signing tries it again.
    await _replaceMessagingKeysWith(newSeed, generation: 0);
    if (!await SecureKeyStore.finishMovingToThePhrase(words)) {
      throw StateError('the new phrase could not be made the phrase in force; '
          'the move is in the log and both phrases are still kept');
    }
    return RotationResult(
      aid: state.aid,
      newPublicKey: KeyManager.publicKeyAt(newSeed, 1),
      kel: '',
      cesrSignature: signature,
    );
  }

  /// Step 1 of a move, made with the old phrase at the key state the copies
  /// say is in force. Where somebody else holding the old phrase rotated
  /// first, it is made once more after their rotation; where they moved the
  /// identity to keys of their own, the move is dropped.
  Future<void> _stepOne(
      Uint8List oldSeed, Uint8List newSeed, List<String> words) async {
    for (var tries = 0;; tries++) {
      final VerifiedKeyState state;
      try {
        state = await _keyInForce(oldSeed);
      } on TheKeyInForceIsNotThisPhrases {
        await SecureKeyStore.clearPhraseMovingTo();
        throw TheOldPhraseNoLongerControlsTheIdentity();
      }
      final makes = await _makesFor(oldSeed);
      try {
        await makes.moveToANewPhrase(oldSeed, newSeed,
            aid: state.aid,
            generation: state.generation,
            afterSn: state.tip.sn,
            afterDigest: state.tip.digest,
            toad: state.witnesses.toad,
            witnessedBy: state.witnesses,
            // Kept once the core has prepared step 1 and it has been checked,
            // before the old keys sign it: a step 1 the core refuses at prepare,
            // or that is not the one expected, keeps nothing and leaves the
            // identity able to sign. One refused at commit, after it was signed,
            // stops all signing until it is let go, as any signed-then-refused
            // key event does.
            beforeSigning: () async {
          if (!await SecureKeyStore.savePhraseMovingTo(words)) {
            throw StateError('the new phrase could not be kept safely, so '
                'the move did not start');
          }
        });
        return;
      } on TheKeyInForceIsNotThisPhrases {
        await SecureKeyStore.clearPhraseMovingTo();
        throw TheOldPhraseNoLongerControlsTheIdentity();
      } on TheLogKeepsMoving catch (e) {
        if (!e.rotatedElsewhere || tries > 0) rethrow;
        await _held.forgetTheTip();
      }
    }
  }

  /// Commits what this device signed and its core never acknowledged. An
  /// interaction the core refused for good is left for step 2, which
  /// supersedes it and marks it dead.
  Future<void> _finishSignedDuringAMove() async {
    final h = await _held.read();
    if (h == null) return;
    final makes = TheKeyEventsThisDeviceMakes(_client, _baseUrl, _km,
        held: _held,
        witnesses: TheWitnessesOfThisDevicesEvents(
            _client, _km, KnownWitnesses(h.witnessAddresses)));
    try {
      await makes.finishSigned(h.aid,
          witnessedBy: WitnessSet(h.witnesses, h.toad));
    } on AnEventWasRefused catch (e) {
      if (e.reservation.t != 'ixn') rethrow;
    }
  }

  /// Replaces this device's identity's messaging keys with the next
  /// generation of its phrase (ADR-061 section 8), and returns that
  /// generation: the keyset is derived on this device, the core is handed its
  /// seed and must return the same anchor, and an interaction anchors it. The
  /// earlier keys still open messages sent to them until counterparties have
  /// read the replacement.
  ///
  /// For an identity whose messaging keys are not its phrase's: founded before
  /// the fixed branch, recovered from a phrase it moved to, or moved to a new
  /// phrase. The generation after the last one the log anchors is used, or 0
  /// where the log anchors none of this phrase's.
  Future<int> replaceMessagingKeys() async {
    await _finishAnyMoveUnderWay();
    final mnemonic = await SecureKeyStore.loadMnemonic();
    if (mnemonic == null)
      throw Exception('No identity keys found in secure storage.');
    final seed = Bip39.mnemonicToSeed(mnemonic);
    try {
      return await _replaceMessagingKeysWith(seed);
    } finally {
      seed.fillRange(0, seed.length, 0);
    }
  }

  Future<int> _replaceMessagingKeysWith(Uint8List seed,
      {int? generation}) async {
    final copies = await _readTheCopies(seed);
    final anchored = [
      for (final e in copies.log?.events ?? const <LoggedEvent>[])
        ...e.messagingKeysets
    ];
    var g = generation;
    if (g == null) {
      final last = anchored.isEmpty
          ? null
          : await RecoveringThisIdentity.messagingGenerationOf(
              _km, seed, anchored.last);
      g = last == null ? 0 : last + 1;
    }

    final messagingSeed = KeyManager.slip10Ed25519(seed, KeyPaths.messaging(g));
    final Map<String, dynamic> anchor;
    try {
      anchor = await _km.messagingKeySet(messagingSeed);
      final res =
          await _client.post(Uri.parse('$_baseUrl/api/keystore/messaging-seed'),
              headers: const {'Content-Type': 'application/json'},
              body: jsonEncode({
                'seed_hex': [
                  for (final b in messagingSeed)
                    b.toRadixString(16).padLeft(2, '0')
                ].join()
              }));
      if (res.statusCode < 200 || res.statusCode > 299) {
        throw Exception('the core would not take the messaging keys '
            '(${res.statusCode}): ${res.body}');
      }
      final held = (jsonDecode(res.body) as Map)['anchor'];
      if (RecoveringThisIdentity.canonicalJson(held) !=
          RecoveringThisIdentity.canonicalJson(anchor)) {
        throw StateError('the core holds messaging keys other than the ones '
            'this phrase derives, so they are not anchored');
      }
    } finally {
      messagingSeed.fillRange(0, messagingSeed.length, 0);
    }
    // Already the keyset the log anchors last (a replacement whose answer was
    // lost, finished again): the core now holds it, and it is not anchored
    // twice.
    if (anchored.isNotEmpty &&
        RecoveringThisIdentity.canonicalJson(anchored.last) ==
            RecoveringThisIdentity.canonicalJson(anchor)) {
      return g;
    }

    var state = await _keyInForce(seed);
    final makes = await _makesFor(seed);
    if ((await makes.finishSigned(state.aid, witnessedBy: state.witnesses))
        .isNotEmpty) {
      state = await _keyInForce(seed);
    }
    await makes.interact(seed,
        aid: state.aid,
        generation: state.generation,
        afterSn: state.tip.sn,
        afterDigest: state.tip.digest,
        anchors: [anchor],
        witnessedBy: state.witnesses);
    return g;
  }

  /// Finishes a move to a new phrase under way, before anything is signed.
  Future<void> _finishAnyMoveUnderWay() async {
    if (await SecureKeyStore.loadPhraseMovingTo() != null) {
      await finishMovingToANewPhrase();
    }
  }

  @override
  Future<RotationResult> rotateAid({required String name}) async {
    await _finishAnyMoveUnderWay();
    final mnemonic = await SecureKeyStore.loadMnemonic();
    if (mnemonic == null) {
      throw Exception('No identity keys found in secure storage.');
    }
    final seed = Bip39.mnemonicToSeed(mnemonic);
    try {
      // The keys are this app's identity's, so only it can be rotated with them.
      var state = await _keyInForce(seed);
      final aid = state.aid;
      if (name != aid) {
        throw ArgumentError.value(name, 'name',
            'the identity held here is $aid, and only it can be rotated with this phrase');
      }
      final makes = await _makesFor(seed);
      // What this device signed and the core never acknowledged goes first, so
      // this rotation builds on a log that verifies.
      if ((await makes.finishSigned(aid, witnessedBy: state.witnesses))
          .isNotEmpty) {
        state = await _keyInForce(seed);
      }
      // The rotation reveals the key the last establishment event committed to
      // (generation n + 1), signs with it, and commits to n + 2; the witness
      // threshold stays as it is.
      final rotated = await makes.rotate(seed,
          aid: aid,
          generation: state.generation,
          afterSn: state.tip.sn,
          afterDigest: state.tip.digest,
          toad: state.witnesses.toad,
          witnessedBy: state.witnesses);
      return RotationResult(
        aid: aid,
        newPublicKey: KeyManager.publicKeyAt(seed, state.generation + 1),
        kel: '',
        cesrSignature: rotated.signatures.first,
      );
    } finally {
      seed.fillRange(0, seed.length, 0);
    }
  }

  @override
  Future<InteractResult> interactAid({
    required String name,
    List<Map<String, String>> sealData = const [],
  }) async {
    await _finishAnyMoveUnderWay();
    final mnemonic = await SecureKeyStore.loadMnemonic();
    if (mnemonic == null) {
      throw Exception('No identity keys found in secure storage.');
    }
    final seed = Bip39.mnemonicToSeed(mnemonic);
    try {
      var state = await _keyInForce(seed);
      final makes = await _makesFor(seed);
      if ((await makes.finishSigned(state.aid, witnessedBy: state.witnesses))
          .isNotEmpty) {
        state = await _keyInForce(seed);
      }
      final done = await makes.interact(seed,
          aid: state.aid,
          generation: state.generation,
          afterSn: state.tip.sn,
          afterDigest: state.tip.digest,
          anchors: sealData,
          witnessedBy: state.witnesses);
      return InteractResult(
        aid: done.aid,
        said: done.digest,
        sequenceNumber: done.sn,
        cesrSignature: done.signatures.first,
      );
    } finally {
      seed.fillRange(0, seed.length, 0);
    }
  }

  @override
  Future<SignatureResult> signPayload({
    required String name,
    required List<int> data,
  }) async {
    // Signing is performed locally in Dart using the stored mnemonic.
    // The private key never leaves the device and is never sent to the backend.
    await _finishAnyMoveUnderWay();
    final mnemonic = await SecureKeyStore.loadMnemonic();
    if (mnemonic == null) {
      throw Exception('No identity keys found in secure storage. '
          'Please recreate your identity to restore signing capability.');
    }

    final seed = Bip39.mnemonicToSeed(mnemonic);
    final String publicKey;
    final List<int> rawSig;
    try {
      // The key reported is the key that signed, and it is the key the
      // identity's log says is in force: after a rotation that is no longer
      // the founding key, and a signature by the founding key verifies against
      // nothing a counterparty would look up.
      final index = (await _keyInForce(seed)).generation;
      publicKey = KeyManager.publicKeyAt(seed, index);
      final child = KeyManager.signingSeed(seed, index: index);
      final privateKey = ed.newKeyFromSeed(child);
      try {
        rawSig = ed.sign(privateKey, Uint8List.fromList(data));
      } finally {
        child.fillRange(0, child.length, 0);
        privateKey.bytes.fillRange(0, privateKey.bytes.length, 0);
      }
    } finally {
      seed.fillRange(0, seed.length, 0);
    }
    final rawSigB64 = base64Encode(rawSig);

    // CESR-encode the signature via the stateless Python driver endpoint.
    final cesrSig = await _cesrEncode(rawSigB64);

    return SignatureResult(
      signature: rawSigB64,
      publicKey: publicKey,
      cesrSignature: cesrSig,
    );
  }

  /// The private key in force (TheKeyInForce), with any event left unsigned
  /// finished first. Throws where this device holds no recovery phrase: an
  /// event the core builds would otherwise be added and never signed.
  Future<({ed.PrivateKey key, KeyState state})> _signerInForce() async {
    await _finishAnyMoveUnderWay();
    final mnemonic = await SecureKeyStore.loadMnemonic();
    if (mnemonic == null) {
      throw Exception('No identity keys found in secure storage.');
    }
    final seed = Bip39.mnemonicToSeed(mnemonic);
    try {
      final state = await _keys.finishStrandedEvents(seed);
      final child = KeyManager.signingSeed(seed, index: state.index);
      try {
        return (key: ed.newKeyFromSeed(child), state: state);
      } finally {
        child.fillRange(0, child.length, 0);
      }
    } finally {
      seed.fillRange(0, seed.length, 0);
    }
  }

  /// The key event log of the identity held under [name], as the core serves
  /// it: the parsed events and the bytes each was published as. The core
  /// answers with a list of events, not text; this once returned that list as
  /// a String and failed at runtime for every caller.
  @override
  Future<KeyEventLog> getCurrentKel({required String name}) =>
      _keys.keyLog(name);

  @override
  Future<bool> verifySignature({
    required List<int> data,
    required String signature,
    required String publicKey,
  }) async {
    final response = await _client.post(
      Uri.parse('$_baseUrl/api/verify'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'data': base64Encode(data),
        'signature': signature,
        'public_key': publicKey,
      }),
    );

    if (response.statusCode == 200) {
      final json = jsonDecode(response.body);
      return json['valid'] == true;
    } else {
      return false;
    }
  }

  @override
  Future<CredentialIssuanceResult> issueCredential({
    required Map<String, dynamic> claims,
    required String schemaSaid,
    String holderAid = '',
    String name = '',
  }) async {
    // The key is worked out before the event exists, so a key log this phrase
    // cannot sign for is refused before anything is added to it.
    final signer = await _signerInForce();
    final aid = signer.state.aid;
    // Written down before it is asked for. The anchor is built by the core, so
    // nothing about it is known yet: this entry is only ever recognised by the
    // sequence number and digest of the answer.
    final request = await _asked.asking(
        t: 'ixn', aid: aid, expectedSn: signer.state.nextSequenceNumber);

    final Map<String, dynamic> json;
    final String ixnRawBytesB64;
    // Step 1: Ask the Go backend to format the ACDC and create the IXN anchor.
    // A request that fails in transit is NOT forgotten: the core may have
    // added the event, and the entry, bounded by its sequence number, lets it
    // be finished later. Only a refusal or a failed check forgets it.
    final response = await _client.post(
      Uri.parse('$_baseUrl/api/credential/issue'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'claims': claims,
        'schema_said': schemaSaid,
        'holder_aid': holderAid,
      }),
    );
    try {
      if (response.statusCode != 201 && response.statusCode != 200) {
        refusedByTheCore(response, 'Credential issuance failed');
      }
      json = jsonDecode(response.body) as Map<String, dynamic>;
      ixnRawBytesB64 = json['ixn_raw_bytes_b64'] as String? ?? '';

      // The interaction must be this identity's, at the next sequence number,
      // anchoring exactly the credential the core says it issued: one seal,
      // {"i": the credential's identifier, "s": "0", "d": the same}, which is
      // what the core anchors for a credential issued without a registry.
      //
      // THE LIMIT. That the identifier is the digest of the credential returned
      // is the core's computation and is not repeated here (this package does
      // not compute KERI digests), so a core could anchor a credential other
      // than the one it shows. What it cannot do is anchor anything else.
      final acdcSaid = json['acdc_said'] as String? ?? '';
      final anchor = _eventIn(ixnRawBytesB64);
      if (anchor['t'] != 'ixn' ||
          anchor['i'] != aid ||
          anchor['s'] != signer.state.nextSequenceNumber.toRadixString(16) ||
          acdcSaid.isEmpty ||
          !_same(anchor['a'], [
            {'i': acdcSaid, 's': '0', 'd': acdcSaid}
          ])) {
        throw Exception(
            'the core returned an event that is not the anchor of the credential it issued, '
            'so it is not signed');
      }
      await _asked.added(request,
          aid: aid,
          sequenceNumber: signer.state.nextSequenceNumber,
          digest: '${anchor['d']}');
    } catch (_) {
      await _asked.forget(request);
      rethrow;
    }

    // Step 2: Sign the IXN event bytes locally with the key in force.
    // Private key never leaves this device (ADR-014). The core signs this
    // anchor itself where it holds the key; this signature is handed back.
    final List<int> rawSig;
    try {
      rawSig =
          ed.sign(signer.key, Uint8List.fromList(base64Decode(ixnRawBytesB64)));
    } finally {
      signer.key.bytes.fillRange(0, signer.key.bytes.length, 0);
    }
    final cesrSig = await _cesrEncode(base64Encode(rawSig));

    return CredentialIssuanceResult(
      acdcSaid: json['acdc_said'] ?? '',
      acdcJsonB64: json['acdc_json_b64'] ?? '',
      ixnRawBytesB64: ixnRawBytesB64,
      ixnSaid: json['ixn_said'] ?? '',
      sequenceNumber: json['sequence_number'] as int? ?? 0,
      cesrSignature: cesrSig,
    );
  }

  @override
  Future<PresentationResult> presentCredential({
    required String acdcSaid,
    required String holderAid,
    String issuerAid = '',
    String schemaSaid = '',
  }) async {
    final signer = await _signerInForce();

    // Step 1: Ask the Go backend to build the presentation and compute its SAID.
    final response = await _client.post(
      Uri.parse('$_baseUrl/api/credential/present'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'acdc_said': acdcSaid,
        'holder_aid': holderAid,
        'issuer_aid': issuerAid,
        'schema_said': schemaSaid,
      }),
    );

    if (response.statusCode != 201 && response.statusCode != 200) {
      final body = jsonDecode(response.body);
      throw Exception(
          body['error'] ?? 'Presentation failed: ${response.statusCode}');
    }

    final json = jsonDecode(response.body);
    final presSaidB64 = json['pres_said_b64'] as String? ?? '';

    // Step 2: Sign the presentation SAID bytes locally with the holder's key in
    // force. This proves possession of the key bound to the holder AID.
    // The holder signs pres_said.encode() — the UTF-8 bytes of the 44-char SAID.
    // Private key never leaves this device (ADR-014).
    String cesrSig = '';
    try {
      if (presSaidB64.isNotEmpty) {
        final saidBytes = base64Decode(presSaidB64);
        final rawSig = ed.sign(signer.key, Uint8List.fromList(saidBytes));
        cesrSig = await _cesrEncode(base64Encode(rawSig));
      }
    } finally {
      signer.key.bytes.fillRange(0, signer.key.bytes.length, 0);
    }

    return PresentationResult(
      presentationSaid: json['presentation_said'] ?? '',
      presentationJsonB64: json['presentation_json_b64'] ?? '',
      cesrSignature: cesrSig,
    );
  }

  @override
  Future<WitnessReceiptResult> submitWitnessReceipt({
    required String eventSaid,
    required String witnessAid,
    required String cesrSignature,
  }) async {
    final response = await _client.post(
      Uri.parse('$_baseUrl/api/receipt/submit'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'event_said': eventSaid,
        'witness_aid': witnessAid,
        'cesr_signature': cesrSignature,
      }),
    );

    if (response.statusCode == 200) {
      final json = jsonDecode(response.body);
      return WitnessReceiptResult(
        accepted: json['accepted'] == true,
        thresholdMet: json['threshold_met'] == true,
        receiptCount: json['receipt_count'] as int? ?? 0,
        errors: List<String>.from(json['errors'] ?? []),
      );
    } else {
      final body = jsonDecode(response.body);
      throw Exception(
          body['error'] ?? 'Receipt submission failed: ${response.statusCode}');
    }
  }

  @override
  Future<KerlEntry> getKERL({
    required String eventSaid,
    int threshold = 0,
  }) async {
    final response = await _client.get(
      Uri.parse(
          '$_baseUrl/api/kerl?event_said=$eventSaid&threshold=$threshold'),
    );

    if (response.statusCode == 200) {
      final json = jsonDecode(response.body);
      return KerlEntry(
        eventSaid: json['event_said'] ?? '',
        receipts: List<Map<String, dynamic>>.from(
          (json['receipts'] as List? ?? [])
              .map((r) => Map<String, dynamic>.from(r)),
        ),
        receiptCount: json['receipt_count'] as int? ?? 0,
        thresholdMet: json['threshold_met'] == true,
      );
    } else {
      throw Exception('Failed to get KERL: ${response.statusCode}');
    }
  }

  @override
  Future<VerificationResult> verifyCredential({
    required String acdcJson,
    String holderAid = '',
    String presentationSaid = '',
    String cesrSignature = '',
    String holderPublicKey = '',
    List<String> trustedSchemaSaids = const [],
  }) async {
    final response = await _client.post(
      Uri.parse('$_baseUrl/api/credential/verify'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'acdc_json': acdcJson,
        'holder_aid': holderAid,
        'presentation_said': presentationSaid,
        'cesr_signature': cesrSignature,
        'holder_public_key': holderPublicKey,
        'trusted_schema_saids': trustedSchemaSaids,
      }),
    );

    if (response.statusCode == 200) {
      final json = jsonDecode(response.body);
      return VerificationResult(
        verified: json['verified'] == true,
        checks: (json['checks'] as Map<String, dynamic>?) ?? {},
        errors: List<String>.from(json['errors'] ?? []),
        acdcSaid: json['acdc_said'] ?? '',
      );
    } else {
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ??
          'Credential verification failed: ${response.statusCode}');
    }
  }

  @override
  void dispose() {
    _client.close();
  }
}

/// The name this class had when it was only used on desktop.
@Deprecated('Use LocalCoreKeriService — it serves mobile too')
typedef DesktopOnDeviceKeriService = LocalCoreKeriService;

/// A move to a new phrase cannot happen: the old phrase no longer controls
/// the identity, because somebody else holding it moved the identity to keys
/// of their own first. The identity is theirs now; the move is dropped.
class TheOldPhraseNoLongerControlsTheIdentity implements Exception {
  @override
  String toString() => 'somebody else holding the old recovery phrase moved '
      'the identity to keys of their own before this move, so it is no longer '
      'controlled by that phrase and cannot be moved';
}
