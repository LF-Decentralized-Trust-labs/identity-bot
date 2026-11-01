import 'dart:convert';
import 'dart:typed_data';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:http/http.dart' as http;
import '../crypto/bip39.dart';
import '../crypto/keys.dart';
import 'key_math.dart';
import 'keri_service.dart';
import 'secure_key_store.dart';
import 'signing_an_event.dart';
import 'the_events_this_device_asked_for.dart';
import 'the_key_events_this_device_makes.dart';
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

  /// [theCoreWasGivenThisPhrase] must be true ONLY when this same core — the
  /// one at this base URL — accepted this phrase's seed in a
  /// RootSeedHandoff.register call that returned true, before founding. It
  /// lets the founding carry the core's post-quantum commitment and messaging
  /// keys (TheKeyInForce.requireTheFoundingIsThisDevices), which the core adds
  /// only for keys it derives from the seed it holds. Set any other way — for a
  /// different core, a handoff that failed or was never made — it lets a core
  /// put a post-quantum key of its own into this identity, which alone could
  /// rotate it.
  ///
  /// [keyMath] is how this app runs the core's key arithmetic (a phone's
  /// bridge, or the core binary on a desktop). Founding, rotating and
  /// interacting need it; without it they refuse rather than fall back.
  LocalCoreKeriService(
      {String? baseUrl, http.Client? client, this.theCoreWasGivenThisPhrase = false, this.keyMath})
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

  final bool theCoreWasGivenThisPhrase;
  final KeyMath? keyMath;

  /// How this device makes its identity's key events.
  TheKeyEventsThisDeviceMakes get _makes {
    final km = keyMath;
    if (km == null) {
      throw StateError('this app has not given the client the core\'s key arithmetic (KeyMath), '
          'so it cannot check an event before signing it, and signs nothing');
    }
    return TheKeyEventsThisDeviceMakes(_client, _baseUrl, km);
  }

  late final TheKeyInForce _keys =
      TheKeyInForce(_client, _baseUrl, asked: _asked, theCoreWasGivenThisPhrase: theCoreWasGivenThisPhrase);
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
    final founded = await _makes.found(seed);
    return InceptionResult(
      aid: founded.aid,
      publicKey: KeyManager.keyAt(seed, 0).publicKeyEncoded,
      kel: '',
      created: DateTime.now().toIso8601String(),
      cesrSignature: founded.signatures.first,
      rawBytesB64: founded.bytesB64,
    );
  }

  /// The CESR form of a raw base64 signature that is handed back rather than
  /// recorded (a payload, a credential anchor, a presentation), or an empty
  /// string where the core could not encode it.
  Future<String> _cesrEncode(String rawSigB64) async {
    try {
      return await cesrEncodeSignature(_client, _baseUrl, base64Decode(rawSigB64));
    } catch (_) {
      return '';
    }
  }

  @override
  Future<RotationResult> rotateAid({required String name}) async {
    final mnemonic = await SecureKeyStore.loadMnemonic();
    if (mnemonic == null) {
      throw Exception('No identity keys found in secure storage.');
    }
    final seed = Bip39.mnemonicToSeed(mnemonic);
    // The keys are this app's identity's, so only it can be rotated with them.
    final aid = await _keys.ownIdentifier();
    if (name != aid) {
      throw ArgumentError.value(name, 'name',
          'the identity held here is $aid, and only it can be rotated with this phrase');
    }
    final makes = _makes;
    // What this device signed and the core never acknowledged goes first, and
    // an event an earlier version left unsigned is finished, so this rotation
    // builds on a log that verifies.
    await makes.finishSigned(aid);
    final state = await _keys.finishStrandedEvents(seed);
    // The rotation reveals the key the last establishment event committed to
    // (generation n + 1), signs with it, and commits to n + 2; the witness
    // threshold stays as it is.
    final rotated = await makes.rotate(seed,
        aid: aid,
        generation: state.index,
        afterSn: state.nextSequenceNumber - 1,
        afterDigest: state.tipDigest,
        toad: int.tryParse('${state.establishment['bt'] ?? '0'}', radix: 16) ?? 0);
    return RotationResult(
      aid: aid,
      newPublicKey: KeyManager.keyAt(seed, state.index + 1).publicKeyEncoded,
      kel: '',
      cesrSignature: rotated.signatures.first,
    );
  }


  @override
  Future<InteractResult> interactAid({
    required String name,
    List<Map<String, String>> sealData = const [],
  }) async {
    final mnemonic = await SecureKeyStore.loadMnemonic();
    if (mnemonic == null) {
      throw Exception('No identity keys found in secure storage.');
    }
    final seed = Bip39.mnemonicToSeed(mnemonic);
    final makes = _makes;
    final aid = await _keys.ownIdentifier();
    await makes.finishSigned(aid);
    final state = await _keys.finishStrandedEvents(seed);
    final done = await makes.interact(seed,
        aid: state.aid,
        generation: state.index,
        afterSn: state.nextSequenceNumber - 1,
        afterDigest: state.tipDigest,
        anchors: sealData);
    return InteractResult(
      aid: done.aid,
      said: done.digest,
      sequenceNumber: done.sn,
      cesrSignature: done.signatures.first,
    );
  }


  @override
  Future<SignatureResult> signPayload({
    required String name,
    required List<int> data,
  }) async {
    // Signing is performed locally in Dart using the stored mnemonic.
    // The private key never leaves the device and is never sent to the backend.
    final mnemonic = await SecureKeyStore.loadMnemonic();
    if (mnemonic == null) {
      throw Exception(
          'No identity keys found in secure storage. '
          'Please recreate your identity to restore signing capability.');
    }

    final seed = Bip39.mnemonicToSeed(mnemonic);
    // The key reported is the key that signed, and it is the key the identity's
    // log says is in force: after a rotation that is no longer the founding
    // key, and a signature by the founding key verifies against nothing a
    // counterparty would look up.
    final index = (await _keys.finishStrandedEvents(seed)).index;
    final signingKeyPair = KeyManager.keyAt(seed, index);
    final privateKey = ed.newKeyFromSeed(KeyManager.signingSeed(seed, index: index));

    final rawSig = ed.sign(privateKey, Uint8List.fromList(data));
    final rawSigB64 = base64Encode(rawSig);

    // CESR-encode the signature via the stateless Python driver endpoint.
    final cesrSig = await _cesrEncode(rawSigB64);

    return SignatureResult(
      signature: rawSigB64,
      publicKey: signingKeyPair.publicKeyEncoded,
      cesrSignature: cesrSig,
    );
  }

  /// The private key in force (TheKeyInForce), with any event left unsigned
  /// finished first. Throws where this device holds no recovery phrase: an
  /// event the core builds would otherwise be added and never signed.
  Future<({ed.PrivateKey key, KeyState state})> _signerInForce() async {
    final mnemonic = await SecureKeyStore.loadMnemonic();
    if (mnemonic == null) {
      throw Exception('No identity keys found in secure storage.');
    }
    final seed = Bip39.mnemonicToSeed(mnemonic);
    final state = await _keys.finishStrandedEvents(seed);
    return (key: ed.newKeyFromSeed(KeyManager.signingSeed(seed, index: state.index)), state: state);
  }


  /// The key event log of the identity held under [name], as the core serves
  /// it: the parsed events and the bytes each was published as. The core
  /// answers with a list of events, not text; this once returned that list as
  /// a String and failed at runtime for every caller.
  @override
  Future<KeyEventLog> getCurrentKel({required String name}) => _keys.keyLog(name);

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
    final request = await _asked.asking(t: 'ixn', aid: aid, expectedSn: signer.state.nextSequenceNumber);

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
        throw Exception('the core returned an event that is not the anchor of the credential it issued, '
            'so it is not signed');
      }
      await _asked.added(request,
          aid: aid, sequenceNumber: signer.state.nextSequenceNumber, digest: '${anchor['d']}');
    } catch (_) {
      await _asked.forget(request);
      rethrow;
    }

    // Step 2: Sign the IXN event bytes locally with the key in force.
    // Private key never leaves this device (ADR-014). The core signs this
    // anchor itself where it holds the key; this signature is handed back.
    final rawSig = ed.sign(signer.key, Uint8List.fromList(base64Decode(ixnRawBytesB64)));
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
      throw Exception(body['error'] ?? 'Presentation failed: ${response.statusCode}');
    }

    final json = jsonDecode(response.body);
    final presSaidB64 = json['pres_said_b64'] as String? ?? '';

    // Step 2: Sign the presentation SAID bytes locally with the holder's key in
    // force. This proves possession of the key bound to the holder AID.
    // The holder signs pres_said.encode() — the UTF-8 bytes of the 44-char SAID.
    // Private key never leaves this device (ADR-014).
    String cesrSig = '';
    if (presSaidB64.isNotEmpty) {
      final saidBytes = base64Decode(presSaidB64);
      final rawSig = ed.sign(signer.key, Uint8List.fromList(saidBytes));
      cesrSig = await _cesrEncode(base64Encode(rawSig));
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
      throw Exception(body['error'] ?? 'Receipt submission failed: ${response.statusCode}');
    }
  }

  @override
  Future<KerlEntry> getKERL({
    required String eventSaid,
    int threshold = 0,
  }) async {
    final response = await _client.get(
      Uri.parse('$_baseUrl/api/kerl?event_said=$eventSaid&threshold=$threshold'),
    );

    if (response.statusCode == 200) {
      final json = jsonDecode(response.body);
      return KerlEntry(
        eventSaid: json['event_said'] ?? '',
        receipts: List<Map<String, dynamic>>.from(
          (json['receipts'] as List? ?? []).map((r) => Map<String, dynamic>.from(r)),
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
      throw Exception(body['error'] ?? 'Credential verification failed: ${response.statusCode}');
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
