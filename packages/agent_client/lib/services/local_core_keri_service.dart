import 'dart:convert';
import 'dart:typed_data';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:http/http.dart' as http;
import '../crypto/bip39.dart';
import '../crypto/keys.dart';
import 'keri_service.dart';
import 'secure_key_store.dart';
import 'signing_an_event.dart';
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

  LocalCoreKeriService({String? baseUrl, http.Client? client})
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

  late final TheKeyInForce _keys = TheKeyInForce(_client, _baseUrl);

  @override
  AgentEnvironment get environment => AgentEnvironment.desktop;

  @override
  Future<InceptionResult> inceptAid({
    required String name,
    required String code,
  }) async {
    final mnemonic = code.split(' ');
    final keys = KeyManager.generateKeysFromMnemonic(mnemonic);

    // Step 1: Create the inception event on the Python driver via Go backend.
    final response = await _client.post(
      Uri.parse('$_baseUrl/api/inception'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'public_key': keys.signing.publicKeyEncoded,
        'next_public_key': keys.next.publicKeyEncoded,
      }),
    );

    if (response.statusCode != 201 && response.statusCode != 200) {
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'Inception failed: ${response.statusCode}');
    }

    final json = jsonDecode(response.body);
    final rawBytesB64 = json['raw_bytes_b64'] as String? ?? '';

    // Step 2: Sign the inception event bytes locally with the Ed25519 key,
    // have the core CESR-encode the signature, and record it against the
    // event. Private key never leaves this device (ADR-014).
    //
    // RECORDING IT IS THE STEP EVERY CALLER ONCE HAD TO REMEMBER.
    //
    // The route that records this has existed since August and is correct.
    // What was missing is that nothing here called it: each screen was
    // expected to, and the applications people actually ran did not — so
    // every identity they founded published a key history in which nothing
    // had been authorised by anybody. A counterparty
    // checking properly refuses such a log, so the identity works alone and
    // can convince nobody, and nothing said so at any point.
    //
    // It belongs here rather than in a screen for exactly that reason: this
    // is the one place that knows the signature was made, and a step every
    // caller must remember is a step somebody will not.
    //
    // It cannot be sent with the inception itself — the signature is over
    // bytes the engine has not produced when that call is made — so founding
    // is two steps, and this is the second.
    final cesrSignature = await signAndRecordEvent(_client, _baseUrl,
        aid: json['aid'] as String? ?? '',
        sequenceNumber: 0,
        rawBytesB64: rawBytesB64,
        signingSeed: KeyManager.signingSeed(Bip39.mnemonicToSeed(mnemonic)),
        what: 'the founding of this identity');

    return InceptionResult(
      aid: json['aid'] ?? '',
      publicKey: json['public_key'] ?? '',
      kel: json['kel'] ?? '',
      created: json['created'] ?? DateTime.now().toIso8601String(),
      cesrSignature: cesrSignature,
      rawBytesB64: rawBytesB64,
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

    // The new key is the one the last establishment event committed to, and it
    // signs the rotation; the rotation commits to the key after it. With the
    // key in force at index n, that is n + 1 and n + 2: 1 and 2 at the first
    // rotation, 2 and 3 at the second. Both come from KeyManager.signingSeed
    // and nothing hashes them again: a second hash here once made the named
    // key neither the committed one nor the signer.
    final seed = Bip39.mnemonicToSeed(mnemonic);
    // The keys are this app's identity's, so only it can be rotated with them.
    final aid = await _keys.ownIdentifier();
    if (name != aid) {
      throw ArgumentError.value(name, 'name',
          'the identity held here is $aid, and only it can be rotated with this phrase');
    }
    // An earlier event left unsigned is finished first, so this rotation does
    // not build on one nobody can verify.
    await _keys.finishStrandedEvents(seed);
    final current = await _keys.index(seed);
    final rot1Seed = KeyManager.signingSeed(seed, index: current + 1);
    final rot1Keys = KeyManager.keyAt(seed, current + 1);
    final rot2Keys = KeyManager.keyAt(seed, current + 2);

    // Step 1: Ask the Python driver to create the rotation event.
    final response = await _client.post(
      Uri.parse('$_baseUrl/api/rotation'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'name': name,
        'new_public_key': rot1Keys.publicKeyEncoded,
        'new_next_public_key': rot2Keys.publicKeyEncoded,
      }),
    );

    if (response.statusCode != 200) {
      refusedByTheCore(response, 'Rotation failed');
    }

    final json = jsonDecode(response.body);
    final rawBytesB64 = json['raw_bytes_b64'] as String? ?? '';

    // Step 2: Sign with the key being rotated to and record the signature
    // against the event, as founding does. The core does not sign a rotation
    // itself, so a rotation whose signature is only handed back stays
    // unsigned in the log and every counterparty that checks refuses the
    // identity from then on.
    final cesrSig = await signAndRecordEvent(_client, _baseUrl,
        aid: json['aid'] as String? ?? '',
        sequenceNumber: json['sequence_number'],
        rawBytesB64: rawBytesB64,
        signingSeed: rot1Seed,
        what: 'this rotation');

    return RotationResult(
      aid: json['aid'] ?? '',
      newPublicKey: json['new_public_key'] ?? '',
      kel: json['kel'] ?? '',
      cesrSignature: cesrSig,
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
    // The key is worked out before the event exists, so a key log this phrase
    // cannot sign for is refused before anything is added to it.
    final seed = Bip39.mnemonicToSeed(mnemonic);
    await _keys.finishStrandedEvents(seed);
    final signingSeed = KeyManager.signingSeed(seed, index: await _keys.index(seed));

    // Step 1: Create the IXN event via the Python driver.
    final response = await _client.post(
      Uri.parse('$_baseUrl/api/interact'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'name': name, 'data': sealData}),
    );

    if (response.statusCode != 201 && response.statusCode != 200) {
      refusedByTheCore(response, 'IXN failed');
    }

    final json = jsonDecode(response.body);
    final rawBytesB64 = json['raw_bytes_b64'] as String? ?? '';

    // Step 2: Sign the IXN event with the key in force and record the
    // signature against it.
    final cesrSig = await signAndRecordEvent(_client, _baseUrl,
        aid: json['aid'] as String? ?? '',
        sequenceNumber: json['sequence_number'],
        rawBytesB64: rawBytesB64,
        signingSeed: signingSeed,
        what: 'this interaction');

    return InteractResult(
      aid: json['aid'] ?? '',
      said: json['said'] ?? '',
      sequenceNumber: json['sequence_number'] as int? ?? 0,
      cesrSignature: cesrSig,
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
    await _keys.finishStrandedEvents(seed);
    final index = await _keys.index(seed);
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
  Future<ed.PrivateKey> _signerInForce() async {
    final mnemonic = await SecureKeyStore.loadMnemonic();
    if (mnemonic == null) {
      throw Exception('No identity keys found in secure storage.');
    }
    final seed = Bip39.mnemonicToSeed(mnemonic);
    await _keys.finishStrandedEvents(seed);
    return ed.newKeyFromSeed(KeyManager.signingSeed(seed, index: await _keys.index(seed)));
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

    // Step 1: Ask the Go backend to format the ACDC and create the IXN anchor.
    final response = await _client.post(
      Uri.parse('$_baseUrl/api/credential/issue'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'claims': claims,
        'schema_said': schemaSaid,
        'holder_aid': holderAid,
      }),
    );

    if (response.statusCode != 201 && response.statusCode != 200) {
      refusedByTheCore(response, 'Credential issuance failed');
    }

    final json = jsonDecode(response.body);
    final ixnRawBytesB64 = json['ixn_raw_bytes_b64'] as String? ?? '';

    // Step 2: Sign the IXN event bytes locally with the key in force.
    // Private key never leaves this device (ADR-014).
    String cesrSig = '';
    if (ixnRawBytesB64.isNotEmpty) {
      final rawEventBytes = base64Decode(ixnRawBytesB64);
      final rawSig = ed.sign(signer, Uint8List.fromList(rawEventBytes));
      cesrSig = await _cesrEncode(base64Encode(rawSig));
    }

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
      final rawSig = ed.sign(signer, Uint8List.fromList(saidBytes));
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
