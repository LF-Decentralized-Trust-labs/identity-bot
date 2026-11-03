import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import '../crypto/keys.dart';
import '../crypto/owner_signature.dart';
import 'the_identity_this_device_holds.dart';
import 'the_key_state_this_device_reads.dart';
import 'the_path_a_signature_covers.dart';
import 'the_owner_at_this_computer.dart';

/// Signing every request to your own agent, without having to remember to.
///
/// An agent running on hardware you rent cannot tell who you are from the
/// connection: you are remote by definition, so "this request came from the
/// machine the agent runs on" is never true for the person who owns it. Every
/// owner endpoint therefore answers `sign this request with the owner key`, and
/// until something does, a hosted agent is correctly locked and completely
/// unusable by the person who owns it.
///
/// The signing itself already existed. What did not was anything calling it —
/// so this sits at the transport instead of at eighty-one call sites. A request
/// added tomorrow is signed without anybody remembering to sign it, which is
/// the only version of this that stays true.
///
/// IT SIGNS ONLY REQUESTS TO YOUR OWN AGENT, and that restraint is the whole
/// reason this is a wrapper rather than a header added in one helper. The same
/// client resolves other people's discovery records and talks to relays and
/// witnesses. Attaching an owner signature to those would hand your identifier
/// to every stranger you look up — the opposite of what a per-relationship
/// identifier is for.
///
/// Given [ownerKey], every request also names the establishment event its key
/// was put in force by (`X-IA-Owner-Key-State`, ADR-061 section 9). An agent
/// whose log has moved past it answers `401 stale_key_state`; the client then
/// calls [onStaleKeyState], reads the key again and sends the request once
/// more, signed with the key that reading gives. It never guesses a key.
class OwnerSigningClient extends http.BaseClient {
  OwnerSigningClient({
    required this.agentOrigin,
    Future<Uint8List?> Function()? ownerSeed,
    this.ownerKey,
    this.onStaleKeyState,
    this.ownerAid,
    this.agentAid = '',
    http.Client? inner,
  })  : ownerSeed = ownerSeed ?? (() async => null),
        _inner = ProvingThisComputer.over(inner),
        _ownsInner = inner == null;

  /// The header naming the establishment event a request was signed under:
  /// its sequence number, as KERI writes it, a dot, and its digest.
  static const keyStateHeader = 'X-IA-Owner-Key-State';

  /// Reads the owner's key in force: the signing seed and the establishment
  /// event that put it in force. Preferred to [ownerSeed] where given; null
  /// means not available, as there.
  final Future<OwnerKey?> Function()? ownerKey;

  /// Called when the agent says the key state a request named is stale,
  /// before the key is read again: the device forgets where it believed its
  /// log ends, so the reading that follows asks the witnesses.
  final Future<void> Function()? onStaleKeyState;

  /// The origin of the agent this client owns, as scheme://host:port. Requests
  /// anywhere else are passed through untouched.
  final String agentOrigin;

  /// Reads the owner's signing seed. Async and called per request rather than
  /// held, because the seed lives in secure storage and a copy kept in memory
  /// for the lifetime of a process is a copy that can be read out of it.
  ///
  /// Returning null means "not available" — a locked device, an identity not
  /// yet created — and the request goes unsigned rather than failing. The agent
  /// will refuse it, which is the correct outcome and a clearer one than an
  /// exception from the transport.
  final Future<Uint8List?> Function() ownerSeed;

  /// The owner's identifier, when known. Optional: the agent already knows
  /// which key it accepts, so this only lets it say "that is a different
  /// identity" instead of "that signature does not verify".
  final String? ownerAid;

  /// The identifier of the Identity Agent at [agentOrigin], signed into every
  /// request so no other Identity Agent the same key administers accepts a
  /// copy. Empty names nobody, which only an Identity Agent with no identity
  /// yet accepts.
  final String agentAid;

  final http.Client _inner;

  /// Whether this wrapper created [_inner] and so may close it. A borrowed inner
  /// belongs to the caller; closing it would break a transport still in use.
  final bool _ownsInner;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    if (!_isOwnAgent(request.url)) {
      return _inner.send(request);
    }

    // Only a plain Request can be signed, because the body has to be read to
    // digest it and a stream can only be read once. Streamed uploads are passed
    // through rather than silently half-consumed; the agent refuses them, which
    // is a better failure than a request that arrives truncated.
    if (request is! http.Request) {
      return _inner.send(request);
    }

    final first = await _signAndSend(request);
    if (first == null) return _inner.send(request);
    final stale = onStaleKeyState;
    if (ownerKey == null || stale == null || first.statusCode != 401) {
      return first;
    }
    final body = await first.stream.toBytes();
    if (!_saysStale(body)) {
      return http.StreamedResponse(Stream.value(body), first.statusCode,
          headers: first.headers,
          reasonPhrase: first.reasonPhrase,
          request: first.request);
    }
    // The agent's log has moved past the key this device signed with. The
    // device reads its key state again, and the request goes once more under
    // whatever that reading gives.
    await stale();
    return await _signAndSend(request) ??
        http.StreamedResponse(Stream.value(body), first.statusCode,
            headers: first.headers, request: first.request);
  }

  static bool _saysStale(List<int> body) {
    try {
      final j = jsonDecode(utf8.decode(body));
      return j is Map && j['error'] == 'stale_key_state';
    } catch (_) {
      return false;
    }
  }

  /// Signs [request] with the owner's key and sends it; null where no key is
  /// available.
  Future<http.StreamedResponse?> _signAndSend(http.Request request) async {
    final read = ownerKey;
    Uint8List? seed;
    Place? place;
    if (read != null) {
      final key = await read();
      seed = key?.seed;
      place = key?.establishment;
    } else {
      seed = await ownerSeed();
    }
    if (seed == null) return null;

    final signed = http.Request(request.method, request.url)
      ..headers.addAll(request.headers)
      ..bodyBytes = request.bodyBytes
      ..followRedirects = request.followRedirects
      ..maxRedirects = request.maxRedirects
      ..persistentConnection = request.persistentConnection;

    signed.headers.addAll(OwnerSignature.headers(
      method: request.method,
      // The path the agent will actually verify — its own, with no host and no
      // relay mount prefix. A signature over the host breaks when a relay
      // renames it; a signature over the mount prefix breaks because a
      // path-mounting relay strips that prefix before the agent sees the
      // request, so the agent verifies `/api/…` and a prefixed signature matches
      // nothing. pathSignatureCovers removes the prefix, and leaves a bare
      // origin's path untouched.
      path: pathSignatureCovers(agentOrigin, request.url),
      body: request.bodyBytes,
      ownerSeed: seed,
      ownerAid: ownerAid,
      targetAid: agentAid,
    ));
    if (place != null) {
      signed.headers[keyStateHeader] =
          '${place.sn.toRadixString(16)}.${place.digest}';
    }
    // A seed read for this request alone is zeroed once it has signed; one
    // the caller's [ownerSeed] hands over stays the caller's.
    if (read != null) seed.fillRange(0, seed.length, 0);

    return _inner.send(signed);
  }

  /// Whether a URL belongs to the agent this client owns.
  ///
  /// Compared on scheme, host and port rather than on a prefix. A prefix test
  /// would accept `https://my-agent.example.com.attacker.test` as the agent,
  /// which is a real way to be handed somebody else's signature.
  bool _isOwnAgent(Uri url) {
    final own = Uri.tryParse(agentOrigin);
    if (own == null || own.host.isEmpty) return false;
    return url.scheme == own.scheme &&
        url.host == own.host &&
        url.port == own.port;
  }

  @override
  void close() {
    // Only what this wrapper created; a borrowed inner belongs to the caller.
    if (_ownsInner) _inner.close();
    super.close();
  }
}

/// The owner's key in force: its signing seed, and the establishment event
/// that put it in force.
typedef OwnerKey = ({Uint8List seed, Place establishment});

/// The owner key and stale-state handler for an identity whose phrase this
/// device holds, read without any owner route (ADR-061 section 9): the key in
/// force from [reader], and, when an agent says a request named a stale key
/// state, the device's record told to forget where its log ends, so the next
/// reading asks the witnesses. No key is given while the identity is moving to
/// this phrase and the move is unfinished.
({
  Future<OwnerKey?> Function() ownerKey,
  Future<void> Function() onStaleKeyState
}) ownerKeyFromThePhrase(
  Future<List<String>?> Function() loadMnemonic,
  Uint8List Function(String mnemonic) toSeed,
  TheKeyStateThisDeviceReads reader, {
  TheIdentityThisDeviceHolds? held,
}) {
  final record = held ?? TheIdentityThisDeviceHolds();
  return (
    ownerKey: () async {
      final words = await loadMnemonic();
      if (words == null || words.isEmpty) return null;
      final seed = toSeed(words.join(' '));
      try {
        final state = await reader.read(seed);
        if (state.movingToThisPhrase) return null;
        return (
          seed: KeyManager.signingSeed(seed, index: state.generation),
          establishment: state.establishment
        );
      } finally {
        seed.fillRange(0, seed.length, 0);
      }
    },
    onStaleKeyState: record.forgetTheTip,
  );
}

/// Builds the seed reader most callers want: the owner's signing seed, derived
/// from the recovery phrase held in secure storage, for the key the owner's
/// identity has in force.
///
/// [keyInForce] says which of the identity's keys that is, from the 64-byte
/// BIP39 seed: `TheKeyInForce(client, origin).index` reads it from the key log
/// at the core that keeps it. Signing with the key the identity was founded
/// with stops being signing as the owner at the first rotation.
///
/// Kept separate from the client so that a caller signing as something other
/// than the root — an organisation's founder signing with the per-relationship
/// identifier they minted for it — supplies its own reader rather than working
/// around this one.
Future<Uint8List?> Function() seedFromMnemonic(
  Future<List<String>?> Function() loadMnemonic,
  Uint8List Function(String mnemonic) toSeed,
  Future<int> Function(Uint8List bip39Seed) keyInForce,
) {
  return () async {
    final words = await loadMnemonic();
    if (words == null || words.isEmpty) return null;
    final seed = toSeed(words.join(' '));
    // The bytes the identity's key in force has, obtained by calling the one
    // function that defines every key rather than by repeating its steps.
    return KeyManager.signingSeed(seed, index: await keyInForce(seed));
  };
}
