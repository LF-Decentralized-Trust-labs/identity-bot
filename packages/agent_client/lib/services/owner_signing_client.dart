import 'dart:typed_data';

import 'package:http/http.dart' as http;

import '../crypto/keys.dart';
import '../crypto/owner_signature.dart';

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
class OwnerSigningClient extends http.BaseClient {
  OwnerSigningClient({
    required this.agentOrigin,
    required this.ownerSeed,
    this.ownerAid,
    http.Client? inner,
  }) : _inner = inner ?? http.Client();

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

  final http.Client _inner;

  @override
  Future<http.StreamedResponse> send(http.BaseRequest request) async {
    if (!_isOwnAgent(request.url)) {
      return _inner.send(request);
    }

    final seed = await ownerSeed();
    if (seed == null) {
      return _inner.send(request);
    }

    // Only a plain Request can be signed, because the body has to be read to
    // digest it and a stream can only be read once. Streamed uploads are passed
    // through rather than silently half-consumed; the agent refuses them, which
    // is a better failure than a request that arrives truncated.
    if (request is! http.Request) {
      return _inner.send(request);
    }

    final signed = http.Request(request.method, request.url)
      ..headers.addAll(request.headers)
      ..bodyBytes = request.bodyBytes
      ..followRedirects = request.followRedirects
      ..maxRedirects = request.maxRedirects
      ..persistentConnection = request.persistentConnection;

    signed.headers.addAll(OwnerSignature.headers(
      method: request.method,
      // The path only, with no query and no host. The agent signs the same
      // thing, and a signature over a full URL would break the moment the same
      // agent were reached by a different name — which is exactly what happens
      // behind a relay.
      path: request.url.path,
      body: request.bodyBytes,
      ownerSeed: seed,
      ownerAid: ownerAid,
    ));

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
    _inner.close();
    super.close();
  }
}

/// Builds the seed reader most callers want: the owner's root seed, derived
/// from the recovery phrase held in secure storage.
///
/// Kept separate from the client so that a caller signing as something other
/// than the root — an organisation's founder signing with the per-relationship
/// identifier they minted for it — supplies its own reader rather than working
/// around this one.
Future<Uint8List?> Function() seedFromMnemonic(
  Future<List<String>?> Function() loadMnemonic,
  Uint8List Function(String mnemonic) toSeed,
) {
  return () async {
    final words = await loadMnemonic();
    if (words == null || words.isEmpty) return null;
    final seed = toSeed(words.join(' '));
    // The same 32 bytes the identity was founded with, obtained by calling the
    // one function that defines them rather than by repeating its steps.
    //
    // This used to truncate the BIP39 seed to 32 bytes, with a comment saying
    // truncating rather than hashing was what matched. It was the wrong half of
    // its own warning: KeyManager.generateFromSeed hashes the first 32 bytes,
    // so a truncated seed signs as a key this identity has never used. Proven
    // by deriving both and comparing — see the test beside this file. Nothing
    // called it, so nothing had ever failed.
    return KeyManager.signingSeed(seed);
  };
}
