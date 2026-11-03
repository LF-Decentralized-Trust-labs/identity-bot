import 'dart:convert';

import 'package:http/http.dart' as http;

import '../crypto/owner_signature.dart';
import 'signs_before_it_sends.dart';
import 'the_path_a_signature_covers.dart';
import 'the_owner_at_this_computer.dart';

/// Reaching a machine you own but are not sitting at.
///
/// The machine cannot tell who is calling from the connection — its owner is
/// remote by definition — so every owner route there answers "sign this". The
/// key that satisfies it is NOT the root key. A machine is adopted by a
/// pairwise identity this device minted for that machine alone, and that
/// identity is what the machine sealed and what it checks against. Signing with
/// the root produces a signature that verifies nowhere, which is a failure with
/// no visible cause.
///
/// THIS DEVICE HOLDS THE KEY BUT NEVER HANDS IT OVER. The pairwise key is
/// derived from the root seed at an index only the local core wrote down, so the
/// signing happens there — `POST /api/machines/owner/sign` — and this client
/// asks for it per request. [OwnerSigningClient] signs in Dart from a seed the
/// caller supplies, which suits the root identity and cannot reach these: the
/// index is deliberately never handed out.
///
/// IT SIGNS ONLY REQUESTS TO THE MACHINE IT IS POINTED AT, for the reason every
/// client here does. The same client resolves other people's discovery records
/// and talks to relays and witnesses, and attaching an identifier to those would
/// hand it to every stranger it looks up — the opposite of what a pairwise
/// identifier is for.
///
/// What it deliberately does NOT do is fall back, or send unsigned. If the local
/// core will not sign, or this device has no identity recorded as owning that
/// machine, the request is refused here with [ThisMachineCouldNotSign]. Signing
/// as anything else — the root, another machine's identity — would be a request
/// that fails at the far end with a reason nobody can see.
class SigningAsTheIdentityThatOwnsAMachine extends SignsBeforeItSends {
  SigningAsTheIdentityThatOwnsAMachine({
    required this.machineOrigin,
    required this.localCoreOrigin,
    required this.ownerAid,
    super.waitAtMost = const Duration(seconds: 90),
    super.inner,
  }) : super(signedOrigin: machineOrigin);

  /// The machine this device owns, as scheme://host:port. Requests anywhere
  /// else are passed through untouched.
  final String machineOrigin;

  /// Where this device's own core is, which can derive the pairwise key and
  /// does the signing.
  ///
  /// A function, read for EVERY request, and not an address captured when the
  /// client was built: the core takes the next free port when its default is
  /// held and is restarted when the profile changes.
  final String Function() localCoreOrigin;

  /// Which of this device's minted identities owns that machine.
  ///
  /// Read from the machine itself — it reports the owner it sealed — rather than
  /// remembered here. The machine is the side that decides which signature it
  /// will accept, so its answer is the one that matters, and a second copy on
  /// this device would be a second place for it to be wrong.
  ///
  /// Async and called per request rather than held: a machine can be adopted, or
  /// forgotten, while the app is running.
  final Future<String?> Function() ownerAid;

  /// Asks the local core to sign this request as the machine's owner.
  ///
  /// Throws [ThisMachineCouldNotSign] when it will not: an identity not yet
  /// minted, a machine this device does not own, a core still starting or one
  /// that cannot be reached. Each is said as what it is, rather than sent on as
  /// a request the machine can only answer with a refusal that blames the
  /// person.
  @override
  Future<Map<String, String>> headersFor(http.Request request) async {
    final aid = await ownerAid();
    if (aid == null || aid.isEmpty) {
      throw ThisMachineCouldNotSign(
          'this device has no identity of its own recorded as owning that '
          'machine',
          request.url);
    }
    final body = await askTheCoreToSign(
      localCoreOrigin(),
      '/api/machines/owner/sign',
      {
        'owner_aid': aid,
        'method': request.method,
        // The path the machine will actually verify — its own, with no host
        // and no relay mount prefix. A signature over the host breaks when a
        // relay renames it; a signature over the mount prefix breaks because a
        // path-mounting relay strips that prefix before the machine sees the
        // request, so the machine verifies `/api/…` and a prefixed signature
        // matches nothing. pathSignatureCovers removes the prefix, and leaves
        // a bare origin's path untouched.
        'path': pathSignatureCovers(machineOrigin, request.url),
        'body_b64': base64.encode(request.bodyBytes),
      },
      request.url,
      mustHave: const {
        'signature': 'a signature',
        'timestamp': 'a timestamp',
      },
    );
    // The Identity Agent the core signed this for — the machine this owner
    // adopted. Echoed, because it is inside the signature.
    final signedFor = (body['for'] ?? '').toString();

    return {
      'X-IA-Owner-Sig': body['signature'].toString(),
      // Echoed back from the core rather than formatted again here. The moment
      // is inside the signature, so a second formatting that differs by a
      // millisecond or a zone signs a string the machine never sees.
      'X-IA-Owner-Timestamp': body['timestamp'].toString(),
      // The digest the signature covers, so the machine checks the signature
      // before it reads any of the body. Computed here from the very bytes
      // that are sent (and that the core was asked to sign), not echoed.
      OwnerSignature.bodyDigestHeader:
          OwnerSignature.blake3QB64(request.bodyBytes),
      'X-IA-Owner-AID': (body['owner_aid'] ?? aid).toString(),
      if (signedFor.isNotEmpty) 'X-IA-Owner-For': signedFor,
    };
  }
}

/// The reader most callers want: which identity this device adopted a given
/// machine as, looked up in its own record of what it owns.
///
/// Asked of THIS DEVICE rather than of the machine. The machine's own answer —
/// `/api/owners/authority` — is owner-only, so reading it would need the
/// signature this is being used to produce. The record here was written at
/// adoption by the side that minted the identity, and it is the same fact.
///
/// A machine this device does not own returns null, and the request is
/// refused. That is the honest answer: there is no identity to sign as.
Future<String?> Function() theIdentityThatAdopted(
  String machineOrigin, {
  required String Function() localCoreOrigin,
  http.Client? using,
}) {
  return () async {
    final client = ProvingThisComputer.over(using);
    try {
      final res = await client.get(Uri.parse('${localCoreOrigin()}/api/agents'));
      if (res.statusCode != 200) return null;
      final agents =
          ((jsonDecode(res.body) as Map<String, dynamic>)['agents'] as List?) ??
              const [];
      final want = Uri.tryParse(machineOrigin);
      if (want == null) return null;
      for (final a in agents.whereType<Map<String, dynamic>>()) {
        final url = Uri.tryParse((a['url'] ?? '').toString());
        // Matched on scheme, host and port, not on the string. A machine's
        // address is recorded with whatever path and trailing slash it arrived
        // with, and comparing the text would miss the row for the machine being
        // called — leaving the request unsigned with nothing saying why.
        if (url == null) continue;
        if (url.scheme != want.scheme ||
            url.host != want.host ||
            url.port != want.port) {
          continue;
        }
        final owner = (a['owner_aid'] ?? '').toString();
        // Empty means this machine was adopted before machines were adopted
        // pairwise, so the ROOT owns it — an answer, not a gap, and one this
        // client cannot act on: it signs only as identities minted per machine.
        return owner.isEmpty ? null : owner;
      }
      return null;
    } catch (_) {
      return null;
    } finally {
      if (using == null) client.close();
    }
  };
}
