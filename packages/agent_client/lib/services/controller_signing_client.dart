import 'dart:convert';

import 'package:http/http.dart' as http;

import '../crypto/endpoint_record.dart';
import '../crypto/owner_signature.dart';
import 'signs_before_it_sends.dart';
export 'signs_before_it_sends.dart' show ThisMachineCouldNotSign;
import 'the_path_a_signature_covers.dart';

/// Reaching an Identity Agent that runs on a different machine.
///
/// The Identity Agent is one application. Where its halves run is a deployment
/// question: when the identity lives on a sealed machine, that machine runs the
/// back end and this app runs the front end, in **controller mode**. So every
/// request a screen makes has to leave this computer and arrive at the agent —
/// and arrive proven, because the agent has never seen this connection before
/// and "it came from localhost" is exactly what is not true any more.
///
/// THIS COMPUTER SIGNS, BUT IT DOES NOT HOLD THE KEY. The controller's key is in
/// this machine's enclave and cannot leave it, so the signing happens in the
/// local core — `POST /api/controller/sign` — and this client asks for it per
/// request. That call is the only work a controller's own back end does, and it
/// is about the controller rather than about the identity.
///
/// IT SIGNS ONLY REQUESTS TO THE AGENT IT IS POINTED AT, for the same reason
/// [OwnerSigningClient] does. The same client resolves other people's discovery
/// records and talks to relays and witnesses; attaching this machine's
/// identifier to those would hand it to every stranger it looks up.
///
/// What it deliberately does NOT do is fall back, and it does not send unsigned
/// either. If the local core will not sign — no enclave, no key, the core not
/// running, an answer missing a field — the request is REFUSED here with
/// [ThisMachineCouldNotSign] and never leaves this computer. Reaching for the
/// local core's own answer instead would be the failure this whole mode exists
/// to prevent: a screen showing a roster, a policy or a credential belonging to
/// nobody, with nothing reporting a problem. Sending it unsigned is the same
/// failure one step later: the agent's refusal reads as "you are not allowed",
/// when the truth is "this machine has not finished starting".
class ControllerSigningClient extends SignsBeforeItSends {
  ControllerSigningClient({
    required this.agentOrigin,
    required this.localCoreOrigin,
    this.agentAid,
    this.authentication,
    super.waitAtMost = const Duration(seconds: 90),
    super.inner,
  }) : super(signedOrigin: agentOrigin);

  /// The agent this app is a front end for, as scheme://host:port.
  /// Requests anywhere else are passed through untouched.
  final String agentOrigin;

  /// Where this machine's own core is, which holds the enclave key and does the
  /// signing.
  ///
  /// A function, read for EVERY request, and not an address captured when the
  /// client was built. The core takes the next free port when its default is
  /// held and is restarted when the profile changes, so an address read once
  /// goes on pointing at a core that is no longer there.
  final String Function() localCoreOrigin;

  /// The identifier of the Identity Agent at [agentOrigin], signed into every
  /// request so no other Identity Agent will accept a copy.
  ///
  /// Null leaves it to the local core, which uses the Identity Agent it was told this
  /// app is a front end for. Empty names nobody, which an Identity Agent accepts
  /// only when a machine asks which identity it acts for — the one request made
  /// before the identifier is known.
  final String? agentAid;

  /// What the device holding the root key last said about the person, when
  /// anything did.
  ///
  /// Carried through into the signature rather than decided here, because this
  /// machine cannot decide it: a machine may not score itself, so an
  /// authentication level is only worth anything when the root-identity device
  /// has vouched for it. Null means nothing has, and the agent will refuse the
  /// actions that need one — which is the correct outcome and a legible one.
  final Future<VouchedAuthentication?> Function()? authentication;

  /// Asks the local core to sign this request as this machine.
  ///
  /// Throws [ThisMachineCouldNotSign] when it will not. A locked machine, a core
  /// still starting, or hardware that cannot hold a key are ordinary states, and
  /// each is reported as what it is rather than sent on as a request the agent
  /// can only answer with a refusal that blames the person.
  @override
  Future<Map<String, String>> headersFor(http.Request request) async {
    // Refused here, not sent in the older form that names no origin: a request
    // to an address this client cannot write as an origin could be relayed
    // through any host, and nothing would say so.
    final origin = canonicalOriginOf(agentOrigin);
    if (origin == null) {
      throw ThisMachineCouldNotSign(
          'the agent address $agentOrigin is not an http or https address with a host, '
          'so a request to it cannot be signed for it',
          request.url);
    }
    final vouched = await authentication?.call();
    final body = await askTheCoreToSign(
      localCoreOrigin(),
      '/api/controller/sign',
      {
        'method': request.method,
        // The path the agent will actually verify — its own, with no host and
        // no relay mount prefix. A signature over the host breaks when a relay
        // renames it; a signature over the mount prefix breaks because a
        // path-mounting relay strips that prefix before the agent sees the
        // request, so the agent verifies `/api/…` and a prefixed signature
        // matches nothing. pathSignatureCovers removes the prefix, and leaves
        // a bare origin's path untouched.
        'path': pathSignatureCovers(agentOrigin, request.url),
        'body_b64': base64.encode(request.bodyBytes),
        if (vouched != null) 'auth_level': vouched.level,
        if (vouched != null) 'auth_at': vouched.at.toUtc().toIso8601String(),
        if (vouched != null) 'auth_score': vouched.score,
        if (agentAid != null) 'for': agentAid,
        // The origin this request is going to, signed so a copy relayed
        // through any other address is refused by the agent. Written in its one
        // spelling (the port always, host in lower case), because the agent
        // compares text.
        'origin': origin,
      },
      request.url,
      mustHave: const {
        'controller_aid': 'its identifier',
        'signature': 'a signature',
        'timestamp': 'a timestamp',
      },
    );
    final aid = body['controller_aid'].toString();
    final sig = body['signature'].toString();
    final stamp = body['timestamp'].toString();
    // Which Identity Agent the core signed this for. Echoed rather than
    // filled in here, because it is inside the signature.
    final signedFor = (body['for'] ?? '').toString();
    // The origin the core signed this for, echoed for the same reason: it is
    // inside the signature. An old core does not echo one and signed the older
    // form, which carries no header.
    final signedOrigin = (body['origin'] ?? '').toString();

    return {
      'X-IA-Controller-AID': aid,
      'X-IA-Controller-Sig': sig,
      // Echoed back from the core rather than formatted again here. The
      // moment is inside the signature, so a second formatting that differs
      // by a millisecond or a timezone produces a signature over a string the
      // agent never sees.
      'X-IA-Controller-Timestamp': stamp,
      // The digest the signature covers, so the agent checks the signature
      // before it reads any of the body. Computed here from the very bytes
      // that are sent (and that the core was asked to sign), not echoed.
      OwnerSignature.bodyDigestHeader:
          OwnerSignature.blake3QB64(request.bodyBytes),
      if (signedFor.isNotEmpty) 'X-IA-Controller-For': signedFor,
      if (signedOrigin.isNotEmpty) 'X-IA-Controller-Origin': signedOrigin,
      for (final e in {
        'X-IA-Controller-Auth-Level': (body['auth_level'] ?? '').toString(),
        'X-IA-Controller-Auth-At': (body['auth_at'] ?? '').toString(),
        'X-IA-Controller-Auth-Score': (body['auth_score'] ?? '').toString(),
      }.entries)
        if (e.value.isNotEmpty) e.key: e.value,
      if (vouched?.vouchedBy.isNotEmpty ?? false)
        'X-IA-Auth-Level-Vouched-By': vouched!.vouchedBy,
    };
  }
}

/// How well the person was authenticated, as established by the device holding
/// the root identity and signed by it.
///
/// [vouchedBy] is that signature, over the machine it was made for, the level,
/// the moment and the score. Without it the agent treats the level as nothing
/// measured — a machine may not score itself, because software nobody can
/// attest reports whatever its operator likes.
class VouchedAuthentication {
  const VouchedAuthentication({
    required this.level,
    required this.at,
    required this.score,
    required this.vouchedBy,
  });

  final String level;
  final DateTime at;
  final int score;
  final String vouchedBy;
}
