import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

import '../config/agent_config.dart';
import 'a_controller_offering_itself.dart';
import 'controller_signing_client.dart';
import 'the_owner_at_this_computer.dart';

/// The machine's own half of asking to act for an identity.
///
/// Two questions, asked of two different places, and keeping them apart is the
/// whole of it. What this computer OFFERS is asked of the core beside it, which
/// holds the enclave key and is the only thing that can answer. What this
/// computer has BEEN GRANTED is asked of the agent, because the agent is where
/// the grant lives and nothing else knows.
///
/// IT ASKS RATHER THAN BEING TOLD, and that is not a limitation to fix later.
/// The device holding the identity's key has never spoken to this machine and
/// has no way to reach it — a push would mean an address this computer
/// published and something listening on it, which is a great deal of machinery
/// to avoid one poll. Asking needs nothing, works behind anything, and the
/// answer is the same.
class AskingToActForAnIdentity {
  AskingToActForAnIdentity({
    String? localCoreOrigin,
    http.Client? client,
  })  : _localCore = localCoreOrigin ?? AgentConfig.coreBaseUrl,
        _plain = ProvingThisComputer.over(client),
        _ownClient = client == null;

  /// The core on THIS computer. Never the agent: the key that names this
  /// machine is in this machine's hardware, and the agent cannot reach it.
  final String _localCore;

  /// Unsigned, deliberately. Asking this computer what it would offer is a
  /// local question and the core answers a local request as its owner's.
  final http.Client _plain;
  final bool _ownClient;

  /// Set when this object is disposed, so a wait in flight stops.
  ///
  /// Without it the loop went on asking every two seconds for the rest of its
  /// ten minutes, against a client that had already been closed, long after the
  /// screen that started it was gone. Nothing broke; it simply kept a machine
  /// busy doing something nobody was waiting for, which is the kind of thing
  /// that is only ever found by somebody looking.
  bool _disposed = false;

  /// A signed offer to act for the identity at [agentOrigin], which
  /// [aShortCodeFor] leaves at that Identity Agent.
  ///
  /// Asked of the core beside this app, which holds the enclave key and is the
  /// only thing that can sign as this machine. The core mints the timestamp off
  /// its own clock and signs the key, the agent, and that moment together, so a
  /// photograph of the code cannot be replayed to another agent or after it goes
  /// stale — the whole reason this replaced the bare offer it used to carry.
  ///
  /// Returns null when this hardware cannot act for an identity at all — no
  /// enclave, or one the software cannot use (the core answers 501). That is an
  /// answer rather than a failure, and the screen says so plainly instead of
  /// offering a button that will not work.
  Future<ControllerOffer?> aSignedOfferFor(String agentOrigin,
      {String orgName = ''}) async {
    final res = await _plain.post(
      Uri.parse('$_localCore/api/controller/offer'),
      headers: const {'Content-Type': 'application/json'},
      body: jsonEncode({'agent_origin': agentOrigin}),
    );
    if (res.statusCode == 501) return null;
    if (res.statusCode != 200) {
      throw Exception('this computer could not sign an offer to act '
          '(${res.statusCode}): ${res.body}');
    }
    // The org name is the front end's to supply — the core that signs the offer
    // is pre-founding and has no name for it. Added as display only (unsigned),
    // so the authorize consent can name what is being connected to.
    final body = jsonDecode(res.body) as Map<String, dynamic>;
    if (orgName.isNotEmpty) body['org_name'] = orgName;
    final offer = ControllerOffer.fromJson(body);
    if (offer.aid.isEmpty || offer.publicKey.isEmpty || offer.signature.isEmpty) {
      throw Exception('this computer signed nothing usable, so there is '
          'nothing anybody could authorise');
    }
    return offer;
  }

  /// The short code this computer shows to ask to act for the identity at
  /// [agentOrigin]: a bare pointer to its signed offer, left at that Identity
  /// Agent (ADR-041 Amendment 1).
  ///
  /// Two steps, in two places. The core on this computer signs the offer, as
  /// [aSignedOfferFor] always has; then the offer is left at the Identity Agent
  /// it is for, which the owner's phone can reach where it cannot reach this
  /// computer, and which answers with a token. The code is that Identity
  /// Agent's `https://{agent}/i/{token}`, read by the owner's Identity Agent
  /// through the same scan gate as every other code.
  ///
  /// Each call is a new offer and a new code, and makes the previous code from
  /// this computer stop working. The code expires with the offer
  /// ([AControllerRequest.expiresAt]); nothing renews it unless the screen
  /// asks again, which by default it does not.
  ///
  /// Returns null when this hardware cannot act for an identity at all, as
  /// [aSignedOfferFor] does. Leaving the offer never grants anything: the
  /// owner's own signed approval does.
  Future<AControllerRequest?> aShortCodeFor(String agentOrigin,
      {String orgName = '', String label = ''}) async {
    final origin = agentOrigin.trim().replaceAll(RegExp(r'/+$'), '');
    final offer = await aSignedOfferFor(origin, orgName: orgName);
    if (offer == null) return null;
    // Unsigned, deliberately: this computer has no standing at the Identity
    // Agent yet, and the offer inside is what carries its signature.
    final res = await _plain.post(
      Uri.parse('$origin/api/controller/requests'),
      headers: const {'Content-Type': 'application/json'},
      body: jsonEncode(offer.toRequestBody(label: label)),
    );
    if (res.statusCode == 429) {
      throw const ControllerRequestRefused(
          'too many codes have been asked for just now; wait a minute and '
          'ask for a new one');
    }
    if (res.statusCode == 409) {
      // A code from this same moment is already waiting: two presses inside
      // one second. The one already shown still works.
      throw const ControllerRequestRefused(
          'this computer already has a code waiting; ask for a new one in a '
          'second');
    }
    if (res.statusCode != 200) {
      throw ControllerRequestRefused('the Identity Agent at $origin would not '
          'take this computer\'s request: ${_said(res.body)}');
    }
    final body = jsonDecode(res.body) as Map<String, dynamic>;
    final url = (body['url'] ?? '').toString();
    final token = (body['token'] ?? '').toString();
    final expiresAt = DateTime.tryParse((body['expires_at'] ?? '').toString());
    // The pointer must be the Identity Agent this computer signed its offer
    // for: the owner's Identity Agent refuses a request served from anywhere
    // else, so a code pointing elsewhere would only fail on the phone.
    if (token.isEmpty || url != '$origin/i/$token' || expiresAt == null) {
      throw ControllerRequestRefused('the Identity Agent at $origin answered '
          'with a code this computer cannot show');
    }
    return AControllerRequest(
        url: url, token: token, expiresAt: expiresAt.toUtc(), offer: offer);
  }

  /// What the agent at [agentOrigin] says this machine has been granted.
  ///
  /// Signed as this machine, because the agent has never seen this connection
  /// and there is nothing else to prove who is asking. Returns null while
  /// nothing has been granted — a refusal is the ordinary state before somebody
  /// approves, not an error worth showing anybody.
  Future<WhatThisMachineWasTold?> whatTheAgentSays(String agentOrigin) async {
    // SIGNED AS THIS MACHINE, EXPLICITLY, and not through the transport that
    // decides for itself.
    //
    // That transport picks the controller client only once this installation
    // already IS a controller, which is the state this call exists to reach —
    // so going through it during the ceremony is circular. It would fall to the
    // client for "a machine this device owns", find no record of having adopted
    // anything, and send the request unsigned. The agent would then read it as
    // not coming from a controller at all, refuse it, and this method would
    // report that as "nobody has approved you yet" — forever, however many
    // times somebody approved it.
    final client = ControllerSigningClient(
      agentOrigin: agentOrigin,
      // The key that signs is in THIS machine's hardware, and the agent cannot
      // reach it, so the signing happens next door and this asks for it.
      localCoreOrigin: () => _localCore,
      // Naming nobody, explicitly: this is how the identifier is learned, and
      // the core must not fill in whichever Identity Agent it was told about
      // before, which would make this one refuse it.
      agentAid: '',
      inner: _plain,
    );
    try {
      final res = await client.get(Uri.parse('$agentOrigin/api/controller/agent'));
      if (res.statusCode == 401 || res.statusCode == 403) return null;
      if (res.statusCode != 200) {
        throw Exception('the Identity Agent at $agentOrigin answered '
            '${res.statusCode}: ${res.body}');
      }
      final body = jsonDecode(res.body) as Map<String, dynamic>;
      final aid = (body['aid'] ?? '').toString();
      if (aid.isEmpty) return null;
      return WhatThisMachineWasTold(
        agentAid: aid,
        agentLabel: (body['label'] ?? '').toString(),
        yourLabel: (body['your_label'] ?? '').toString(),
        yourGrade: (body['your_grade'] ?? '').toString(),
        yourAuthorisationEnds: body['your_authorisation_ends'] == null
            ? null
            : DateTime.tryParse(body['your_authorisation_ends'].toString()),
      );
    } finally {
      // Closes only the wrapper. The transport underneath belongs to this
      // object and is closed by dispose, or by whoever handed it in.
      client.close();
    }
  }

  /// Whether an Identity Agent is really at [agentOrigin].
  ///
  /// ASKED OF THE ONE ROUTE AN AGENT ANSWERS TO A STRANGER, and checked on what
  /// comes back rather than on the status alone. Health is a liveness probe
  /// that reveals nothing, which is exactly why it is public — and it names the
  /// software answering, so a 200 from something else does not pass.
  ///
  /// It cannot say WHICH identity is there. Nothing public does: the routes that
  /// name an identity all need to know the identifier already, which is the
  /// thing being looked for. So the identifier is learned when the grant
  /// arrives, and this establishes only that the address leads to an agent —
  /// which is the common mistake, a typo, and worth catching before somebody
  /// watches a code for ten minutes.
  ///
  /// Reaching for an owner-only route and reading its refusal as success would
  /// accept far more: anything behind an access proxy, any server with a deny
  /// rule, any JSON endpoint, and any OTHER person's agent all refuse
  /// identically.
  Future<void> confirmAnAgentIsAt(String agentOrigin) async {
    late final http.Response res;
    try {
      res = await _plain.get(Uri.parse('$agentOrigin/api/health'));
    } catch (e) {
      throw Exception('nothing answered at $agentOrigin — check the address');
    }
    if (res.statusCode != 200) {
      throw Exception('something answered at $agentOrigin and it is not an '
          'Identity Agent (${res.statusCode})');
    }
    Object? body;
    try {
      body = jsonDecode(res.body);
    } catch (_) {
      throw Exception('whatever is at $agentOrigin did not answer like an '
          'Identity Agent');
    }
    // The shape, not merely the status. A great many things answer 200 at a
    // path they do not know; far fewer describe themselves this way.
    if (body is! Map<String, dynamic> ||
        (body['agent'] ?? '').toString().isEmpty ||
        (body['status'] ?? '').toString().isEmpty) {
      throw Exception('whatever is at $agentOrigin did not answer like an '
          'Identity Agent');
    }
  }

  /// Whether the identity answering at an address really is the one it claims.
  ///
  /// THE CHECK THAT RUNS THE OTHER WAY. Everything else here is about the
  /// Identity Agent satisfying itself that a request came from a machine it
  /// authorised. This is the reverse, and without it the machine took the
  /// identifier the agent reported at face value and wrote it down as the
  /// identity it now fronts for — so anything at that address could name any
  /// identity and be believed, permanently, because every later launch trusts
  /// what was written.
  ///
  /// Asked of THIS computer's own core, which is the only party with an engine
  /// it controls. Asking the agent to verify itself would be asking the thing
  /// under question to answer for itself.
  ///
  /// The answer is worth something because a key event log is self-verifying:
  /// the identifier is derived from the inception event, so a log that checks
  /// out cannot name an identifier other than its own. Nobody is trusted for
  /// this — not the agent, not the address, not whatever is in between.
  ///
  /// Throws rather than returning false. There is one thing to do about every
  /// reason it fails, and a caller offered a boolean will eventually treat one
  /// of them as good enough.
  Future<String> confirmThisIsReally(String agentAid, String agentOrigin) async {
    final res = await _plain.post(
      Uri.parse('$_localCore/api/verify/identity-elsewhere'),
      headers: const {'Content-Type': 'application/json'},
      body: jsonEncode({
        'aid': agentAid,
        // Where a KERI identity publishes its history, composed from the
        // address rather than taken from the far side — an address that names
        // where to check itself is not a check.
        'oobi_url': '$agentOrigin/oobi/$agentAid',
      }),
    );
    if (res.statusCode != 200) {
      throw Exception('this computer could not check who is at $agentOrigin '
          '(${res.statusCode}): ${res.body}');
    }
    final body = jsonDecode(res.body) as Map<String, dynamic>;
    if (body['verified'] != true) {
      throw Exception('the identity at $agentOrigin could not be verified: '
          '${body['why'] ?? 'no reason given'}');
    }
    final confirmed = (body['aid'] ?? '').toString();
    if (confirmed != agentAid) {
      throw Exception('the address $agentOrigin answers for $confirmed, not '
          'for $agentAid');
    }
    return (body['public_key'] ?? '').toString();
  }

  /// Whether the core beside this app will actually sign for it.
  ///
  /// Asked because the signing client cannot report that it did not. By design
  /// it sends unsigned when the core will not sign, and the agent then refuses
  /// — which is indistinguishable, from here, from nobody having approved
  /// anything. So a machine whose core cannot sign would wait the full ten
  /// minutes and then say nothing had been approved, however many times
  /// somebody approved it. That is the same shape as the bug this whole class
  /// was written around, one layer down.
  ///
  /// Throws with what the core said, because it is the one thing anybody can
  /// act on: an enclave that is locked, a core that is not running, hardware
  /// that cannot hold a key.
  Future<void> confirmThisMachineCanSign() async {
    final res = await _plain.post(
      Uri.parse('$_localCore/api/controller/sign'),
      headers: const {'Content-Type': 'application/json'},
      // A request that goes nowhere. What is being established is whether this
      // machine's hardware will produce a signature at all, not what it says.
      body: jsonEncode({'method': 'GET', 'path': '/api/controller/agent'}),
    );
    if (res.statusCode != 200) {
      throw Exception('this computer cannot sign for itself, so nothing it '
          'sends can be recognised (${res.statusCode}): ${res.body}');
    }
  }

  /// Asks until the agent says this machine may act, or [until] passes.
  ///
  /// Every failure is treated as "not yet". The agent is reached over a network
  /// that may be down, through a relay that may still be allocating, on a
  /// machine that may still be starting — and none of those is distinguishable
  /// from "nobody has approved you", nor should they be: the person is waiting
  /// for the same thing either way.
  ///
  /// Returns null on running out, which the screen says as "nothing yet" rather
  /// than as a failure, because the usual reason is that nobody has picked up
  /// their phone.
  Future<WhatThisMachineWasTold?> waitUntilGranted(
    String agentOrigin, {
    Duration every = const Duration(seconds: 2),
    Duration until = const Duration(minutes: 10),
  }) async {
    // Established once, before waiting on anything. A machine that cannot sign
    // will never be recognised no matter how long it waits, and every minute
    // spent finding that out is a minute somebody spends believing the delay is
    // at the other end.
    await confirmThisMachineCanSign();

    final deadline = DateTime.now().add(until);
    while (!_disposed && DateTime.now().isBefore(deadline)) {
      try {
        final told = await whatTheAgentSays(agentOrigin);
        if (told != null) return told;
      } catch (_) {
        // Not yet, for one of many reasons that look the same from here.
      }
      await Future<void>.delayed(every);
    }
    return null;
  }

  void dispose() {
    _disposed = true;
    if (_ownClient) _plain.close();
  }
}

/// The short code a computer shows to ask to act for an identity.
class AControllerRequest {
  const AControllerRequest({
    required this.url,
    required this.token,
    required this.expiresAt,
    required this.offer,
  });

  /// `https://{agent}/i/{token}`: what the QR holds, and all it holds.
  final String url;
  final String token;

  /// When the code stops working, which is when the offer inside it does. The
  /// screen shows it, says plainly once it has passed, and offers a new code.
  /// Wait for the grant with [AskingToActForAnIdentity.waitUntilGranted] no
  /// longer than this (its `until`), since nobody can approve after it.
  final DateTime expiresAt;

  /// The signed offer left at the Identity Agent behind the pointer.
  final ControllerOffer offer;

  bool hasExpired([DateTime? now]) =>
      !(now ?? DateTime.now()).toUtc().isBefore(expiresAt);
}

/// The person-facing words in an Identity Agent's error body: the detail, then
/// the headline, then a plain sentence when the body is not one.
String _said(String body) {
  try {
    final m = jsonDecode(body) as Map<String, dynamic>;
    for (final k in ['details', 'error']) {
      final v = (m[k] ?? '').toString().trim();
      if (v.isNotEmpty) return v;
    }
  } catch (_) {}
  return 'it gave no reason';
}

/// An Identity Agent would not take, or answered strangely to, a computer's
/// request. Its message is written for a person.
class ControllerRequestRefused implements Exception {
  const ControllerRequestRefused(this.reason);
  final String reason;

  @override
  String toString() => reason;
}

/// What an agent tells a machine it has been granted.
class WhatThisMachineWasTold {
  const WhatThisMachineWasTold({
    required this.agentAid,
    this.agentLabel = '',
    this.yourLabel = '',
    this.yourGrade = '',
    this.yourAuthorisationEnds,
  });

  /// Which identity this machine is now a front end for. Recorded alongside the
  /// address, because an address is not an identity.
  final String agentAid;
  final String agentLabel;

  /// What the person called this machine when they approved it.
  final String yourLabel;

  /// Whether they said they are keeping it, or using it for now.
  final String yourGrade;
  final DateTime? yourAuthorisationEnds;

  bool get theyAreKeepingIt => yourGrade == 'enrolled';
}
