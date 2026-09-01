import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

import '../config/agent_config.dart';
import 'controller_signing_client.dart';

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
        _plain = client ?? http.Client(),
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

  /// What this computer would offer if somebody authorised it.
  ///
  /// Returns null when this hardware cannot act for an identity at all — no
  /// enclave, or one the software cannot use. That is an answer rather than a
  /// failure, and the screen says so plainly instead of offering a button that
  /// will not work.
  Future<AMachineOffering?> whatThisComputerOffers() async {
    final res = await _plain.get(Uri.parse('$_localCore/api/controller/this-machine'));
    if (res.statusCode == 501) return null;
    if (res.statusCode != 200) {
      throw Exception('this computer could not say what it offers '
          '(${res.statusCode}): ${res.body}');
    }
    final body = jsonDecode(res.body) as Map<String, dynamic>;
    final aid = (body['aid'] ?? '').toString();
    final key = (body['public_key'] ?? '').toString();
    if (aid.isEmpty || key.isEmpty) {
      throw Exception('this computer named no identifier and no key, so there '
          'is nothing anybody could authorise');
    }
    return AMachineOffering(
      aid: aid,
      publicKey: key,
      protectedBy: (body['protected_by'] ?? '').toString(),
    );
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
      localCoreOrigin: _localCore,
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

/// What a computer says about itself when it asks to act for an identity.
class AMachineOffering {
  const AMachineOffering({
    required this.aid,
    required this.publicKey,
    this.protectedBy = '',
    this.agentOrigin = '',
  });

  /// This machine's identifier, which IS its public key — the non-transferable
  /// form, with no inception event and nothing published. Knowing it proves
  /// nothing, which is why it can be shown on a screen.
  final String aid;
  final String publicKey;

  /// What is holding the private half. Shown to the person, because "this
  /// computer can keep a key to itself" is what makes authorising it reasonable
  /// at all.
  final String protectedBy;

  /// WHICH IDENTITY AGENT THIS MACHINE IS ASKING, and the field without which
  /// none of this works.
  ///
  /// The grant is written on the agent, by the device holding the identity's
  /// key — so that device has to know which agent to write it on. It cannot
  /// work that out: the person is standing at the computer, and the phone has
  /// never seen this ceremony. Without this the phone posts the grant to its
  /// own core, which on the ordinary arrangement is not the agent at all, and
  /// the computer waits for a grant that was written somewhere else.
  ///
  /// It is a claim, not an instruction. The device receiving it looks for that
  /// address among the machines it actually owns and refuses anything else,
  /// so a code naming somebody else's agent gets nowhere.
  final String agentOrigin;

  /// What the owner's device reads.
  ///
  /// Both fields, though they are the same value in different clothes: the
  /// agent refuses a grant whose identifier and key disagree, so sending both
  /// lets it check rather than trust. A payload naming only the identifier
  /// would have to be expanded by whoever received it, and the expansion is the
  /// part worth checking.
  String get toBeScanned => jsonEncode({
        'aid': aid,
        'public_key': publicKey,
        if (protectedBy.isNotEmpty) 'protected_by': protectedBy,
        if (agentOrigin.isNotEmpty) 'agent_origin': agentOrigin,
      });
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
