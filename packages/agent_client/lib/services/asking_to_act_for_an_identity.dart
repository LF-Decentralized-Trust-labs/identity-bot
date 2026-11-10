import 'dart:async';
import 'dart:convert';

import 'package:http/http.dart' as http;

import '../config/agent_config.dart';
import 'a_controller_offering_itself.dart';
import 'an_agent_proving_itself.dart';
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

  /// A signed, self-contained offer this computer can show as a QR, bound to
  /// the identity at [agentOrigin].
  ///
  /// Asked of the core beside this app, which holds the enclave key and is the
  /// only thing that can sign as this machine. The core mints the timestamp off
  /// its own clock and signs the key, the agent, and that moment together, so a
  /// photograph of the code cannot be replayed to another agent or after it goes
  /// stale — the whole reason this replaced the bare offer it used to show.
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

  /// Which Identity Agent is really at [agentOrigin], proved.
  ///
  /// Not a liveness probe and not a read of what the address claims. The agent
  /// is asked, by the core beside this app, to sign a fresh challenge with the
  /// keys its identifier has in force, and the answer is checked against the key
  /// history it publishes (ADR-062). A host that merely replays a public key
  /// history cannot do that, and neither can a proxy: the agent signs only for
  /// its own address. See [proveTheAgentAt].
  ///
  /// This is also where the identifier is learned. It used to be taken from
  /// the grant, from whatever answered; now it is the identifier a proving
  /// agent named, and the grant must agree with it.
  ///
  /// Throws [AnAgentCouldNotBeProved], whose `words` are fit for the screen.
  Future<ProvedAgent> proveWhoIsAt(String agentOrigin) =>
      proveTheAgentAt(agentOrigin, localCoreOrigin: _localCore, client: _plain);

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
  /// THE GRANT IS BELIEVED ONLY FROM AN AGENT THAT PROVED ITSELF. The agent
  /// named by [agentAid] (found by [proveWhoIsAt]) is asked to prove it holds
  /// that identifier's keys right after it has answered with a grant; a grant
  /// from anything else is thrown away, and so is one that names another
  /// identifier. Nothing the agent says is authenticated by itself: it is plain
  /// JSON that anyone at the address could write.
  ///
  /// Every failure to REACH the agent is treated as "not yet". The agent is
  /// reached over a network that may be down, through a relay that may still be
  /// allocating, on a machine that may still be starting — and none of those is
  /// distinguishable from "nobody has approved you", nor should they be. A
  /// failure to PROVE is not that: something is answering and it is not the
  /// agent, so [AnAgentCouldNotBeProved] is thrown at once.
  ///
  /// Returns null on running out, which the screen says as "nothing yet" rather
  /// than as a failure, because the usual reason is that nobody has picked up
  /// their phone.
  Future<WhatThisMachineWasTold?> waitUntilGranted(
    String agentOrigin, {
    required String agentAid,
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
      WhatThisMachineWasTold? told;
      try {
        told = await whatTheAgentSays(agentOrigin);
      } catch (_) {
        // Not yet, for one of many reasons that look the same from here.
      }
      if (told != null) {
        // Proved AFTER the grant arrived, so a grant is taken from an agent
        // that has just shown it holds the keys, not one that did a minute ago.
        final proved = await proveTheAgentAt(agentOrigin,
            aid: agentAid, localCoreOrigin: _localCore, client: _plain);
        if (proved.aid != told.agentAid) {
          throw const AnAgentCouldNotBeProved(
              NotProved.somethingElse,
              'Something answered at that address, but it could not show '
              'that it is the one you meant.',
              'the grant named another identifier than the one proved');
        }
        return told;
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
