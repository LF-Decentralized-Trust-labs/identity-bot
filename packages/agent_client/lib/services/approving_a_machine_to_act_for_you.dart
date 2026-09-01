import 'dart:convert';

import 'package:http/http.dart' as http;

/// The owner's half of authorising a computer: reading what it offers, and
/// telling the agent it may act.
///
/// This runs on the device holding the identity's key — normally a phone. It is
/// the only party that can do this. An agent cannot authorise its own
/// controllers: it holds the identity's keys and no authority to widen who may
/// use them, and one that could be talked into it would widen them for an
/// attacker without the person ever being asked.
///
/// WHAT THE PERSON IS ASKED IS ONE THING: is this a computer you keep, or one
/// you are using for now. Everything else is derived. The question is put that
/// way — rather than "will you still be using this" — because the answer only
/// matters through its consequence, so the consequence is what the options say.
class ApprovingAMachineToActForYou {
  ApprovingAMachineToActForYou({
    required this.agentOrigin,
    required http.Client client,
  }) : _client = client;

  /// The agent that will hold the grant — the machine the identity lives on,
  /// which is not the machine being authorised.
  final String agentOrigin;

  /// Signs as the owner. The grant route is owner-only and this is the whole
  /// reason: it must be the key-holding device asking.
  final http.Client _client;

  /// What a computer says about itself when it asks to act for you.
  ///
  /// Read from the machine directly rather than taken from what it displayed,
  /// so a code somebody photographed off a screen cannot name a different key
  /// than the machine holding it. The identifier IS the key, so the two cannot
  /// disagree without the agent refusing the grant.
  static AMachineAsking readWhatItOffers(String scanned) {
    final data = jsonDecode(scanned) as Map<String, dynamic>;
    final aid = (data['aid'] ?? '').toString().trim();
    final key = (data['public_key'] ?? '').toString().trim();
    if (aid.isEmpty || key.isEmpty) {
      throw const FormatException(
          'that code does not name a computer and the key it would act with');
    }
    // A COMPUTER IS NAMED BY ITS KEY, and that is what tells one apart from an
    // identity. An identifier and a public key together describe a great many
    // things — an agent's own discovery record is exactly that shape, is served
    // to anybody who knows the identifier, and was being read as a computer
    // asking to act. It got no further, because the agent refuses a grant whose
    // identifier and key disagree, but the refusal talked about a controller's
    // identifier at somebody who had scanned a person.
    //
    // Checked here so the words match what happened. The identifier of a
    // machine IS its key: not derived from it, not committed to by it — the
    // same value, in the non-transferable form that carries the key and
    // publishes nothing.
    if (aid != key) {
      throw const FormatException(
          'that code names an identity rather than a computer — a computer is '
          'named by the very key it acts with, and these are two different '
          'things');
    }
    return AMachineAsking(
      aid: aid,
      publicKey: key,
      protectedBy: (data['protected_by'] ?? '').toString(),
      suggestedLabel: (data['label'] ?? '').toString(),
      agentOrigin: (data['agent_origin'] ?? '').toString().trim(),
    );
  }

  /// Tells the agent this machine may act, at the grade the person chose.
  ///
  /// Returns nothing useful on purpose. What matters afterwards is what the
  /// AGENT thinks, and the machine finds that out by asking the agent — there is
  /// no channel from here to it, and inventing one would mean a push path to a
  /// computer this device has never spoken to.
  Future<void> approve({
    required AMachineAsking machine,
    required String label,
    required bool theyAreKeepingIt,
  }) async {
    if (label.trim().isEmpty) {
      throw ArgumentError(
          'a machine needs a name you will recognise, or you will not know '
          'which one to remove later');
    }
    final res = await _client.post(
      Uri.parse('$agentOrigin/api/controllers'),
      headers: const {'Content-Type': 'application/json'},
      body: jsonEncode({
        'controller_aid': machine.aid,
        'public_key': machine.publicKey,
        'label': label.trim(),
        // The two grades differ in how permanent the record is, and in nothing
        // else today. Both hold their own key, both are named the same way, both
        // can be removed.
        'grade': theyAreKeepingIt ? 'enrolled' : 'scoped',
      }),
    );
    if (res.statusCode != 200) {
      throw ApprovalRefused(res.statusCode, res.body);
    }
  }

  /// Takes a machine's authorisation away.
  ///
  /// Needs nothing to be reachable. The machine never held anything of the
  /// identity's, so removing the record is the whole of it — which is what makes
  /// this work for a laptop somebody no longer has.
  Future<void> revoke(String controllerAID) async {
    final res = await _client.delete(
      Uri.parse('$agentOrigin/api/controllers/${Uri.encodeComponent(controllerAID)}'),
    );
    if (res.statusCode != 200) {
      throw ApprovalRefused(res.statusCode, res.body);
    }
  }

  /// Every machine that may act for this identity, for the screen that shows
  /// them. Includes ones whose authorisation has ended, marked — a machine that
  /// stopped is something the person may still want to see.
  Future<List<AnApprovedMachine>> theMachinesThatMayAct() async {
    final res = await _client.get(Uri.parse('$agentOrigin/api/controllers'));
    if (res.statusCode != 200) {
      throw ApprovalRefused(res.statusCode, res.body);
    }
    final body = jsonDecode(res.body) as Map<String, dynamic>;
    return ((body['controllers'] ?? []) as List)
        .map((e) => AnApprovedMachine.fromJson(e as Map<String, dynamic>))
        .toList();
  }
}

/// A computer asking to act for an identity.
class AMachineAsking {
  const AMachineAsking({
    required this.aid,
    required this.publicKey,
    this.protectedBy = '',
    this.suggestedLabel = '',
    this.agentOrigin = '',
  });

  final String aid;
  final String publicKey;

  /// What is holding the private half — "Apple Secure Enclave" and so on. Shown
  /// to the person, because "this computer can keep a key to itself" is the
  /// thing that makes authorising it reasonable at all.
  final String protectedBy;

  /// What the machine calls itself. A suggestion only: the person names it, and
  /// a machine that could name itself in somebody's device list could name
  /// itself something reassuring.
  final String suggestedLabel;

  /// Which Identity Agent this machine says it is asking.
  ///
  /// The grant is written on the agent, so this device has to know which one —
  /// and it cannot work that out, because the person is standing at the other
  /// computer and this device has never seen the ceremony.
  ///
  /// A CLAIM, NEVER AN INSTRUCTION. What this device does with it is look for
  /// it among the machines it actually owns; a code naming somebody else's
  /// agent matches nothing and gets no further. Treating it as an instruction
  /// would let a code somebody photographed send this device's grant wherever
  /// it liked.
  final String agentOrigin;
}

/// A machine already authorised, as the owner's device sees it.
class AnApprovedMachine {
  const AnApprovedMachine({
    required this.aid,
    required this.label,
    required this.grade,
    required this.live,
    this.expiresAt,
    this.whyNot = '',
  });

  factory AnApprovedMachine.fromJson(Map<String, dynamic> m) => AnApprovedMachine(
        aid: (m['controller_aid'] ?? '').toString(),
        label: (m['label'] ?? '').toString(),
        grade: (m['grade'] ?? '').toString(),
        live: m['live'] == true,
        expiresAt: m['expires_at'] == null
            ? null
            : DateTime.tryParse(m['expires_at'].toString()),
        whyNot: (m['why_not'] ?? '').toString(),
      );

  final String aid;
  final String label;
  final String grade;
  final bool live;
  final DateTime? expiresAt;

  /// Why it is no longer live, in words for the person. Empty while it is.
  final String whyNot;

  bool get theyAreKeepingIt => grade == 'enrolled';
}

class ApprovalRefused implements Exception {
  const ApprovalRefused(this.status, this.body);
  final int status;
  final String body;

  @override
  String toString() => 'the agent refused this ($status): $body';
}
