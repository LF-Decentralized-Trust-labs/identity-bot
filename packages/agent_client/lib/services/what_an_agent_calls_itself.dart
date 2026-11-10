import 'dart:convert';
import 'dart:typed_data';

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

import '../config/agent_config.dart';
import 'an_agent_proving_itself.dart';
import 'controller_signing_client.dart';

/// What an Identity Agent elsewhere calls itself: a display name and a picture.
///
/// Read so that somebody can say "yes, that is the one I meant" BEFORE this app
/// remembers it. An address says where something is, and the identifier that
/// comes back with the approval says nothing a person can recognise; a name and
/// a face is what people actually know their own organisation by. The
/// identifier is never shown (M82 §2) — it is checked internally, here by
/// [WhichHalfThisAppIsRunning] on every later launch.
///
/// What it says is for a person to look at, never for the app to decide on, but
/// it is only read from an agent that has just PROVED it holds the identifier's
/// keys ([proveTheAgentAt]). Without that, anything at the address could show
/// any name and picture, and a person would confirm a face that was never the
/// agent's.
@immutable
class WhatAnAgentCallsItself {
  const WhatAnAgentCallsItself({this.name = '', this.picture});

  /// Empty when the agent has not been given a name.
  final String name;

  /// Small by the agent's own doing — it squares and scales every picture it
  /// stores — and drawn smaller still. Null when it has none.
  final Uint8List? picture;

  /// Read out of the body of `GET /api/profile`.
  ///
  /// An organisation's name is `org_name`; `fn` is the fallback because an
  /// agent that has only ever been given a full name still has something a
  /// person would recognise. A picture that does not decode is treated as no
  /// picture rather than a failure — the name is still worth showing.
  factory WhatAnAgentCallsItself.fromProfileJson(String body) {
    final json = jsonDecode(body);
    if (json is! Map<String, dynamic>) return const WhatAnAgentCallsItself();
    final org = (json['org_name'] ?? '').toString().trim();
    final fn = (json['fn'] ?? '').toString().trim();
    final raw = (json['photo'] ?? '').toString();
    Uint8List? picture;
    if (raw.isNotEmpty) {
      final comma = raw.indexOf(',');
      try {
        picture = base64Decode(comma >= 0 ? raw.substring(comma + 1) : raw);
      } catch (_) {
        picture = null;
      }
    }
    return WhatAnAgentCallsItself(
        name: org.isNotEmpty ? org : fn, picture: picture);
  }
}

/// Asks the agent at [agentOrigin] what it calls itself, signed as THIS
/// computer — which it has just been approved as, so the profile route answers.
///
/// The agent must first prove it is [agentAid] (see [proveTheAgentAt]); nothing
/// is read from one that cannot. Naming [agentAid] in the signature means a
/// copy of the request is refused by any other agent.
///
/// Throws [AnAgentCouldNotBeProved] when it is not the agent, and any other
/// exception when the profile could not be read. A caller that could not ask
/// must not go on to remember the agent unconfirmed.
Future<WhatAnAgentCallsItself> readWhatAnAgentCallsItself({
  required String agentOrigin,
  required String agentAid,
  int? knownSequence,
  String? knownKey,
  String? localCoreOrigin,
  http.Client? inner,
  Duration blipPause = const Duration(seconds: 2),
}) async {
  // With what was proved before, so a history that went back since is refused,
  // and through a blip, so a passing network failure is not a verdict.
  await proveTheAgentAtThroughABlip(agentOrigin,
      aid: agentAid,
      knownSequence: knownSequence,
      knownKey: knownKey,
      localCoreOrigin: localCoreOrigin,
      client: inner,
      pause: blipPause);
  final client = ControllerSigningClient(
    agentOrigin: agentOrigin,
    // The key that signs is in THIS machine's hardware; the agent cannot reach it.
    localCoreOrigin: () => localCoreOrigin ?? AgentConfig.coreBaseUrl,
    agentAid: agentAid,
    inner: inner,
  );
  try {
    final res = await client.get(Uri.parse('$agentOrigin/api/profile'));
    if (res.statusCode != 200) {
      // The detail is for the log. What a person is told is worded by the
      // caller.
      throw Exception('the Identity Agent at $agentOrigin would not say what '
          'it is called (${res.statusCode})');
    }
    return WhatAnAgentCallsItself.fromProfileJson(res.body);
  } finally {
    client.close();
  }
}
