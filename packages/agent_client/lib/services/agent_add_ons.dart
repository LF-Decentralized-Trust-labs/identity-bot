import 'core_service.dart';

/// Which add-ons the Identity Agent at one address includes, as its
/// `/api/info` says (`add_ons`), so a screen shows only what is there.
///
/// An add-on is a package an app may include alongside the core: AI agents,
/// sandboxed apps. An agent built without one serves none of its routes, and
/// a screen for it would only fail.
///
/// Two answers err towards showing things. An agent that does not say (a
/// core older than add-ons) includes everything, as every one did. An agent
/// that cannot be asked right now hides nothing, so a network blip never
/// takes a screen away; that answer is not kept, and the next asks again.
class AgentAddOns {
  /// The AI-agent add-on: AI agents, their tokens and the MCP endpoint.
  static const aiAgents = 'ai_agents';

  /// The sandboxed-apps add-on: apps, the capability gateway, and the model
  /// keys and model proxy apps use.
  static const sandboxedApps = 'sandboxed_apps';

  /// The add-ons included, or null where everything is present.
  final Set<String>? included;

  const AgentAddOns._(this.included);

  /// Everything present: what an agent that does not say is taken to include.
  static const everything = AgentAddOns._(null);

  /// Exactly [ids] included.
  factory AgentAddOns.only(Iterable<String> ids) => AgentAddOns._(ids.toSet());

  /// Whether add-on [id] is included.
  bool has(String id) => included == null || included!.contains(id);

  bool get hasAiAgents => has(aiAgents);
  bool get hasSandboxedApps => has(sandboxedApps);

  static final Map<String, AgentAddOns> _known = {};
  static final Map<String, Future<AgentAddOns>> _asking = {};

  /// What the agent at [baseUrl] includes, asked once and then kept.
  ///
  /// [ask] reads its `/api/info`; left out, a [CoreService] for [baseUrl]
  /// does. A failed ask answers [everything] and is not kept.
  static Future<AgentAddOns> at(String baseUrl,
      {Future<CoreInfoResponse> Function()? ask}) {
    final known = _known[baseUrl];
    if (known != null) return Future.value(known);
    return _asking.putIfAbsent(baseUrl, () async {
      try {
        final info = await (ask ?? () => _askInfo(baseUrl))();
        final answer = info.addOns == null
            ? everything
            : AgentAddOns.only(info.addOns!);
        _known[baseUrl] = answer;
        return answer;
      } catch (_) {
        return everything;
      } finally {
        _asking.remove(baseUrl);
      }
    });
  }

  /// What is already known about the agent at [baseUrl], without asking:
  /// [everything] until it has answered.
  static AgentAddOns known(String baseUrl) => _known[baseUrl] ?? everything;

  /// Forgets every answer, as when the app is pointed at another agent.
  static void forgetAll() {
    _known.clear();
    _asking.clear();
  }

  static Future<CoreInfoResponse> _askInfo(String baseUrl) async {
    final core = CoreService(baseUrl: baseUrl);
    try {
      return await core.getInfo();
    } finally {
      core.dispose();
    }
  }
}
