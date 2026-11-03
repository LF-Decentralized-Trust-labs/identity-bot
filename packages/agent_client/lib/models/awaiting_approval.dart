/// The answer to `GET /api/grants/awaiting-approval`: what waits for a grant,
/// and for what (ADR-044).
///
/// One model for every app that shows it. Read leniently: a field the core
/// does not send is null or empty, never an error, so an older core still
/// reads.
class AwaitingApproval {
  /// Paired machines with no grant yet.
  final List<AwaitingMachine> machines;

  /// AI agents with no grant yet (listed by the add-on that makes them; empty
  /// where none does).
  final List<AwaitingAgent> agents;

  const AwaitingApproval({this.machines = const [], this.agents = const []});

  bool get isEmpty => machines.isEmpty && agents.isEmpty;

  factory AwaitingApproval.fromJson(Map<String, dynamic> json) =>
      AwaitingApproval(
        machines: _items(json['machines'], AwaitingMachine.fromJson),
        agents: _items(json['agents'], AwaitingAgent.fromJson),
      );
}

/// A paired machine whose grant waits.
class AwaitingMachine {
  final String controllerAid;
  final String publicKey;
  final String label;
  final String grade;

  /// What it waits for, in the core's own words.
  final String awaiting;

  /// The name of the device that holds the identity's key, when this waits for
  /// that device and a name is known; null otherwise. Never a guess.
  final String? keyDeviceName;

  const AwaitingMachine({
    required this.controllerAid,
    required this.publicKey,
    required this.label,
    required this.grade,
    required this.awaiting,
    this.keyDeviceName,
  });

  factory AwaitingMachine.fromJson(Map<String, dynamic> json) =>
      AwaitingMachine(
        controllerAid: _text(json['controller_aid']),
        publicKey: _text(json['public_key']),
        label: _text(json['label']),
        grade: _text(json['grade']),
        awaiting: _text(json['awaiting']),
        keyDeviceName: _name(json['key_device_name']),
      );
}

/// An AI agent whose grant waits.
class AwaitingAgent {
  final String assetId;
  final String name;
  final String agentAid;
  final List<String> capabilities;
  final String awaiting;

  /// As [AwaitingMachine.keyDeviceName].
  final String? keyDeviceName;

  const AwaitingAgent({
    required this.assetId,
    required this.name,
    required this.agentAid,
    this.capabilities = const [],
    required this.awaiting,
    this.keyDeviceName,
  });

  factory AwaitingAgent.fromJson(Map<String, dynamic> json) => AwaitingAgent(
        assetId: _text(json['asset_id']),
        name: _text(json['name']),
        agentAid: _text(json['agent_aid']),
        capabilities: [
          for (final c in (json['capabilities'] is List
              ? json['capabilities'] as List
              : const []))
            if (c is String) c
        ],
        awaiting: _text(json['awaiting']),
        keyDeviceName: _name(json['key_device_name']),
      );
}

List<T> _items<T>(Object? raw, T Function(Map<String, dynamic>) parse) => [
      if (raw is List)
        for (final e in raw)
          if (e is Map) parse(Map<String, dynamic>.from(e))
    ];

String _text(Object? v) => v is String ? v : '';

String? _name(Object? v) {
  if (v is! String) return null;
  final t = v.trim();
  return t.isEmpty ? null : t;
}
