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

  /// Grants removed here that the published key log still shows
  /// (`grants_withdrawing`): each has `credential`, `holder`, `kind`,
  /// `withdrawal` and `detail`.
  final List<Map<String, dynamic>> grantsWithdrawing;

  /// Places of this identity's key-log events written without its key
  /// (`key_log_unsigned_events`).
  final List<int> keyLogUnsignedEvents;

  /// What to do about them, in the core's words (`key_log_detail`).
  final String keyLogDetail;

  /// Interactions whose anchored events are not held here
  /// (`key_log_anchors_not_held`): each has `interaction` and `anchors`.
  final List<Map<String, dynamic>> keyLogAnchorsNotHeld;

  /// Why that list could not be read (`key_log_anchors_not_held_unreadable`);
  /// empty when it could.
  final String keyLogAnchorsNotHeldUnreadable;

  const AwaitingApproval({
    this.machines = const [],
    this.agents = const [],
    this.grantsWithdrawing = const [],
    this.keyLogUnsignedEvents = const [],
    this.keyLogDetail = '',
    this.keyLogAnchorsNotHeld = const [],
    this.keyLogAnchorsNotHeldUnreadable = '',
  });

  bool get isEmpty =>
      machines.isEmpty &&
      agents.isEmpty &&
      grantsWithdrawing.isEmpty &&
      keyLogUnsignedEvents.isEmpty &&
      keyLogAnchorsNotHeld.isEmpty &&
      keyLogAnchorsNotHeldUnreadable.isEmpty;

  factory AwaitingApproval.fromJson(Map<String, dynamic> json) =>
      AwaitingApproval(
        machines: _items(json['machines'], AwaitingMachine.fromJson),
        agents: _items(json['agents'], AwaitingAgent.fromJson),
        grantsWithdrawing: _items(json['grants_withdrawing'], (m) => m),
        keyLogUnsignedEvents: [
          for (final n in (json['key_log_unsigned_events'] is List
              ? json['key_log_unsigned_events'] as List
              : const []))
            if (n is num) n.toInt()
        ],
        keyLogDetail: _text(json['key_log_detail']),
        keyLogAnchorsNotHeld:
            _items(json['key_log_anchors_not_held'], (m) => m),
        keyLogAnchorsNotHeldUnreadable:
            _text(json['key_log_anchors_not_held_unreadable']),
      );
}

/// A paired machine whose grant waits.
class AwaitingMachine {
  final String controllerAid;
  final String publicKey;
  final String label;
  final String grade;

  /// What it waits for, in the core's own words. For people: do not compare it,
  /// use [waitingForKeyDevice].
  final String awaiting;

  /// True while it waits for the device that holds the identity's key,
  /// including after that device refused it or it expired (`waiting_for_key_device`).
  final bool waitingForKeyDevice;

  /// The name of the device that holds the identity's key, when this waits for
  /// that device and a name is known; null otherwise. Never a guess.
  final String? keyDeviceName;

  /// When the machine was paired and asked for a grant (`granted_at`); null
  /// where absent or unreadable.
  final DateTime? grantedAt;

  /// Whether the machine's row is live now (`live`), and if not, why
  /// (`why_not`).
  final bool live;
  final String whyNot;

  /// When the grant ends (`expires_at`); null for one that does not.
  final DateTime? expiresAt;

  /// The identity or device that signs (`signer`), and the grant credential
  /// (`credential`, or the core's words that it is pending); empty if none.
  final String signer;
  final String credential;

  const AwaitingMachine({
    required this.controllerAid,
    required this.publicKey,
    required this.label,
    required this.grade,
    required this.awaiting,
    this.waitingForKeyDevice = false,
    this.keyDeviceName,
    this.grantedAt,
    this.live = false,
    this.whyNot = '',
    this.expiresAt,
    this.signer = '',
    this.credential = '',
  });

  factory AwaitingMachine.fromJson(Map<String, dynamic> json) =>
      AwaitingMachine(
        controllerAid: _text(json['controller_aid']),
        publicKey: _text(json['public_key']),
        label: _text(json['label']),
        grade: _text(json['grade']),
        awaiting: _text(json['awaiting']),
        waitingForKeyDevice: json['waiting_for_key_device'] == true,
        keyDeviceName: _name(json['key_device_name']),
        grantedAt: _time(json['granted_at']),
        live: json['live'] == true,
        whyNot: _text(json['why_not']),
        expiresAt: _time(json['expires_at']),
        signer: _text(json['signer']),
        credential: _text(json['credential']),
      );
}

/// An AI agent whose grant waits.
class AwaitingAgent {
  final String assetId;
  final String name;
  final String agentAid;
  final List<String> capabilities;

  /// What the agent may touch (`resource_constraints`), as the core sends it.
  final Object? resourceConstraints;
  final String awaiting;

  /// As [AwaitingMachine.waitingForKeyDevice].
  final bool waitingForKeyDevice;

  /// As [AwaitingMachine.keyDeviceName].
  final String? keyDeviceName;

  const AwaitingAgent({
    required this.assetId,
    required this.name,
    required this.agentAid,
    this.capabilities = const [],
    this.resourceConstraints,
    required this.awaiting,
    this.waitingForKeyDevice = false,
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
        resourceConstraints: json['resource_constraints'],
        awaiting: _text(json['awaiting']),
        waitingForKeyDevice: json['waiting_for_key_device'] == true,
        keyDeviceName: _name(json['key_device_name']),
      );
}

List<T> _items<T>(Object? raw, T Function(Map<String, dynamic>) parse) => [
      if (raw is List)
        for (final e in raw)
          if (e is Map) parse(Map<String, dynamic>.from(e))
    ];

DateTime? _time(Object? v) => v is String ? DateTime.tryParse(v) : null;

String _text(Object? v) => v is String ? v : '';

String? _name(Object? v) {
  if (v is! String) return null;
  final t = v.trim();
  return t.isEmpty ? null : t;
}
