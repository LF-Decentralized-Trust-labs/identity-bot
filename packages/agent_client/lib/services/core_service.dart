import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:http/http.dart' as http;

import 'package:crypto/crypto.dart';

import 'owner_signing_client.dart';
import 'browser_session_client.dart';
import '../config/agent_config.dart';

class HealthResponse {
  final String status;
  final String agent;
  final String version;
  final String uptime;
  final String timestamp;
  final String mode;

  HealthResponse({
    required this.status,
    required this.agent,
    required this.version,
    required this.uptime,
    required this.timestamp,
    required this.mode,
  });

  factory HealthResponse.fromJson(Map<String, dynamic> json) {
    return HealthResponse(
      status: json['status'] ?? 'unknown',
      agent: json['agent'] ?? 'unknown',
      version: json['version'] ?? '0.0.0',
      uptime: json['uptime'] ?? '0s',
      timestamp: json['timestamp'] ?? '',
      mode: json['mode'] ?? 'unknown',
    );
  }

  bool get isActive => status == 'active';
}

class CoreInfoResponse {
  final String name;
  final String description;
  final String version;
  final String phase;
  final List<String> capabilities;

  CoreInfoResponse({
    required this.name,
    required this.description,
    required this.version,
    required this.phase,
    required this.capabilities,
  });

  factory CoreInfoResponse.fromJson(Map<String, dynamic> json) {
    return CoreInfoResponse(
      name: json['name'] ?? '',
      description: json['description'] ?? '',
      version: json['version'] ?? '',
      phase: json['phase'] ?? '',
      capabilities: List<String>.from(json['capabilities'] ?? []),
    );
  }
}

class IdentityResponse {
  final bool initialized;
  final String? aid;
  final String? publicKey;
  final String? nextKeyDigest;
  final String? created;
  final int? eventCount;

  IdentityResponse({
    required this.initialized,
    this.aid,
    this.publicKey,
    this.nextKeyDigest,
    this.created,
    this.eventCount,
  });

  factory IdentityResponse.fromJson(Map<String, dynamic> json) {
    return IdentityResponse(
      initialized: json['initialized'] ?? false,
      aid: json['aid'],
      publicKey: json['public_key'],
      nextKeyDigest: json['next_key_digest'],
      created: json['created'],
      eventCount: json['event_count'],
    );
  }
}

class InceptionResponse {
  final String aid;
  final String publicKey;
  final String created;

  /// Whether the founding event actually carries a commitment to a
  /// post-quantum key the identity can rotate to.
  ///
  /// Read rather than assumed. The commitment is best-effort in the core — an
  /// agent with no root seed to derive from founds the identity anyway, with a
  /// single classical commitment — so a screen that says the identity is ready
  /// for a post-quantum key must ask, or it will eventually say so when it is
  /// not true.
  ///
  /// Defaults to false against a core that predates the field, which is the
  /// safe direction: an older core did not make the commitment.
  final bool postQuantumCommitted;

  InceptionResponse({
    required this.aid,
    required this.publicKey,
    required this.created,
    this.postQuantumCommitted = false,
  });

  factory InceptionResponse.fromJson(Map<String, dynamic> json) {
    return InceptionResponse(
      aid: json['aid'] ?? '',
      publicKey: json['public_key'] ?? '',
      created: json['created'] ?? '',
      postQuantumCommitted: json['post_quantum_committed'] == true,
    );
  }
}

class OobiResponse {
  final String oobiUrl;
  final String aid;
  final String publicKey;
  final String baseUrl;
  final bool tunnelActive;
  final String tunnelProvider;
  final String tunnelError;
  final String endpointUrl;
  final String endpointSource;

  OobiResponse({
    required this.oobiUrl,
    required this.aid,
    required this.publicKey,
    required this.baseUrl,
    this.tunnelActive = false,
    this.tunnelProvider = '',
    this.tunnelError = '',
    this.endpointUrl = '',
    this.endpointSource = '',
  });

  factory OobiResponse.fromJson(Map<String, dynamic> json) {
    return OobiResponse(
      oobiUrl: json['oobi_url'] ?? '',
      aid: json['aid'] ?? '',
      publicKey: json['public_key'] ?? '',
      baseUrl: json['base_url'] ?? '',
      tunnelActive: json['tunnel_active'] == true,
      tunnelProvider: json['tunnel_provider'] ?? '',
      tunnelError: json['tunnel_error'] ?? '',
      endpointUrl: json['endpoint_url'] ?? '',
      endpointSource: json['endpoint_source'] ?? '',
    );
  }
}

class JCardResponse {
  final String fullName;
  final String familyName;
  final String givenName;
  final String org;
  final String title;
  final String email;
  final String tel;
  final String note;
  final String uid;
  final String xKeriAid;
  final String xKeriOobi;
  final String xKeriRole;

  JCardResponse({
    required this.fullName,
    this.familyName = '',
    this.givenName = '',
    this.org = '',
    this.title = '',
    this.email = '',
    this.tel = '',
    this.note = '',
    this.uid = '',
    this.xKeriAid = '',
    this.xKeriOobi = '',
    this.xKeriRole = '',
  });

  factory JCardResponse.fromJson(Map<String, dynamic> json) {
    return JCardResponse(
      fullName: json['fn'] ?? '',
      familyName: json['family_name'] ?? '',
      givenName: json['given_name'] ?? '',
      org: json['org'] ?? '',
      title: json['title'] ?? '',
      email: json['email'] ?? '',
      tel: json['tel'] ?? '',
      note: json['note'] ?? '',
      uid: json['uid'] ?? '',
      xKeriAid: json['x-keri-aid'] ?? '',
      xKeriOobi: json['x-keri-oobi'] ?? '',
      xKeriRole: json['x-keri-role'] ?? '',
    );
  }
}

class ProfileResponse {
  final String fullName;
  final String familyName;
  final String givenName;
  final String org;
  final String title;
  final String email;
  final String tel;
  final String note;
  final String photo;
  final String uid;
  // Organization-specific fields (ADR-020)
  final String entityType;   // "individual" | "organization"
  final String orgName;
  final String orgType;      // e.g. "school", "business", "healthcare"
  final String jurisdiction; // free-text for now

  ProfileResponse({
    this.fullName = '',
    this.familyName = '',
    this.givenName = '',
    this.org = '',
    this.title = '',
    this.email = '',
    this.tel = '',
    this.note = '',
    this.photo = '',
    this.uid = '',
    this.entityType = '',
    this.orgName = '',
    this.orgType = '',
    this.jurisdiction = '',
  });

  factory ProfileResponse.fromJson(Map<String, dynamic> json) {
    return ProfileResponse(
      fullName: json['fn'] ?? '',
      familyName: json['family_name'] ?? '',
      givenName: json['given_name'] ?? '',
      org: json['org'] ?? '',
      title: json['title'] ?? '',
      email: json['email'] ?? '',
      tel: json['tel'] ?? '',
      note: json['note'] ?? '',
      photo: json['photo'] ?? '',
      uid: json['uid'] ?? '',
      entityType: json['entity_type'] ?? '',
      orgName: json['org_name'] ?? '',
      orgType: json['org_type'] ?? '',
      jurisdiction: json['jurisdiction'] ?? '',
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'fn': fullName,
      'family_name': familyName,
      'given_name': givenName,
      'org': org,
      'title': title,
      'email': email,
      'tel': tel,
      'note': note,
      'photo': photo,
      'uid': uid,
      if (entityType.isNotEmpty) 'entity_type': entityType,
      if (orgName.isNotEmpty) 'org_name': orgName,
      if (orgType.isNotEmpty) 'org_type': orgType,
      if (jurisdiction.isNotEmpty) 'jurisdiction': jurisdiction,
    };
  }
}

class ContactResponse {
  final String aid;
  final String alias;
  final String publicKey;
  final String oobiUrl;
  final bool verified;
  final String discoveredAt;
  final String status;

  // contactType: Identity Agent contact category (user-facing).
  // Values: "general" | "trusted" | "professional"
  final String contactType;

  // isWitness: KERI protocol flag — auto-managed by the backend.
  // True when this contact's Identity Agent is witnessing our key events.
  final bool isWitness;

  final JCardResponse? jcard;
  final String photo;

  ContactResponse({
    required this.aid,
    required this.alias,
    required this.publicKey,
    required this.oobiUrl,
    required this.verified,
    required this.discoveredAt,
    this.status = '',
    this.contactType = 'general',
    this.isWitness = false,
    this.jcard,
    this.photo = '',
  });

  bool get isAccepted => status == 'accepted';
  bool get isPendingInbound => status == 'pending_inbound';
  bool get isPendingOutbound => status == 'pending_outbound';
  bool get isRejected => status == 'rejected';

  String get displayName {
    if (jcard != null && jcard!.fullName.isNotEmpty) return jcard!.fullName;
    if (alias.isNotEmpty) return alias;
    return aid.length > 12 ? '${aid.substring(0, 12)}...' : aid;
  }

  factory ContactResponse.fromJson(Map<String, dynamic> json) {
    return ContactResponse(
      aid: json['aid'] ?? '',
      alias: json['alias'] ?? '',
      publicKey: json['public_key'] ?? '',
      oobiUrl: json['oobi_url'] ?? '',
      verified: json['verified'] ?? false,
      discoveredAt: json['discovered_at'] ?? '',
      status: json['status'] ?? '',
      contactType: json['contact_type'] ?? 'general',
      isWitness: json['is_witness'] ?? false,
      jcard: json['jcard'] != null ? JCardResponse.fromJson(json['jcard']) : null,
      photo: json['photo'] ?? '',
    );
  }
}

class ContactsListResponse {
  final List<ContactResponse> contacts;
  final int count;

  ContactsListResponse({required this.contacts, required this.count});

  factory ContactsListResponse.fromJson(Map<String, dynamic> json) {
    return ContactsListResponse(
      contacts: (json['contacts'] as List<dynamic>?)?.map((c) => ContactResponse.fromJson(c)).toList() ?? [],
      count: json['count'] ?? 0,
    );
  }
}

/// Something another agent told this one.
///
/// Distinct from the other three things on the alerts screen, which are all
/// requests for the user's approval. A notification is not asking for anything
/// — it is telling them something, possibly something with a deadline.
class NotificationRecord {
  final String id;
  final String fromAid;
  final String kind;

  /// info | warning | critical. Decided by the sender, because only the sender
  /// knows whether this is a receipt or a deadline.
  final String severity;
  final String title;
  final String body;

  /// unread | read | dismissed.
  final String status;
  final String receivedAt;

  const NotificationRecord({
    required this.id,
    this.fromAid = '',
    this.kind = '',
    this.severity = 'info',
    this.title = '',
    this.body = '',
    this.status = 'unread',
    this.receivedAt = '',
  });

  bool get isUnread => status == 'unread';
  bool get isCritical => severity == 'critical';

  factory NotificationRecord.fromJson(Map<String, dynamic> json) {
    return NotificationRecord(
      id: json['id'] ?? '',
      fromAid: json['from_aid'] ?? '',
      kind: json['kind'] ?? '',
      severity: json['severity'] ?? 'info',
      title: json['title'] ?? '',
      body: json['body'] ?? '',
      status: json['status'] ?? 'unread',
      receivedAt: json['received_at'] ?? '',
    );
  }
}

class AlertsResponse {
  final List<ContactResponse> alerts;
  final List<PendingRequestResponse> pendingRequests;
  final List<CredentialRecord> pendingCredentials;

  /// Unread notifications. Defaulted rather than required, so an older backend
  /// that does not send the key still constructs.
  final List<NotificationRecord> notifications;

  /// The contacts count, not a total — kept with its original meaning because
  /// changing it would silently alter every caller that passes it on. Callers
  /// wanting a total use [totalCount].
  final int count;

  AlertsResponse({
    required this.alerts,
    this.pendingRequests = const [],
    this.pendingCredentials = const [],
    this.notifications = const [],
    required this.count,
  });

  int get totalCount =>
      alerts.length + pendingRequests.length + pendingCredentials.length + notifications.length;

  factory AlertsResponse.fromJson(Map<String, dynamic> json) {
    return AlertsResponse(
      alerts: (json['alerts'] as List<dynamic>?)?.map((c) => ContactResponse.fromJson(c)).toList() ?? [],
      pendingRequests: (json['pending_requests'] as List<dynamic>?)?.map((p) => PendingRequestResponse.fromJson(p)).toList() ?? [],
      pendingCredentials: (json['pending_credentials'] as List<dynamic>?)?.map((c) => CredentialRecord.fromJson(c as Map<String, dynamic>)).toList() ?? [],
      notifications: (json['notifications'] as List<dynamic>?)?.map((n) => NotificationRecord.fromJson(n as Map<String, dynamic>)).toList() ?? [],
      count: json['count'] ?? 0,
    );
  }
}

class PendingRequestResponse {
  final String aid;
  final String oobiUrl;
  final String alias;
  final String errorReason;
  final String receivedAt;
  final String expiresAt;

  PendingRequestResponse({
    required this.aid,
    required this.oobiUrl,
    this.alias = '',
    required this.errorReason,
    required this.receivedAt,
    this.expiresAt = '',
  });

  String get displayName {
    if (alias.isNotEmpty) return alias;
    return aid.length > 12 ? '${aid.substring(0, 12)}...' : aid;
  }

  factory PendingRequestResponse.fromJson(Map<String, dynamic> json) {
    return PendingRequestResponse(
      aid: json['aid'] ?? '',
      oobiUrl: json['oobi_url'] ?? '',
      alias: json['alias'] ?? '',
      errorReason: json['error_reason'] ?? '',
      receivedAt: json['received_at'] ?? '',
      expiresAt: json['expires_at'] ?? '',
    );
  }
}

class TaskRecord {
  final String id;
  final String type;
  final String status; // pending | in_progress | completed | failed
  final String contactAid;
  final int progress; // 0–100
  final String detail;
  final String createdAt;
  final String updatedAt;

  TaskRecord({
    required this.id,
    required this.type,
    this.status = 'pending',
    this.contactAid = '',
    this.progress = 0,
    this.detail = '',
    this.createdAt = '',
    this.updatedAt = '',
  });

  factory TaskRecord.fromJson(Map<String, dynamic> json) {
    return TaskRecord(
      id: json['id'] ?? '',
      type: json['type'] ?? '',
      status: json['status'] ?? 'pending',
      contactAid: json['contact_aid'] ?? '',
      progress: json['progress'] ?? 0,
      detail: json['detail'] ?? '',
      createdAt: json['created_at'] ?? '',
      updatedAt: json['updated_at'] ?? '',
    );
  }
}

class TasksResponse {
  final List<TaskRecord> tasks;
  final int count;

  TasksResponse({required this.tasks, required this.count});

  factory TasksResponse.fromJson(Map<String, dynamic> json) {
    return TasksResponse(
      tasks: (json['tasks'] as List<dynamic>?)?.map((t) => TaskRecord.fromJson(t)).toList() ?? [],
      count: json['count'] ?? 0,
    );
  }
}

class ResolvedContactResponse {
  final bool resolved;
  final String aid;
  final String publicKey;
  final String alias;
  final String oobiUrl;
  final int eventCount;
  final String created;
  final bool kelVerified;
  final JCardResponse? jcard;
  final String photo;

  ResolvedContactResponse({
    required this.resolved,
    required this.aid,
    required this.publicKey,
    this.alias = '',
    required this.oobiUrl,
    this.eventCount = 0,
    this.created = '',
    this.kelVerified = false,
    this.jcard,
    this.photo = '',
  });

  String get displayName {
    if (jcard != null && jcard!.fullName.isNotEmpty) return jcard!.fullName;
    if (alias.isNotEmpty) return alias;
    return aid.length > 12 ? '${aid.substring(0, 12)}...' : aid;
  }

  factory ResolvedContactResponse.fromJson(Map<String, dynamic> json) {
    return ResolvedContactResponse(
      resolved: json['resolved'] ?? false,
      aid: json['aid'] ?? '',
      publicKey: json['public_key'] ?? '',
      alias: json['alias'] ?? '',
      oobiUrl: json['oobi_url'] ?? '',
      eventCount: json['event_count'] ?? 0,
      created: json['created'] ?? '',
      kelVerified: json['kel_verified'] ?? false,
      jcard: json['jcard'] != null ? JCardResponse.fromJson(json['jcard']) : null,
      photo: json['photo'] ?? '',
    );
  }
}

enum CoreConnectionState {
  disconnected,
  connecting,
  connected,
  error,
}

/// One label→value row from a scan preview (a requested disclosure, a reference
/// field, …). Mirrors the Go `PreviewDetail`.
class ScanPreviewDetail {
  final String label;
  final String value;

  const ScanPreviewDetail({required this.label, this.value = ''});

  factory ScanPreviewDetail.fromJson(Map<String, dynamic> json) =>
      ScanPreviewDetail(
        label: json['label']?.toString() ?? '',
        value: json['value']?.toString() ?? '',
      );
}

/// The type-agnostic consent preview returned by `POST /api/scan/decode`. The
/// scanner is a dumb router: the backend fetches the Ask, reads its action `t`,
/// and returns this generic preview from the registered handler (login,
/// add-contact, present/receive-credential, …). One consent screen renders every
/// action type. Mirrors the Go `GenericPreview`.
class ScanDecodeResult {
  final int t; // action discriminator (1=login, 2=add_contact, …)
  final String action; // "login" | "add_contact" | …
  final String title; // "Sign-in request", "Contact request"
  final String subtitle; // audience / who is asking
  final String counterparty; // AID or display name of the asker
  final List<ScanPreviewDetail> details; // fields being shared, reference rows
  final List<String> tierOptions; // e.g. add-contact: general/trusted/professional
  final String defaultTier;
  final String warning; // amber caution line, if any

  /// Digest of the exact Ask bytes this preview describes. Pass it back to
  /// [CoreService.scanExecute] so the core can prove it is acting on the
  /// request the user actually approved.
  final String askDigest;

  const ScanDecodeResult({
    required this.t,
    required this.action,
    this.title = '',
    this.subtitle = '',
    this.counterparty = '',
    this.details = const [],
    this.tierOptions = const [],
    this.defaultTier = '',
    this.warning = '',
    this.askDigest = '',
  });

  factory ScanDecodeResult.fromJson(Map<String, dynamic> json) {
    return ScanDecodeResult(
      t: (json['t'] as num?)?.toInt() ?? 0,
      action: json['action']?.toString() ?? '',
      title: json['title']?.toString() ?? '',
      subtitle: json['subtitle']?.toString() ?? '',
      counterparty: json['counterparty']?.toString() ?? '',
      details: (json['details'] as List<dynamic>?)
              ?.map((e) => ScanPreviewDetail.fromJson(e as Map<String, dynamic>))
              .toList() ??
          const [],
      tierOptions: (json['tier_options'] as List<dynamic>?)
              ?.map((e) => e.toString())
              .toList() ??
          const [],
      defaultTier: json['default_tier']?.toString() ?? '',
      warning: json['warning']?.toString() ?? '',
      askDigest: json['ask_digest']?.toString() ?? '',
    );
  }
}

class CoreService {
  final String baseUrl;
  final http.Client _client;

  /// Carries a browser session, when there is one. Null on a client that signs
  /// with the owner key instead — a caller holding the key has no use for a
  /// session, and giving it one would mean two ways to prove the same thing.
  final BrowserSessionClient? _session;

  /// Builds a client for an agent.
  ///
  /// [ownerSeed] is what lets this talk to an agent running on hardware you
  /// rent. There, you are remote by definition, so every owner endpoint answers
  /// "sign this request with the owner key" — and without a seed to sign with,
  /// a hosted agent is correctly locked and unusable by the person who owns it.
  ///
  /// Left out, requests go unsigned. That is right for an agent on the machine
  /// you are sitting at, which recognises a local request as its owner's, and
  /// it keeps every existing caller working unchanged.
  ///
  /// Signing is applied at the transport rather than per request, so a call
  /// added tomorrow is signed without anybody remembering to sign it.
  /// A key beats a session. Where the caller can sign it signs; only a client
  /// that cannot — a browser — carries a session instead. Wiring both would
  /// leave two answers to "who is this" and the agent choosing between them.
  ///
  /// A factory, because the session client and the request client must be the
  /// SAME object: adopting a token has to change the client that actually sends
  /// requests, and an initialiser list cannot build one field from another.
  factory CoreService({
    String? baseUrl,
    Future<Uint8List?> Function()? ownerSeed,
    String? ownerAid,
  }) {
    final origin = baseUrl ?? AgentConfig.coreBaseUrl;
    if (ownerSeed == null) {
      final session = BrowserSessionClient(agentOrigin: origin);
      return CoreService._(origin, session, session);
    }
    return CoreService._(
      origin,
      OwnerSigningClient(
          agentOrigin: origin, ownerSeed: ownerSeed, ownerAid: ownerAid),
      null,
    );
  }

  CoreService._(this.baseUrl, this._client, this._session);

  Future<HealthResponse> getHealth() async {
    final response = await _client.get(
      Uri.parse('$baseUrl/api/health'),
    );

    if (response.statusCode == 200) {
      return HealthResponse.fromJson(jsonDecode(response.body));
    } else {
      throw Exception('Health check failed: ${response.statusCode}');
    }
  }

  Future<CoreInfoResponse> getInfo() async {
    final response = await _client.get(
      Uri.parse('$baseUrl/api/info'),
    );

    if (response.statusCode == 200) {
      return CoreInfoResponse.fromJson(jsonDecode(response.body));
    } else {
      throw Exception('Info request failed: ${response.statusCode}');
    }
  }

  Future<IdentityResponse> getIdentity() async {
    final response = await _client.get(
      Uri.parse('$baseUrl/api/identity'),
    );

    if (response.statusCode == 200) {
      return IdentityResponse.fromJson(jsonDecode(response.body));
    }
    // A refusal is not the same answer as "there is nothing here yet", and
    // callers were unable to tell them apart.
    //
    // A fresh agent you are entitled to set up answers 200 with initialized
    // false. An agent that exists and is not yours answers 403. Both arrived as
    // the same exception, and every caller treated it as the first — so somebody
    // opening an agent that was not theirs was shown "Create my identity", and
    // the button then failed with a refusal they had been given no reason to
    // expect.
    if (response.statusCode == 401 || response.statusCode == 403) {
      throw const AgentNotYoursException();
    }
    throw Exception('Identity request failed: ${response.statusCode}');
  }

  /// Creates this agent's identity.
  ///
  /// [ownerAid] names who the identity answers to, and is written into the
  /// event that creates it. Supply it for anything that answers to somebody
  /// else — an organisation answers to its founders — because an identity
  /// founded without an owner can never acquire one afterwards. The remedy for
  /// getting this wrong is to found it again, so it is worth getting right.
  ///
  /// Left out for a person's own agent, whose identity is delegated and whose
  /// delegator is already named in its event.
  Future<InceptionResponse> createInception({
    required String publicKey,
    required String nextPublicKey,
    String? ownerAid,
  }) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/inception'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'public_key': publicKey,
        'next_public_key': nextPublicKey,
        if (ownerAid != null && ownerAid.isNotEmpty) 'owner_aid': ownerAid,
      }),
    );

    if (response.statusCode == 201) {
      return InceptionResponse.fromJson(jsonDecode(response.body));
    } else {
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'Inception failed: ${response.statusCode}');
    }
  }

  Future<OobiResponse> getOobi({String? action}) async {
    final uri = Uri.parse('$baseUrl/api/oobi').replace(
      queryParameters: action != null ? {'action': action} : null,
    );
    final response = await _client.get(uri);
    if (response.statusCode == 200) {
      return OobiResponse.fromJson(jsonDecode(response.body));
    } else {
      throw Exception('OOBI request failed: ${response.statusCode}');
    }
  }

  /// Asks a machine this identity owns, through the local agent.
  ///
  /// A remote machine cannot tell who is calling from the connection alone,
  /// and it should not try: the answer is that the local agent — which holds
  /// this identity's key and already has a relationship with that machine —
  /// seals the request, and the machine replays it through its own router as
  /// though it had arrived locally.
  ///
  /// So an app needs no cryptography of its own. It states the request it
  /// wants made and which machine to make it to, and everything else happens
  /// one process away on the same device.
  ///
  /// This is deliberately the ONLY way this client talks to a machine it does
  /// not run on. A second path — signing a plain request and sending it
  /// directly — would be a parallel way of saying the same thing, and the two
  /// would drift apart in what they permit.
  Future<http.Response> sealedRequest({
    required String toAid,
    required String path,
    /// Which identity of this owner's is speaking.
    ///
    /// A machine is adopted by a PAIRWISE identity, and it only recognises that
    /// one as its owner — so a request sent as the root would be refused by a
    /// machine that has never heard of it. Left empty, the agent falls back to
    /// its own identity, which is right for anything adopted before this and
    /// wrong for everything after.
    String? fromAid,
    String method = 'GET',
    List<int>? body,
  }) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/sealed/send'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'to_aid': toAid,
        if (fromAid != null && fromAid.isNotEmpty) 'from_aid': fromAid,
        'method': method,
        'path': path,
        if (body != null) 'body_b64': base64Encode(body),
      }),
    );
    if (response.statusCode != 200) {
      // The local agent refused to send it. Never retried in the clear: a
      // fallback that quietly works is one anybody can force by breaking this
      // path, which would undo the whole point of it.
      throw Exception(
          'Could not reach that machine privately: ${response.statusCode}');
    }
    final envelope = jsonDecode(response.body) as Map<String, dynamic>;
    final bodyB64 = (envelope['body_b64'] ?? '') as String;
    return http.Response(
      bodyB64.isEmpty ? '' : utf8.decode(base64Decode(bodyB64)),
      (envelope['status'] ?? 502) as int,
    );
  }

  /// What an agent's trust rests on, as one document.
  ///
  /// The facts live in three places in the core because they answer three
  /// different questions there. This is the one call a screen makes.
  ///
  /// Pass [ofAgentAid] to ask a machine this identity owns rather than the
  /// agent on this device. Same document either way, so one screen renders
  /// both — which matters, because a person comparing their laptop with their
  /// black box should not be reading two different reports.
  Future<AttestationLineageDto> attestationLineage({
    String? ofAgentAid,
    String? asOwnerAid,
  }) async {
    const path = '/api/security/lineage';
    final response = ofAgentAid == null
        ? await _client.get(Uri.parse('$baseUrl$path'))
        : await sealedRequest(
            toAid: ofAgentAid, path: path, fromAid: asOwnerAid);
    if (response.statusCode != 200) {
      throw Exception(
          'Could not read this agent\'s attestation: ${response.statusCode}');
    }
    return AttestationLineageDto.fromJson(
        jsonDecode(response.body) as Map<String, dynamic>);
  }

  /// The machines this identity has adopted.
  ///
  /// An agent that has adopted nothing answers with an empty list, which is an
  /// answer rather than a failure — a person who owns no machines yet should
  /// see "none yet", not an error, and the caller cannot tell the two apart if
  /// this throws for both.
  Future<List<AdoptedAgent>> listAgents() async {
    final response = await _client.get(Uri.parse('$baseUrl/api/agents'));
    if (response.statusCode != 200) {
      throw Exception('Could not list this identity\'s machines: ${response.statusCode}');
    }
    final body = jsonDecode(response.body) as Map<String, dynamic>;
    final raw = (body['agents'] as List?) ?? const [];
    return raw
        .whereType<Map<String, dynamic>>()
        .map(AdoptedAgent.fromJson)
        .toList(growable: false);
  }

  /// Stops listing a machine. Does NOT revoke its delegation — that was issued
  /// in a published key event log and the machine can still sign under it.
  Future<void> forgetAgent(String aid) async {
    final response = await _client.delete(Uri.parse('$baseUrl/api/agents/$aid'));
    if (response.statusCode != 200) {
      throw Exception('Could not forget that machine: ${response.statusCode}');
    }
  }

  /// Gives a machine a name its owner chose.
  Future<void> labelAgent(String aid, String label) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/agents/$aid/label'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'label': label}),
    );
    if (response.statusCode != 200) {
      throw Exception('Could not rename that machine: ${response.statusCode}');
    }
  }

  Future<ContactsListResponse> getContacts() async {
    final response = await _client.get(Uri.parse('$baseUrl/api/contacts'));
    if (response.statusCode == 200) {
      return ContactsListResponse.fromJson(jsonDecode(response.body));
    } else {
      throw Exception('Contacts request failed: ${response.statusCode}');
    }
  }

  Future<ResolvedContactResponse> resolveOobiContact({required String oobiUrl}) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/contacts/resolve'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'oobi_url': oobiUrl}),
    );
    if (response.statusCode == 200) {
      return ResolvedContactResponse.fromJson(jsonDecode(response.body));
    } else {
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'OOBI resolution failed: ${response.statusCode}');
    }
  }

  Future<ContactResponse> addContact({required String oobiUrl, String? alias, bool trusted = false}) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/contacts'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'oobi_url': oobiUrl, if (alias != null) 'alias': alias, 'trusted': trusted}),
    );
    if (response.statusCode == 201) {
      return ContactResponse.fromJson(jsonDecode(response.body));
    } else {
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'Add contact failed: ${response.statusCode}');
    }
  }

  Future<void> deleteContact(String aid) async {
    final response = await _client.delete(Uri.parse('$baseUrl/api/contacts/$aid'));
    if (response.statusCode != 204) {
      throw Exception('Delete contact failed: ${response.statusCode}');
    }
  }

  Future<ContactResponse> acceptContact(String aid, {String contactType = 'general'}) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/contacts/$aid/accept'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'contact_type': contactType}),
    );
    if (response.statusCode == 200) {
      return ContactResponse.fromJson(jsonDecode(response.body));
    } else {
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'Accept contact failed: ${response.statusCode}');
    }
  }

  Future<void> rejectContact(String aid) async {
    final response = await _client.post(Uri.parse('$baseUrl/api/contacts/$aid/reject'));
    if (response.statusCode != 200) {
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'Reject contact failed: ${response.statusCode}');
    }
  }

  Future<ContactResponse> updateContact(String aid, {String? contactType, String? alias}) async {
    final body = <String, dynamic>{};
    if (contactType != null) body['contact_type'] = contactType;
    if (alias != null) body['alias'] = alias;
    final response = await _client.put(
      Uri.parse('$baseUrl/api/contacts/$aid'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode(body),
    );
    if (response.statusCode == 200) {
      return ContactResponse.fromJson(jsonDecode(response.body));
    } else {
      final err = jsonDecode(response.body);
      throw Exception(err['error'] ?? 'Update contact failed: ${response.statusCode}');
    }
  }

  Future<TasksResponse> getTasks() async {
    final response = await _client.get(Uri.parse('$baseUrl/api/tasks'));
    if (response.statusCode == 200) {
      return TasksResponse.fromJson(jsonDecode(response.body));
    } else {
      throw Exception('Tasks request failed: ${response.statusCode}');
    }
  }

  Future<AlertsResponse> getAlerts() async {
    final response = await _client.get(Uri.parse('$baseUrl/api/alerts'));
    if (response.statusCode == 200) {
      return AlertsResponse.fromJson(jsonDecode(response.body));
    } else {
      throw Exception('Alerts request failed: ${response.statusCode}');
    }
  }

  /// Marks a notification read or dismissed.
  ///
  /// Read and dismissed are separate on purpose: having seen something urgent
  /// is not the same as having dealt with it.
  Future<void> setNotificationStatus(String id, String status) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/notifications/status'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'id': id, 'status': status}),
    );
    if (response.statusCode != 200) {
      throw Exception('Failed to update notification: ${response.statusCode}');
    }
  }

  Future<Map<String, dynamic>> getTunnelSettings() async {
    final response = await _client.get(Uri.parse('$baseUrl/api/settings/tunnel'));
    if (response.statusCode == 200) {
      return jsonDecode(response.body) as Map<String, dynamic>;
    } else {
      throw Exception('Failed to get tunnel settings: ${response.statusCode}');
    }
  }

  Future<({bool? available, bool hubError, String message, String debugUrl, int debugStatus, String debugBody})> checkGrapeIdName(String domain, String name) async {
    final domainParam = domain.isNotEmpty ? '&domain=${Uri.encodeComponent(domain)}' : '';
    final url = Uri.parse('$baseUrl/api/settings/tunnel/check-name?name=${Uri.encodeComponent(name)}$domainParam');
    final debugUrl = url.toString();

    try {
      final response = await _client.get(url);
      final rawBody = response.body.length > 500 ? '${response.body.substring(0, 500)}...' : response.body;

      if (response.statusCode == 200) {
        final data = jsonDecode(response.body) as Map<String, dynamic>;
        if (data['hub_error'] == true) {
          return (
            available: null,
            hubError: true,
            message: (data['message'] as String?) ?? 'Provider not responsive',
            debugUrl: debugUrl,
            debugStatus: response.statusCode,
            debugBody: rawBody,
          );
        }
        final isAvailable = data['available'] == true;
        return (
          available: isAvailable,
          hubError: false,
          message: '',
          debugUrl: debugUrl,
          debugStatus: response.statusCode,
          debugBody: rawBody,
        );
      }
      return (
        available: null,
        hubError: true,
        message: 'Go Core returned HTTP ${response.statusCode}',
        debugUrl: debugUrl,
        debugStatus: response.statusCode,
        debugBody: rawBody,
      );
    } catch (e) {
      return (
        available: null,
        hubError: true,
        message: 'Cannot reach local Go Core',
        debugUrl: debugUrl,
        debugStatus: 0,
        debugBody: 'Connection error: $e',
      );
    }
  }

  Future<({bool reachable, String reason})> checkGrapeIdHealth(String domain) async {
    final domainParam = domain.isNotEmpty ? '?domain=${Uri.encodeComponent(domain)}' : '';
    final url = Uri.parse('$baseUrl/api/settings/tunnel/grapeid-health$domainParam');
    try {
      final response = await _client.get(url);
      if (response.statusCode == 200) {
        final data = jsonDecode(response.body) as Map<String, dynamic>;
        return (reachable: data['reachable'] == true, reason: (data['reason'] as String?) ?? '');
      }
      return (reachable: false, reason: 'Provider not responsive');
    } catch (_) {
      return (reachable: false, reason: 'Provider not responsive');
    }
  }

  Future<Map<String, dynamic>> releaseTunnelName() async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/settings/tunnel/release-name'),
    );
    if (response.statusCode == 200) {
      return jsonDecode(response.body) as Map<String, dynamic>;
    } else {
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'Release failed: ${response.statusCode}');
    }
  }

  Future<Map<String, dynamic>> saveTunnelSettings({
    required String provider,
    String? ngrokAuthToken,
    String? cloudflareTunnelToken,
    String? tunnelDomain,
    String? tunnelExtension,
  }) async {
    final response = await _client.put(
      Uri.parse('$baseUrl/api/settings/tunnel'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'provider': provider,
        if (ngrokAuthToken != null) 'ngrok_auth_token': ngrokAuthToken,
        if (cloudflareTunnelToken != null) 'cloudflare_tunnel_token': cloudflareTunnelToken,
        if (tunnelDomain != null) 'tunnel_domain': tunnelDomain,
        if (tunnelExtension != null) 'tunnel_extension': tunnelExtension,
      }),
    );
    if (response.statusCode != 200) {
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'Save settings failed: ${response.statusCode}');
    }
    return jsonDecode(response.body) as Map<String, dynamic>;
  }

  Future<Map<String, dynamic>> getTunnelStatus() async {
    final response = await _client.get(Uri.parse('$baseUrl/api/tunnel/status'));
    if (response.statusCode == 200) {
      return jsonDecode(response.body) as Map<String, dynamic>;
    } else {
      throw Exception('Failed to get tunnel status: ${response.statusCode}');
    }
  }

  Future<Map<String, dynamic>> restartTunnel() async {
    final response = await _client.post(Uri.parse('$baseUrl/api/tunnel/restart'));
    if (response.statusCode == 200) {
      return jsonDecode(response.body) as Map<String, dynamic>;
    } else {
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'Tunnel restart failed: ${response.statusCode}');
    }
  }

  Future<void> deletePendingRequest(String aid) async {
    final response = await _client.delete(
      Uri.parse('$baseUrl/api/pending-requests/${Uri.encodeComponent(aid)}'),
    );
    if (response.statusCode != 200) {
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'Failed to delete pending request');
    }
  }

  Future<void> resetAll() async {
    final response = await _client.post(Uri.parse('$baseUrl/api/reset'));
    if (response.statusCode != 200) {
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'Failed to reset');
    }
  }

  Future<Map<String, dynamic>> getEndpoint() async {
    final response = await _client.get(Uri.parse('$baseUrl/api/endpoint'));
    if (response.statusCode == 200) {
      return jsonDecode(response.body) as Map<String, dynamic>;
    } else {
      throw Exception('Failed to get endpoint: ${response.statusCode}');
    }
  }

  Future<List<Map<String, dynamic>>> getActions() async {
    final response = await _client.get(Uri.parse('$baseUrl/api/actions'));
    if (response.statusCode == 200) {
      final body = jsonDecode(response.body) as Map<String, dynamic>;
      return List<Map<String, dynamic>>.from(body['actions'] ?? []);
    } else {
      throw Exception('Failed to get actions: ${response.statusCode}');
    }
  }

  Future<List<ShareAction>> getShareActions() async {
    final response = await _client.get(Uri.parse('$baseUrl/api/share-actions'));
    if (response.statusCode == 200) {
      final body = jsonDecode(response.body) as Map<String, dynamic>;
      final list = body['actions'] as List<dynamic>? ?? [];
      return list.map((e) => ShareAction.fromJson(e as Map<String, dynamic>)).toList();
    }
    throw Exception('Failed to get share actions: ${response.statusCode}');
  }

  Future<ShareAction> upsertShareAction(ShareAction action) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/share-actions'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode(action.toJson()),
    );
    if (response.statusCode == 201 || response.statusCode == 200) {
      return ShareAction.fromJson(jsonDecode(response.body) as Map<String, dynamic>);
    }
    throw Exception('Failed to save share action: ${response.statusCode}');
  }

  Future<ShareAction> updateShareAction(String id, ShareAction action) async {
    final response = await _client.put(
      Uri.parse('$baseUrl/api/share-actions/$id'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode(action.toJson()),
    );
    if (response.statusCode == 200) {
      return ShareAction.fromJson(jsonDecode(response.body) as Map<String, dynamic>);
    }
    throw Exception('Failed to update share action: ${response.statusCode}');
  }

  Future<void> deleteShareAction(String id) async {
    final response = await _client.delete(Uri.parse('$baseUrl/api/share-actions/$id'));
    if (response.statusCode != 204) {
      throw Exception('Failed to delete share action: ${response.statusCode}');
    }
  }

  Future<ProfileResponse> getProfile() async {
    final response = await _client.get(Uri.parse('$baseUrl/api/profile'));
    if (response.statusCode == 200) {
      return ProfileResponse.fromJson(jsonDecode(response.body));
    } else {
      throw Exception('Failed to get profile: ${response.statusCode}');
    }
  }

  /// Asks the agent for a freshly generated avatar without saving it, so the
  /// user can look at it and ask for another. Generation happens on the device.
  Future<String> generateAvatar() async {
    final response = await _client.post(Uri.parse('$baseUrl/api/profile/avatar/generate'));
    if (response.statusCode != 200) {
      throw Exception('Could not generate an avatar: ${response.body}');
    }
    return (jsonDecode(response.body) as Map<String, dynamic>)['avatar'] as String? ?? '';
  }

  /// Turns a photo into a drawing of itself. The image is processed by the
  /// local agent — no model download, no upload, nothing leaves the device.
  Future<String> stylizeAvatar(String imageBase64) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/profile/avatar/stylize'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'image': imageBase64}),
    );
    if (response.statusCode != 200) {
      throw Exception('Could not stylize that image: ${response.body}');
    }
    return (jsonDecode(response.body) as Map<String, dynamic>)['avatar'] as String? ?? '';
  }

  Future<Map<String, dynamic>> saveProfile(ProfileResponse profile) async {
    final response = await _client.put(
      Uri.parse('$baseUrl/api/profile'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode(profile.toJson()),
    );
    if (response.statusCode == 200) {
      return jsonDecode(response.body) as Map<String, dynamic>;
    } else {
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'Failed to save profile: ${response.statusCode}');
    }
  }

  Future<Map<String, dynamic>> getLLMSettings() async {
    final response = await _client.get(Uri.parse('$baseUrl/api/settings/llm'));
    if (response.statusCode == 200) {
      return jsonDecode(response.body) as Map<String, dynamic>;
    } else {
      throw Exception('Failed to get LLM settings: ${response.statusCode}');
    }
  }

  Future<void> saveLLMKey(String service, String apiKey) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/settings/llm'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'service': service, 'api_key': apiKey}),
    );
    if (response.statusCode != 200) {
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'Failed to save key: ${response.statusCode}');
    }
  }

  Future<void> deleteLLMKey(String service) async {
    final response = await _client.delete(Uri.parse('$baseUrl/api/settings/llm/$service'));
    if (response.statusCode != 200) {
      throw Exception('Failed to delete key: ${response.statusCode}');
    }
  }

  Future<EnclaveStatusResponse> getEnclaveStatus() async {
    final response = await _client.get(Uri.parse('$baseUrl/api/security/enclave'));
    if (response.statusCode != 200) {
      throw Exception('Failed to get enclave status: ${response.statusCode}');
    }
    return EnclaveStatusResponse.fromJson(jsonDecode(response.body));
  }

  // ── Guardianship ──────────────────────────────────────────────────────────

  Future<GuardianshipsListResponse> getGuardianships() async {
    final response = await _client.get(Uri.parse('$baseUrl/api/guardianship'));
    if (response.statusCode == 200) {
      return GuardianshipsListResponse.fromJson(jsonDecode(response.body));
    }
    throw Exception('Failed to list guardianships: ${response.statusCode}');
  }

  Future<GuardianshipResponse> createGuardianship({
    required String type,
    required String dependentName,
    required String hostingType,
    String? dependentAid,
    String? hostingUrl,
    Map<String, dynamic>? emancipationTrigger,
    List<String>? coGuardians,
    int? multisigThreshold,
    Map<String, String>? metadata,
  }) async {
    final body = <String, dynamic>{
      'type': type,
      'dependent_name': dependentName,
      'hosting_type': hostingType,
    };
    if (dependentAid != null) body['dependent_aid'] = dependentAid;
    if (hostingUrl != null) body['hosting_url'] = hostingUrl;
    if (emancipationTrigger != null) body['emancipation_trigger'] = emancipationTrigger;
    if (coGuardians != null) body['co_guardians'] = coGuardians;
    if (multisigThreshold != null) body['multisig_threshold'] = multisigThreshold;
    if (metadata != null) body['metadata'] = metadata;

    final response = await _client.post(
      Uri.parse('$baseUrl/api/guardianship'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode(body),
    );
    if (response.statusCode == 201) {
      return GuardianshipResponse.fromJson(jsonDecode(response.body));
    }
    throw Exception(jsonDecode(response.body)['error'] ?? 'Failed to create guardianship');
  }

  Future<GuardianshipResponse> getGuardianship(String id) async {
    final response = await _client.get(Uri.parse('$baseUrl/api/guardianship/$id'));
    if (response.statusCode == 200) {
      return GuardianshipResponse.fromJson(jsonDecode(response.body));
    }
    throw Exception('Failed to get guardianship: ${response.statusCode}');
  }

  Future<GuardianshipResponse> updateGuardianship(String id, Map<String, dynamic> updates) async {
    final response = await _client.put(
      Uri.parse('$baseUrl/api/guardianship/$id'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode(updates),
    );
    if (response.statusCode == 200) {
      return GuardianshipResponse.fromJson(jsonDecode(response.body));
    }
    throw Exception(jsonDecode(response.body)['error'] ?? 'Failed to update guardianship');
  }

  Future<GuardianshipResponse> revokeGuardianship(String id) async {
    final response = await _client.delete(Uri.parse('$baseUrl/api/guardianship/$id'));
    if (response.statusCode == 200) {
      return GuardianshipResponse.fromJson(jsonDecode(response.body));
    }
    throw Exception('Failed to revoke guardianship: ${response.statusCode}');
  }

  Future<GuardianshipResponse> emancipateGuardianship(String id) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/guardianship/$id/emancipate'),
      headers: {'Content-Type': 'application/json'},
    );
    if (response.statusCode == 200) {
      return GuardianshipResponse.fromJson(jsonDecode(response.body));
    }
    throw Exception(jsonDecode(response.body)['error'] ?? 'Failed to emancipate guardianship');
  }

  // ── Credentials ─────────────────────────────────────────────────────────────

  // ── Built-in schema catalog ─────────────────────────────────────────────────

  Future<List<BuiltinSchema>> getBuiltinSchemas() async {
    final response = await _client.get(Uri.parse('$baseUrl/api/schemas'));
    if (response.statusCode == 200) {
      final data = jsonDecode(response.body) as Map<String, dynamic>;
      final list = data['schemas'] as List<dynamic>? ?? [];
      return list.map((e) => BuiltinSchema.fromJson(e as Map<String, dynamic>)).toList();
    } else {
      throw Exception('Failed to get schemas: ${response.statusCode}');
    }
  }

  Future<Map<String, dynamic>> issueCredential({
    required String schemaSaid,
    required String holderAid,
    required Map<String, String> claims,
    // edges: optional ACDC edge block for credential chaining.
    // Structure: {"<label>": {"n": "<parent-SAID>", "s": "<schema-SAID>"}}
    Map<String, dynamic>? edges,
  }) async {
    final body = <String, dynamic>{
      'schema_said': schemaSaid,
      'holder_aid': holderAid,
      'claims': claims,
    };
    if (edges != null) body['edges'] = edges;
    final response = await _client.post(
      Uri.parse('$baseUrl/api/credential/issue'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode(body),
    );
    if (response.statusCode == 201) {
      return jsonDecode(response.body) as Map<String, dynamic>;
    } else {
      final err = jsonDecode(response.body) as Map<String, dynamic>;
      throw Exception(err['error'] ?? 'Credential issuance failed: ${response.statusCode}');
    }
  }

  /// Verify a credential and walk its ACDC edges chain.
  /// Pass [acdcSaid] to look up from local store, or [acdcJsonB64] for an external credential.
  /// Returns {valid, chain: [{said, schema_said, issuer_aid, checks, errors, valid, edge_label}], warnings, errors}.
  Future<Map<String, dynamic>> verifyCredentialChain({
    String? acdcSaid,
    String? acdcJsonB64,
  }) async {
    final reqBody = <String, dynamic>{};
    if (acdcSaid != null) reqBody['acdc_said'] = acdcSaid;
    if (acdcJsonB64 != null) reqBody['acdc_json_b64'] = acdcJsonB64;
    final response = await _client.post(
      Uri.parse('$baseUrl/api/credentials/verify'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode(reqBody),
    );
    if (response.statusCode == 200) {
      return jsonDecode(response.body) as Map<String, dynamic>;
    } else {
      final err = jsonDecode(response.body) as Map<String, dynamic>;
      throw Exception(err['error'] ?? 'Verification failed: ${response.statusCode}');
    }
  }

  Future<List<CredentialRecord>> getCredentials({String? role, String? status}) async {
    var uri = Uri.parse('$baseUrl/api/credentials');
    final params = <String, String>{};
    if (role != null && role.isNotEmpty) params['role'] = role;
    if (status != null && status.isNotEmpty) params['status'] = status;
    if (params.isNotEmpty) uri = uri.replace(queryParameters: params);

    final response = await _client.get(uri);
    if (response.statusCode == 200) {
      final data = jsonDecode(response.body) as Map<String, dynamic>;
      final list = data['credentials'] as List<dynamic>? ?? [];
      return list.map((e) => CredentialRecord.fromJson(e as Map<String, dynamic>)).toList();
    } else {
      throw Exception('Failed to get credentials: ${response.statusCode}');
    }
  }

  Future<CredentialRecord> getCredential(String said) async {
    final response = await _client.get(Uri.parse('$baseUrl/api/credentials/$said'));
    if (response.statusCode == 200) {
      return CredentialRecord.fromJson(jsonDecode(response.body) as Map<String, dynamic>);
    } else {
      throw Exception('Credential not found: $said');
    }
  }

  Future<Map<String, dynamic>> receiveCredential({
    required String acdcJson,
    String rawJson = '',
    String format = 'acdc',
  }) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/credentials/receive'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'acdc_json': acdcJson, 'raw_json': rawJson, 'format': format}),
    );
    if (response.statusCode == 201) {
      return jsonDecode(response.body) as Map<String, dynamic>;
    } else {
      final body = jsonDecode(response.body) as Map<String, dynamic>;
      throw Exception(body['error'] ?? 'Failed to receive credential: ${response.statusCode}');
    }
  }

  Future<void> deleteCredential(String said) async {
    final response = await _client.delete(Uri.parse('$baseUrl/api/credentials/$said'));
    if (response.statusCode != 204) {
      throw Exception('Failed to delete credential: ${response.statusCode}');
    }
  }

  Future<void> acceptCredential(String said) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/credentials/$said/accept'),
      headers: {'Content-Type': 'application/json'},
    );
    if (response.statusCode != 200) {
      throw Exception('Failed to accept credential: ${response.statusCode}');
    }
  }

  Future<void> rejectCredential(String said) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/credentials/$said/reject'),
      headers: {'Content-Type': 'application/json'},
    );
    if (response.statusCode != 204) {
      throw Exception('Failed to reject credential: ${response.statusCode}');
    }
  }

  /// Fetches a credential from a public delivery URL (e.g. {agent_url}/public/credential/{said}).
  /// Used in the receive-via-link flow.
  Future<Map<String, dynamic>> fetchPublicCredential(String url) async {
    final response = await _client.get(Uri.parse(url));
    if (response.statusCode == 200) {
      return jsonDecode(response.body) as Map<String, dynamic>;
    } else {
      throw Exception('Failed to fetch credential from link: ${response.statusCode}');
    }
  }

  // ── Service Providers ────────────────────────────────────────────────────

  Future<ServiceProvidersListResponse> getServiceProviders({String? category, String? status}) async {
    var url = '$baseUrl/api/service-providers';
    final params = <String>[];
    if (category != null) params.add('category=$category');
    if (status != null) params.add('status=$status');
    if (params.isNotEmpty) url += '?${params.join('&')}';

    final response = await _client.get(Uri.parse(url));
    if (response.statusCode == 200) {
      return ServiceProvidersListResponse.fromJson(jsonDecode(response.body));
    }
    throw Exception('Failed to list service providers: ${response.statusCode}');
  }

  Future<ServiceProviderResponse> connectServiceProvider(String id) async {
    final response = await _client.post(Uri.parse('$baseUrl/api/service-providers/$id/connect'));
    if (response.statusCode == 200) {
      return ServiceProviderResponse.fromJson(jsonDecode(response.body));
    }
    throw Exception('Failed to connect: ${response.statusCode}');
  }

  Future<ServiceProviderResponse> disconnectServiceProvider(String id) async {
    final response = await _client.post(Uri.parse('$baseUrl/api/service-providers/$id/disconnect'));
    if (response.statusCode == 200) {
      return ServiceProviderResponse.fromJson(jsonDecode(response.body));
    }
    throw Exception('Failed to disconnect: ${response.statusCode}');
  }

  Future<ServiceProviderResponse> checkServiceProviderHealth(String id) async {
    final response = await _client.post(Uri.parse('$baseUrl/api/service-providers/$id/health'));
    if (response.statusCode == 200) {
      return ServiceProviderResponse.fromJson(jsonDecode(response.body));
    }
    throw Exception('Failed to check health: ${response.statusCode}');
  }

  // ── Assets (credential-gated access) ─────────────────────────────────────
  //
  // An "asset" is a website/domain or application the controller owns and gates
  // sign-in to. The EnrollmentPolicy on each asset is the credential gate: set
  // `requiredCredSchema` (+ optionally `requiredCredIssuer`) so a login is only
  // authorized when the assertion presents a valid ACDC of that schema issued by
  // that AID — e.g. gate a website behind an employee credential the org issued.

  Future<AssetsListResponse> listAssets() async {
    final response = await _client.get(Uri.parse('$baseUrl/api/assets'));
    if (response.statusCode == 200) {
      return AssetsListResponse.fromJson(jsonDecode(response.body));
    }
    throw Exception('Failed to list assets: ${response.statusCode}');
  }

  Future<AssetDetailResponse> createAsset({
    required String displayName,
    required String origin,
    required String assetType, // "domain" | "application"
    String? delegationModel, // "delegated" | "standalone"
    EnrollmentPolicy? policy,
  }) async {
    final body = <String, dynamic>{
      'display_name': displayName,
      'origin': origin,
      'asset_type': assetType,
      if (delegationModel != null) 'delegation_model': delegationModel,
      'policy': (policy ?? const EnrollmentPolicy()).toJson(),
    };
    final response = await _client.post(
      Uri.parse('$baseUrl/api/assets'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode(body),
    );
    if (response.statusCode == 201) {
      return AssetDetailResponse.fromJson(jsonDecode(response.body));
    }
    final err = jsonDecode(response.body);
    throw Exception(err['error'] ?? 'Failed to create asset: ${response.statusCode}');
  }

  Future<AssetDetailResponse> getAsset(String id) async {
    final response = await _client.get(Uri.parse('$baseUrl/api/assets/${Uri.encodeComponent(id)}'));
    if (response.statusCode == 200) {
      return AssetDetailResponse.fromJson(jsonDecode(response.body));
    }
    throw Exception('Failed to get asset: ${response.statusCode}');
  }

  /// Updates the enrollment policy — this is the credential gate. To gate a
  /// website login on an employee credential, set the policy's
  /// [EnrollmentPolicy.requiredCredSchema] (schema SAID) and, to require the
  /// org's own issuance, [EnrollmentPolicy.requiredCredIssuer] (the org AID).
  Future<AssetResponse> updateAssetPolicy(String id, EnrollmentPolicy policy) async {
    final response = await _client.put(
      Uri.parse('$baseUrl/api/assets/${Uri.encodeComponent(id)}/policy'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode(policy.toJson()),
    );
    if (response.statusCode == 200) {
      return AssetResponse.fromJson(jsonDecode(response.body));
    }
    final err = jsonDecode(response.body);
    throw Exception(err['error'] ?? 'Failed to update policy: ${response.statusCode}');
  }

  // Invites ─────────────────────────────────────────────────────────────────

  Future<List<AssetInvite>> listAssetInvites(String id) async {
    final response = await _client.get(Uri.parse('$baseUrl/api/assets/${Uri.encodeComponent(id)}/invites'));
    if (response.statusCode == 200) {
      final list = jsonDecode(response.body) as List<dynamic>? ?? [];
      return list.map((e) => AssetInvite.fromJson(e as Map<String, dynamic>)).toList();
    }
    throw Exception('Failed to list invites: ${response.statusCode}');
  }

  Future<AssetInvite> createAssetInvite(String id, {String? label, int maxUses = 0}) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/assets/${Uri.encodeComponent(id)}/invites'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({if (label != null) 'label': label, 'max_uses': maxUses}),
    );
    if (response.statusCode == 201) {
      return AssetInvite.fromJson(jsonDecode(response.body));
    }
    throw Exception('Failed to create invite: ${response.statusCode}');
  }

  Future<void> revokeAssetInvite(String id, String token) async {
    final response = await _client.delete(
      Uri.parse('$baseUrl/api/assets/${Uri.encodeComponent(id)}/invites/${Uri.encodeComponent(token)}'),
    );
    if (response.statusCode != 200) {
      throw Exception('Failed to revoke invite: ${response.statusCode}');
    }
  }

  // Employees (org roster + add_employee t=3) ─────────────────────────────────

  /// Mint an employee invite for [assetId] (the portal it grants access to) and
  /// its signed t=3 Ask. Returns {invite, token, url} — share `url` as a QR/link.
  /// [maxUses] 1 = invite one; 0 = invite many.
  Future<Map<String, dynamic>> createEmployeeInvite({
    required String role,
    required String assetId,
    String? label,
    int maxUses = 0,
  }) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/employees/invites'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'role': role,
        'asset_id': assetId,
        if (label != null) 'label': label,
        'max_uses': maxUses,
      }),
    );
    if (response.statusCode == 200 || response.statusCode == 201) {
      return jsonDecode(response.body) as Map<String, dynamic>;
    }
    throw Exception('Failed to create employee invite: ${response.statusCode}');
  }

  /// Mint the organisation-founding invite (t=4) and its signed Ask. Returns
  /// {invite, token, url} — the organisation shows `url` as the QR code or
  /// link. The organisation AID must already exist (create keys first). The
  /// signing individual scans it, signs a vouch, and becomes the
  /// organisation's active super-admin.
  Future<Map<String, dynamic>> createSignerInvite() async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/signer/invites'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({}),
    );
    if (response.statusCode == 200 || response.statusCode == 201) {
      return jsonDecode(response.body) as Map<String, dynamic>;
    }
    throw Exception('Failed to create signer invite: ${response.statusCode}');
  }

  /// Who this identity answers to, read from its own key event log rather than
  /// from any record beside it — so it is the same answer anybody outside the
  /// machine would get.
  Future<IdentityOwners> getOwners() async {
    final response = await _client.get(Uri.parse('$baseUrl/api/owners/'));
    if (response.statusCode == 200) {
      return IdentityOwners.fromJson(jsonDecode(response.body) as Map<String, dynamic>);
    }
    throw Exception('Failed to read owners: ${response.statusCode}');
  }

  /// The ceremony in progress, or null. Poll this while codes are on screen:
  /// each acceptance lands here, and the last one applies the rotation.
  Future<OwnerCeremony?> getOwnerCeremony() async {
    final response = await _client.get(Uri.parse('$baseUrl/api/owners/ceremony'));
    if (response.statusCode != 200) {
      throw Exception('Failed to read the ceremony: ${response.statusCode}');
    }
    final body = jsonDecode(response.body) as Map<String, dynamic>;
    final ceremony = body['ceremony'];
    if (ceremony == null) return null;
    return OwnerCeremony.fromJson(ceremony as Map<String, dynamic>);
  }

  /// Begin bringing owners in. Returns one invite per person, each with the URL
  /// that becomes their QR code.
  ///
  /// Nothing changes until every one of them has scanned. threshold omitted
  /// means all of them must sign afterwards.
  Future<OwnerCeremony> startOwnerCeremony(List<String> invite, {int? threshold}) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/owners/ceremony'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'invite': invite,
        if (threshold != null) 'threshold': threshold,
      }),
    );
    if (response.statusCode == 200 || response.statusCode == 201) {
      final body = jsonDecode(response.body) as Map<String, dynamic>;
      return OwnerCeremony.fromJson(body['ceremony'] as Map<String, dynamic>);
    }
    throw Exception(_readError(response.body) ?? 'Failed to start the ceremony: ${response.statusCode}');
  }

  /// Abandon a ceremony that is not going to finish. Kept on record rather than
  /// deleted, so somebody who already accepted can be shown what happened.
  Future<void> abandonOwnerCeremony() async {
    final response = await _client.delete(Uri.parse('$baseUrl/api/owners/ceremony'));
    if (response.statusCode != 200) {
      throw Exception('Failed to abandon the ceremony: ${response.statusCode}');
    }
  }

  String? _readError(String body) {
    try {
      final decoded = jsonDecode(body);
      if (decoded is Map<String, dynamic>) {
        final detail = decoded['details'] ?? decoded['detail'];
        final error = decoded['error'];
        if (detail != null) return '$error — $detail';
        if (error != null) return '$error';
      }
    } catch (_) {}
    return null;
  }

  /// The org roster. Each entry: {pairwise_aid, name, role, status, ...}.
  Future<List<Map<String, dynamic>>> listEmployees() async {
    final response = await _client.get(Uri.parse('$baseUrl/api/employees/'));
    if (response.statusCode == 200) {
      final list = jsonDecode(response.body) as List<dynamic>? ?? [];
      return list.map((e) => e as Map<String, dynamic>).toList();
    }
    throw Exception('Failed to list employees: ${response.statusCode}');
  }

  Future<List<Map<String, dynamic>>> listEmployeeInvites() async {
    final response = await _client.get(Uri.parse('$baseUrl/api/employees/invites'));
    if (response.statusCode == 200) {
      final list = jsonDecode(response.body) as List<dynamic>? ?? [];
      return list.map((e) => e as Map<String, dynamic>).toList();
    }
    throw Exception('Failed to list employee invites: ${response.statusCode}');
  }

  Future<void> revokeEmployeeInvite(String token) async {
    final response = await _client.delete(
      Uri.parse('$baseUrl/api/employees/invites/${Uri.encodeComponent(token)}'),
    );
    if (response.statusCode != 200) {
      throw Exception('Failed to revoke employee invite: ${response.statusCode}');
    }
  }

  /// Approve a pending employee (pending → active). They can now pass the
  /// membership gate on assets sourced to the employee list.
  Future<Map<String, dynamic>> approveEmployee(String pairwiseAid) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/employees/${Uri.encodeComponent(pairwiseAid)}/approve'),
    );
    if (response.statusCode == 200) {
      return jsonDecode(response.body) as Map<String, dynamic>;
    }
    throw Exception('Failed to approve employee: ${response.statusCode}');
  }

  /// Revoke an employee (→ revoked). They immediately fail the membership gate.
  Future<Map<String, dynamic>> revokeEmployee(String pairwiseAid) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/employees/${Uri.encodeComponent(pairwiseAid)}/revoke'),
    );
    if (response.statusCode == 200) {
      return jsonDecode(response.body) as Map<String, dynamic>;
    }
    throw Exception('Failed to revoke employee: ${response.statusCode}');
  }

  // Access requests ───────────────────────────────────────────────────────────

  Future<List<AssetAccessRequest>> listAssetRequests(String id) async {
    final response = await _client.get(Uri.parse('$baseUrl/api/assets/${Uri.encodeComponent(id)}/requests'));
    if (response.statusCode == 200) {
      final list = jsonDecode(response.body) as List<dynamic>? ?? [];
      return list.map((e) => AssetAccessRequest.fromJson(e as Map<String, dynamic>)).toList();
    }
    throw Exception('Failed to list requests: ${response.statusCode}');
  }

  Future<void> approveAssetRequest(String id, String reqId) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/assets/${Uri.encodeComponent(id)}/requests/${Uri.encodeComponent(reqId)}/approve'),
    );
    if (response.statusCode != 200) {
      throw Exception('Failed to approve request: ${response.statusCode}');
    }
  }

  Future<void> denyAssetRequest(String id, String reqId) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/assets/${Uri.encodeComponent(id)}/requests/${Uri.encodeComponent(reqId)}/deny'),
    );
    if (response.statusCode != 200) {
      throw Exception('Failed to deny request: ${response.statusCode}');
    }
  }

  // Members ───────────────────────────────────────────────────────────────────

  Future<List<AssetMember>> listAssetMembers(String id) async {
    final response = await _client.get(Uri.parse('$baseUrl/api/assets/${Uri.encodeComponent(id)}/members'));
    if (response.statusCode == 200) {
      final list = jsonDecode(response.body) as List<dynamic>? ?? [];
      return list.map((e) => AssetMember.fromJson(e as Map<String, dynamic>)).toList();
    }
    throw Exception('Failed to list members: ${response.statusCode}');
  }

  Future<void> removeAssetMember(String id, String aid) async {
    final response = await _client.delete(
      Uri.parse('$baseUrl/api/assets/${Uri.encodeComponent(id)}/members/${Uri.encodeComponent(aid)}'),
    );
    if (response.statusCode != 200) {
      throw Exception('Failed to remove member: ${response.statusCode}');
    }
  }

  // ── Contacts (read-one) ──────────────────────────────────────────────────

  Future<ContactResponse> getContact(String aid) async {
    final response = await _client.get(Uri.parse('$baseUrl/api/contacts/${Uri.encodeComponent(aid)}'));
    if (response.statusCode == 200) {
      return ContactResponse.fromJson(jsonDecode(response.body));
    }
    final err = jsonDecode(response.body);
    throw Exception(err['error'] ?? 'Failed to get contact: ${response.statusCode}');
  }

  // ── Credentials (present) ────────────────────────────────────────────────

  /// Creates an ACDC presentation of a held credential for a verifier.
  /// Returns {presentation_said, presentation_json_b64, pres_said_b64, status}.
  /// (Desktop-only — requires the Python KERI driver.)
  Future<Map<String, dynamic>> presentCredential({
    required String acdcSaid,
    required String holderAid,
    String? issuerAid,
    String? schemaSaid,
    String? cesrSignature,
  }) async {
    final body = <String, dynamic>{
      'acdc_said': acdcSaid,
      'holder_aid': holderAid,
      if (issuerAid != null) 'issuer_aid': issuerAid,
      if (schemaSaid != null) 'schema_said': schemaSaid,
      if (cesrSignature != null) 'cesr_signature': cesrSignature,
    };
    final response = await _client.post(
      Uri.parse('$baseUrl/api/credential/present'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode(body),
    );
    if (response.statusCode == 201) {
      return jsonDecode(response.body) as Map<String, dynamic>;
    }
    final err = jsonDecode(response.body) as Map<String, dynamic>;
    throw Exception(err['error'] ?? 'Credential presentation failed: ${response.statusCode}');
  }

  // ── Universal scan (the one-click transaction initiator) ─────────────────
  //
  // The scanner is a dumb router: it forwards the scanned/pasted Ask pointer
  // (.../i/{token}) to the backend, which fetches the Ask, reads its action `t`,
  // and dispatches to the registered handler. `decode` returns a generic
  // preview; `execute` completes (or declines) the transaction. This covers ANY
  // Ask action — login, add-contact, present/receive-credential, … — through the
  // same two calls; no per-type client logic.

  /// Decodes a scanned/pasted Ask pointer into a generic consent preview.
  /// The backend resolves the action type from the fetched Ask.
  Future<ScanDecodeResult> scanDecode(String url) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/scan/decode'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'url': url}),
    );
    if (response.statusCode == 200) {
      return ScanDecodeResult.fromJson(
          jsonDecode(response.body) as Map<String, dynamic>);
    }
    // The scan handlers return plain-text errors (http.Error), not JSON.
    final detail = response.body.trim();
    throw Exception(detail.isNotEmpty
        ? detail
        : 'Scan decode failed: ${response.statusCode}');
  }

  /// Completes (or declines) the decoded transaction. [tier] is the chosen
  /// escalation tier for actions that take one (e.g. add-contact).
  Future<Map<String, dynamic>> scanExecute({
    required String url,
    required bool approved,
    String? tier,
    // The ask_digest from the decode response the user approved. The core
    // refuses to execute without it, so consent is bound to the exact
    // request that was shown.
    required String askDigest,
  }) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/scan/execute'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'url': url,
        'approved': approved,
        'ask_digest': askDigest,
        if (tier != null) 'tier': tier,
      }),
    );
    if (response.statusCode == 200) {
      return jsonDecode(response.body) as Map<String, dynamic>;
    }
    final detail = response.body.trim();
    throw Exception(detail.isNotEmpty
        ? detail
        : 'Scan execute failed: ${response.statusCode}');
  }

  // ── Bringing an organisation into being on rented hardware ───────────────
  //
  // A freshly provisioned instance belongs to nobody. It has generated no
  // identity and named no owner, and the two routes used here are the only
  // ones reachable in that state — deliberately, because it is the only moment
  // they are for.
  //
  // The founder's device does the naming. It mints an identifier for this
  // relationship specifically, hands over only the public half, and the
  // instance writes that identifier into the event that creates the
  // organisation. Ownership is therefore part of the key log from the first
  // moment: append-only, public, and verifiable by anyone, rather than a row in
  // a table on hardware somebody else runs.
  //
  // NO KEY REACHES THE INSTANCE. It generates its own; the founder keeps
  // theirs. That is what makes renting hardware survivable — the operator ends
  // up holding an agent that can act for itself and cannot act as its owner.

  /// Brings an organisation into being on this instance, owned by [ownerAid].
  ///
  /// Call this on a CoreService pointed at the INSTANCE, not at your own agent.
  ///
  /// [adoptionCode] is the one-time code the instance published when it was
  /// provisioned. Without it, whoever reaches an unclaimed instance first takes
  /// it.
  ///
  /// Returns the organisation's new identifier.
  /// Tells THIS agent to go and adopt another one.
  ///
  /// The owner's side of claiming. This agent already holds the root key, so it
  /// runs the ceremony itself: it asks the other agent for the key it generated
  /// for itself, issues a delegation over that key, anchors it in its own log,
  /// and hands the result back. The root key never leaves this device, and the
  /// other agent never sees it.
  ///
  /// [adoptionCode] is the one-time code issued when that agent was set up. It
  /// is what proves the agent was set up for this person rather than found by
  /// them, so it is required rather than optional — an adoption without one is
  /// a stranger claiming a machine.
  ///
  /// Owner-only, and signed as such. A browser cannot do this and should not be
  /// asked to: it holds no key, and the whole point is that the claim is made
  /// by something that does.
  /// Offers THIS computer for pairing, and returns the code to show on it.
  ///
  /// Only ever call this against the agent running on this machine. It refuses
  /// anything that is not a genuinely local request — not because being local
  /// authorises the pairing (proving control of an identity does that), but
  /// because the code is a secret meant for this machine's own screen and must
  /// not be handed out over the network.
  Future<ComputerPairingOffer> offerThisComputerForPairing() async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/pairing/offer-this-computer'),
      headers: {'Content-Type': 'application/json'},
      body: '{}',
    );
    if (response.statusCode != 200) {
      throw Exception(
          'This computer could not be offered for pairing: ${response.statusCode} ${response.body}');
    }
    final json = jsonDecode(response.body) as Map<String, dynamic>;
    return ComputerPairingOffer(
      code: (json['code'] ?? '').toString(),
      validFor:
          Duration(seconds: (json['expires_in_seconds'] as num?)?.toInt() ?? 0),
      address: (json['address'] ?? '').toString(),
    );
  }

  /// What has happened to the code this computer is showing.
  ///
  /// The screen has to say WHO took the machine, not only that somebody did.
  /// Anyone who can see the screen can read the code, and the first identity to
  /// present it decides who owns the machine — so if that was not you, finding
  /// out immediately is the whole remedy.
  Future<ThisComputersPairing> thisComputersPairingState() async {
    final response = await _client.get(Uri.parse('$baseUrl/api/pairing/this-computer'));
    if (response.statusCode != 200) {
      throw Exception('Could not read this computer\'s pairing state: ${response.statusCode}');
    }
    final json = jsonDecode(response.body) as Map<String, dynamic>;
    return ThisComputersPairing(
      code: (json['code'] ?? '').toString(),
      remaining: Duration(seconds: (json['expires_in_seconds'] as num?)?.toInt() ?? 0),
      claimedBy: (json['claimed_by'] ?? '').toString(),
      paired: json['paired'] == true,
      address: (json['address'] ?? '').toString(),
    );
  }

  /// Mints the identity a machine will answer to, before the machine exists.
  ///
  /// ORDERING IS WHY THIS IS SEPARATE. A machine is told who may claim it
  /// BEFORE it starts — that is what stops whoever reaches it first from taking
  /// it — so the identity has to exist before the machine is even asked for.
  ///
  /// It is a PAIRWISE identity, not this person's root. A machine names its
  /// owner in what it publishes, and publishing the root would hand the
  /// identifier that identifies somebody everywhere to anyone who could reach
  /// their machine. This one means nothing outside that single relationship.
  ///
  /// Only the identifier comes back. Where its key comes from stays on the
  /// device that minted it and is looked up again at adoption.
  Future<String> mintMachineOwner() async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/machines/owner-identity'),
      headers: {'Content-Type': 'application/json'},
      body: '{}',
    );
    if (response.statusCode != 200) {
      throw Exception(
          'Could not create an identity for this machine: ${response.statusCode}');
    }
    final aid = (jsonDecode(response.body)['aid'] ?? '').toString();
    if (aid.isEmpty) {
      throw Exception('No identity came back, so the machine would answer to nobody');
    }
    return aid;
  }

  Future<Map<String, dynamic>> adoptAgent({
    required Uri boxUrl,
    required String adoptionCode,
    /// The identity minted before the machine was asked for. The provisioning
    /// host was told this one may claim it, so adoption must name the same one
    /// or the machine refuses its own owner.
    String? ownerAid,

    /// What you now own: a computer of your own, or an organisation.
    ///
    /// The ceremony does not differ and the machine is never told. What differs
    /// is only what was asked — "be my always-on computer" against "be a signer
    /// and owner of this organisation" — so this is a label on your side, kept
    /// because your computers and your organisations are different lists.
    ///
    /// This is why there is no separate call for founding an organisation.
    /// There was one, and it talked to the machine directly without proving who
    /// was asking, so every organisation founded that way is now refused.
    String kind = 'individual',

    /// The software this owner is willing to adopt, as hex launch measurements.
    ///
    /// An agent with no measurement policy refuses every sealed machine, by
    /// design: read as "accept anything", a missing policy would make every
    /// other check decorative. So something has to say which software is
    /// acceptable, and until a signed list is published this is where it comes
    /// from — the owner stating their own policy on an owner-only route.
    ///
    /// It does not make a measurement trustworthy. It records which value the
    /// owner decided to accept. Where that value came from — a published list,
    /// a build they ran themselves — is the question this cannot answer and
    /// should not appear to.
    List<String> acceptedMeasurements = const [],

    /// Adopt a machine that cannot prove what it is.
    ///
    /// Off by default, so the safe direction is the one that happens when
    /// nobody thought about it. A machine with no attestation may be perfectly
    /// legitimate — a laptop has no such hardware — but it may equally be a
    /// sealed one whose proof was stripped in transit, and those look identical
    /// from here. Saying which has to be a deliberate act, which means somebody
    /// has to be able to say it: the agent has always read this field, and no
    /// app could send it, so an unattested machine could not be adopted at all.
    bool allowUnattested = false,
  }) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/pairing/adopt'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'box_url': boxUrl.toString(),
        'adoption_code': adoptionCode,
        if (ownerAid != null && ownerAid.isNotEmpty) 'owner_aid': ownerAid,
        'kind': kind,
        if (acceptedMeasurements.isNotEmpty)
          'accepted_measurements': acceptedMeasurements,
        if (allowUnattested) 'allow_unattested': true,
      }),
    );
    if (response.statusCode == 200) {
      return jsonDecode(response.body) as Map<String, dynamic>;
    }
    // The agent's refusals are already written for a person; this only strips
    // the JSON wrapper so a screen does not have to.
    try {
      final body = jsonDecode(response.body) as Map<String, dynamic>;
      final detail = (body['details'] ?? body['detail'] ?? body['error'] ?? '').toString();
      throw Exception(detail.isNotEmpty ? detail : 'Adoption failed (${response.statusCode})');
    } on FormatException {
      throw Exception('Adoption failed (${response.statusCode})');
    }
  }

  /// Who agreed to own this agent, as sealed when they agreed.
  ///
  /// Not the same question as [getOwners], and the difference decides which one
  /// a screen wants. That reads the owners out of an identity's own key event
  /// log — the answer anybody outside can check — and needs an identity to
  /// exist. This is what was sealed in at the moment somebody agreed, which is
  /// the only answer available BEFORE the identity is founded.
  ///
  /// Returns null when nobody has claimed this agent, which is an ordinary
  /// state rather than a failure.
  Future<({String aid, String publicKey})?> sealedOwner() async {
    final response = await _client.get(Uri.parse('$baseUrl/api/owners/authority'));
    if (response.statusCode != 200) {
      throw Exception('Could not read who owns this agent: ${response.statusCode}');
    }
    final owner = (jsonDecode(response.body) as Map<String, dynamic>)['owner'];
    if (owner is! Map) return null;
    final aid = (owner['aid'] ?? '').toString();
    final key = (owner['public_key'] ?? '').toString();
    if (aid.isEmpty || key.isEmpty) return null;
    return (aid: aid, publicKey: key);
  }

  /// The keys this agent seals its backups to — the owner's, recorded when
  /// they agreed to own it.
  ///
  /// Public halves. They are read back rather than re-derived because the seed
  /// they come from is on the OWNER's device and never on this one, so this is
  /// the only copy an organisation has.
  Future<List<String>> recoveryKeysHeld() async {
    final response = await _client.get(Uri.parse('$baseUrl/api/backup/config'));
    if (response.statusCode != 200) return const [];
    final cfg = jsonDecode(response.body) as Map<String, dynamic>;
    final keys = cfg['seal_to_public_keys_b64'];
    if (keys is! List) return const [];
    return keys.map((k) => k.toString()).where((k) => k.isNotEmpty).toList();
  }

  // ── Signing in from a browser ────────────────────────────────────────────
  //
  // A browser holds no key, so it cannot prove ownership the way an app does.
  // The agent's answer is a three-step handshake: the browser asks for a
  // challenge while keeping a secret only it knows, a device that DOES hold the
  // key grants the displayed code, and the browser exchanges its secret for a
  // session.
  //
  // The secret is why the code can be read aloud. Anyone who can see the screen
  // learns the code; without a secret the browser never displays, seeing it
  // would be enough to collect the session the owner just granted — and the
  // owner would have authorised a stranger while watching their own screen.

  /// Step one, from the browser: ask for a code to display.
  ///
  /// Returns the challenge and the secret to keep. Hold the secret and pass it
  /// back to [claimBrowserLogin]; it never reaches the agent, only its digest.
  Future<BrowserLogin> startBrowserLogin() async {
    final secret = _randomSecret();
    final claimHash = sha256.convert(utf8.encode(secret)).toString();

    final response = await _client.post(
      Uri.parse('$baseUrl/api/session/challenge'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'claim_hash': claimHash}),
    );
    if (response.statusCode != 200) {
      throw Exception(_sessionError(response, 'Could not start a login'));
    }
    final json = jsonDecode(response.body) as Map<String, dynamic>;
    return BrowserLogin(
      challengeId: json['challenge_id']?.toString() ?? '',
      code: json['code']?.toString() ?? '',
      expiresAt: DateTime.tryParse(json['expires_at']?.toString() ?? ''),
      claimSecret: secret,
    );
  }

  /// Step two, from the device holding the key: approve a displayed code.
  ///
  /// Owner-only, and that is what makes the handshake mean anything — this
  /// request carries the owner's signature exactly as any other does.
  Future<void> grantBrowserLogin(String code) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/session/grant'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'code': code.trim().toUpperCase()}),
    );
    if (response.statusCode != 200) {
      throw Exception(_sessionError(response, 'Could not approve the login'));
    }
  }

  /// Step three, from the browser: collect the session once granted.
  ///
  /// Returns null while the owner has not approved yet — the agent says so
  /// distinctly rather than as a failure, so a caller can keep waiting without
  /// treating every poll as a rejection. On success the session is adopted for
  /// every later call automatically.
  Future<String?> claimBrowserLogin(BrowserLogin login) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/session/claim'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'challenge_id': login.challengeId,
        'claim_secret': login.claimSecret,
      }),
    );
    if (response.statusCode == 202) return null; // granted:false — still waiting
    if (response.statusCode != 200) {
      throw Exception(_sessionError(response, 'Could not collect the session'));
    }
    final json = jsonDecode(response.body) as Map<String, dynamic>;
    final token = json['token']?.toString();
    if (token == null || token.isEmpty) {
      throw Exception('The agent granted a session without a token');
    }
    _session?.adopt(token);
    return token;
  }

  /// Whether this client is carrying a browser session.
  bool get hasBrowserSession => _session?.hasSession ?? false;

  /// Adopt a session obtained elsewhere — after a page reload, say.
  void adoptBrowserSession(String token) => _session?.adopt(token);

  /// Sign out. Reachable with the session itself rather than owner-only,
  /// because ending your own session should not require the device that
  /// started it — that is exactly when you most want to.
  Future<void> endBrowserSession() async {
    if (_session?.hasSession != true) return;
    try {
      await _client.post(Uri.parse('$baseUrl/api/session/end'),
          headers: {'Content-Type': 'application/json'});
    } finally {
      // Dropped locally whatever the agent said. A client still presenting a
      // token it believes in, against an agent that has forgotten it, is worse
      // than being signed out.
      _session?.discard();
    }
  }

  static String _randomSecret() {
    final rnd = Random.secure();
    return base64Url
        .encode(List<int>.generate(32, (_) => rnd.nextInt(256)))
        .replaceAll('=', '');
  }

  String _sessionError(http.Response response, String fallback) {
    try {
      final json = jsonDecode(response.body) as Map<String, dynamic>;
      final d = json['details'] ?? json['detail'] ?? json['error'];
      if (d != null && d.toString().isNotEmpty) return d.toString();
    } catch (_) {}
    return '$fallback (${response.statusCode})';
  }

  void dispose() {
    _client.close();
  }
}

/// A login in progress: what to show, and the secret to keep while showing it.
class BrowserLogin {
  const BrowserLogin({
    required this.challengeId,
    required this.code,
    required this.claimSecret,
    this.expiresAt,
  });

  /// Identifies this login to the agent.
  final String challengeId;

  /// What the person reads off this screen and into the one holding the key.
  final String code;

  /// Held here and never sent — only its digest reached the agent, so an agent
  /// whose memory has been read cannot collect its own pending logins.
  final String claimSecret;

  /// When the code stops being worth reading.
  final DateTime? expiresAt;
}

// ── Guardianship models ─────────────────────────────────────────────────────

class GuardianshipResponse {
  final String id;
  final String type;
  final String guardianAid;
  final String dependentAid;
  final String dependentName;
  final String delegatedAidPrefix;
  final String status;
  final String hostingType;
  final String hostingUrl;
  final String createdAt;
  final String updatedAt;
  final EmancipationTriggerResponse? emancipationTrigger;
  final List<String> coGuardians;
  final int multisigThreshold;
  final Map<String, String> metadata;
  final String credentialSaid;

  GuardianshipResponse({
    required this.id,
    required this.type,
    required this.guardianAid,
    required this.dependentAid,
    required this.dependentName,
    required this.delegatedAidPrefix,
    required this.status,
    required this.hostingType,
    required this.hostingUrl,
    required this.createdAt,
    required this.updatedAt,
    this.emancipationTrigger,
    required this.coGuardians,
    required this.multisigThreshold,
    required this.metadata,
    this.credentialSaid = '',
  });

  factory GuardianshipResponse.fromJson(Map<String, dynamic> json) {
    return GuardianshipResponse(
      id: json['id'] as String? ?? '',
      type: json['type'] as String? ?? '',
      guardianAid: json['guardian_aid'] as String? ?? '',
      dependentAid: json['dependent_aid'] as String? ?? '',
      dependentName: json['dependent_name'] as String? ?? '',
      delegatedAidPrefix: json['delegated_aid_prefix'] as String? ?? '',
      status: json['status'] as String? ?? '',
      hostingType: json['hosting_type'] as String? ?? '',
      hostingUrl: json['hosting_url'] as String? ?? '',
      createdAt: json['created_at'] as String? ?? '',
      updatedAt: json['updated_at'] as String? ?? '',
      emancipationTrigger: json['emancipation_trigger'] != null
          ? EmancipationTriggerResponse.fromJson(json['emancipation_trigger'])
          : null,
      coGuardians: (json['co_guardians'] as List<dynamic>?)
          ?.map((e) => e.toString()).toList() ?? [],
      multisigThreshold: (json['multisig_threshold'] as num?)?.toInt() ?? 0,
      metadata: (json['metadata'] as Map<String, dynamic>?)
          ?.map((k, v) => MapEntry(k, v.toString())) ?? {},
      credentialSaid: json['credential_said'] as String? ?? '',
    );
  }

  String get typeLabel {
    switch (type) {
      case 'minor_child': return 'Minor Child';
      case 'elderly': return 'Elderly Family Member';
      case 'disability': return 'Person with a Disability';
      case 'temporary': return 'Temporary Guardianship';
      default: return type;
    }
  }

  bool get isActive => status == 'active';
}

class EmancipationTriggerResponse {
  final String type;
  final String value;

  EmancipationTriggerResponse({required this.type, required this.value});

  factory EmancipationTriggerResponse.fromJson(Map<String, dynamic> json) {
    return EmancipationTriggerResponse(
      type: json['type'] as String? ?? '',
      value: json['value'] as String? ?? '',
    );
  }

  Map<String, dynamic> toJson() => {'type': type, 'value': value};
}

class GuardianshipsListResponse {
  final List<GuardianshipResponse> guardianships;
  final int count;

  GuardianshipsListResponse({required this.guardianships, required this.count});

  factory GuardianshipsListResponse.fromJson(Map<String, dynamic> json) {
    return GuardianshipsListResponse(
      guardianships: (json['guardianships'] as List<dynamic>?)
          ?.map((e) => GuardianshipResponse.fromJson(e as Map<String, dynamic>))
          .toList() ?? [],
      count: (json['count'] as num?)?.toInt() ?? 0,
    );
  }
}

class EnclaveStatusResponse {
  final bool hardwareBacked;
  final String backingType;
  final String backingLabel;
  final bool? tpmPresent;
  final bool? tpmEnabled;
  // The real device-trust verdict computed by the backend TrustGate from the
  // attestation chain (identity-agent-core/server/enclave_detect.go →
  // trustAllowed). Null means the backend didn't evaluate trust. Onboarding
  // gates fail-closed on this: only `true` proceeds.
  final bool? trustAllowed;

  EnclaveStatusResponse({
    required this.hardwareBacked,
    required this.backingType,
    required this.backingLabel,
    this.tpmPresent,
    this.tpmEnabled,
    this.trustAllowed,
  });

  factory EnclaveStatusResponse.fromJson(Map<String, dynamic> json) {
    return EnclaveStatusResponse(
      hardwareBacked: json['hardwareBacked'] as bool? ?? false,
      backingType: json['backingType'] as String? ?? 'software',
      backingLabel: json['backingLabel'] as String? ?? 'Software',
      tpmPresent: json['tpmPresent'] as bool?,
      tpmEnabled: json['tpmEnabled'] as bool?,
      trustAllowed: json['trustAllowed'] as bool?,
    );
  }
}

// ShareAction represents a user-facing engagement action in the Share menu.
// Managed by the Data Manager sandbox app; persisted in identity.db.
class ShareAction {
  final String id;
  final String actionKey;
  final String name;
  final String subtitle;
  final String icon;
  final bool isEnabled;
  final int sortOrder;

  const ShareAction({
    required this.id,
    required this.actionKey,
    required this.name,
    required this.subtitle,
    required this.icon,
    required this.isEnabled,
    required this.sortOrder,
  });

  factory ShareAction.fromJson(Map<String, dynamic> json) {
    return ShareAction(
      id: json['id'] as String? ?? '',
      actionKey: json['action_key'] as String? ?? '',
      name: json['name'] as String? ?? '',
      subtitle: json['subtitle'] as String? ?? '',
      icon: json['icon'] as String? ?? '',
      isEnabled: json['is_enabled'] == true,
      sortOrder: (json['sort_order'] as num?)?.toInt() ?? 0,
    );
  }

  Map<String, dynamic> toJson() => {
    'id': id,
    'action_key': actionKey,
    'name': name,
    'subtitle': subtitle,
    'icon': icon,
    'is_enabled': isEnabled,
    'sort_order': sortOrder,
  };
}

// ── Built-in schema catalog models ────────────────────────────────────────────

class SchemaField {
  final String key;
  final String label;
  final String type; // "string" | "boolean" | "date" | "aid"
  final bool required;
  final String placeholder;

  const SchemaField({
    required this.key,
    required this.label,
    required this.type,
    required this.required,
    required this.placeholder,
  });

  factory SchemaField.fromJson(Map<String, dynamic> json) => SchemaField(
    key:         json['Key']         as String? ?? '',
    label:       json['Label']       as String? ?? '',
    type:        json['Type']        as String? ?? 'string',
    required:    json['Required']    as bool?   ?? false,
    placeholder: json['Placeholder'] as String? ?? '',
  );
}

class BuiltinSchema {
  final String said;
  final String name;
  final String description;
  final List<SchemaField> fields;

  const BuiltinSchema({
    required this.said,
    required this.name,
    required this.description,
    required this.fields,
  });

  factory BuiltinSchema.fromJson(Map<String, dynamic> json) => BuiltinSchema(
    said:        json['SAID']        as String? ?? '',
    name:        json['Name']        as String? ?? '',
    description: json['Description'] as String? ?? '',
    fields: (json['Fields'] as List<dynamic>? ?? [])
        .map((f) => SchemaField.fromJson(f as Map<String, dynamic>))
        .toList(),
  );
}

// ── Credential data model ──────────────────────────────────────────────────────

class CredentialRecord {
  final String said;
  final String issuerAid;
  final String holderAid;
  final String schemaSaid;
  final String acdcJson;
  final String ixnSaid;
  final String cesrSignature;
  final String issuedAt;
  final String status;
  final String format;
  final String credentialType;
  final String issuerName;
  final String issuerLogoUrl;
  final String expiryDate;
  final String rawJson;

  const CredentialRecord({
    required this.said,
    required this.issuerAid,
    required this.holderAid,
    required this.schemaSaid,
    required this.acdcJson,
    required this.ixnSaid,
    required this.cesrSignature,
    required this.issuedAt,
    required this.status,
    required this.format,
    required this.credentialType,
    required this.issuerName,
    required this.issuerLogoUrl,
    required this.expiryDate,
    required this.rawJson,
  });

  factory CredentialRecord.fromJson(Map<String, dynamic> json) {
    return CredentialRecord(
      said:           json['said']            as String? ?? '',
      issuerAid:      json['issuer_aid']       as String? ?? '',
      holderAid:      json['holder_aid']       as String? ?? '',
      schemaSaid:     json['schema_said']      as String? ?? '',
      acdcJson:       json['acdc_json']        as String? ?? '',
      ixnSaid:        json['ixn_said']         as String? ?? '',
      cesrSignature:  json['cesr_signature']   as String? ?? '',
      issuedAt:       json['issued_at']        as String? ?? '',
      status:         json['status']           as String? ?? '',
      format:         json['format']           as String? ?? 'acdc',
      credentialType: json['credential_type']  as String? ?? '',
      issuerName:     json['issuer_name']      as String? ?? '',
      issuerLogoUrl:  json['issuer_logo_url']  as String? ?? '',
      expiryDate:     json['expiry_date']      as String? ?? '',
      rawJson:        json['raw_json']         as String? ?? '',
    );
  }

  bool get isExpired {
    if (expiryDate.isEmpty) return false;
    try {
      return DateTime.parse(expiryDate).isBefore(DateTime.now());
    } catch (_) {
      return false;
    }
  }

  bool get expiringWithin30Days {
    if (expiryDate.isEmpty) return false;
    try {
      final exp = DateTime.parse(expiryDate);
      final now = DateTime.now();
      return !exp.isBefore(now) && exp.isBefore(now.add(const Duration(days: 30)));
    } catch (_) {
      return false;
    }
  }

  // Attempt to extract a primary claim from the ACDC JSON.
  // Returns a human-readable string representing the most prominent claim.
  /// Decode acdcJson which may be base64-encoded or raw JSON.
  String get decodedAcdcJson {
    if (acdcJson.isEmpty) return '';
    if (acdcJson.trimLeft().startsWith('{')) return acdcJson;
    try {
      return utf8.decode(base64Decode(acdcJson));
    } catch (_) {
      return acdcJson;
    }
  }

  String get primaryClaim {
    if (acdcJson.isEmpty) return said.length > 20 ? '${said.substring(0, 20)}...' : said;
    try {
      final acdc = Map<String, dynamic>.from(jsonDecode(decodedAcdcJson) as Map);
      final a = acdc['a'];
      final attrs = a is Map ? Map<String, dynamic>.from(a) : null;
      if (attrs != null) {
        for (final key in ['email', 'name', 'fullName', 'full_name', 'identifier',
                           'licenseNumber', 'license_number', 'id', 'subject']) {
          if (attrs[key] is String && (attrs[key] as String).isNotEmpty) {
            return attrs[key] as String;
          }
        }
        // Fall back to first non-empty string value
        for (final val in attrs.values) {
          if (val is String && val.isNotEmpty) return val;
        }
      }
    } catch (_) {}
    return said.length > 20 ? '${said.substring(0, 20)}...' : said;
  }
}

// ── Service Provider models ─────────────────────────────────────────────────

class ServiceProviderResponse {
  final String id;
  final String providerName;
  final String providerAid;
  final String category;
  final String displayName;
  final String endpointUrl;
  final String status;
  final String health;
  final String healthCheckedAt;
  final String companyHq;
  final String serverRegion;
  final int identityLevel;
  final int grapeScore;
  final List<String> capabilities;
  final String termsUrl;
  final String termsAcceptedAt;
  final String termsVersion;
  final String connectedAt;
  final Map<String, String> configuration;
  final bool isDefault;
  final String source;

  ServiceProviderResponse({
    required this.id,
    required this.providerName,
    required this.providerAid,
    required this.category,
    required this.displayName,
    required this.endpointUrl,
    required this.status,
    required this.health,
    required this.healthCheckedAt,
    required this.companyHq,
    required this.serverRegion,
    required this.identityLevel,
    required this.grapeScore,
    required this.capabilities,
    required this.termsUrl,
    required this.termsAcceptedAt,
    required this.termsVersion,
    required this.connectedAt,
    required this.configuration,
    required this.isDefault,
    required this.source,
  });

  factory ServiceProviderResponse.fromJson(Map<String, dynamic> json) {
    return ServiceProviderResponse(
      id: json['id'] as String? ?? '',
      providerName: json['provider_name'] as String? ?? '',
      providerAid: json['provider_aid'] as String? ?? '',
      category: json['category'] as String? ?? '',
      displayName: json['display_name'] as String? ?? '',
      endpointUrl: json['endpoint_url'] as String? ?? '',
      status: json['status'] as String? ?? '',
      health: json['health'] as String? ?? 'unknown',
      healthCheckedAt: json['health_checked_at'] as String? ?? '',
      companyHq: json['company_hq'] as String? ?? '',
      serverRegion: json['server_region'] as String? ?? '',
      identityLevel: (json['identity_level'] as num?)?.toInt() ?? 0,
      grapeScore: (json['grape_score'] as num?)?.toInt() ?? 0,
      capabilities: (json['capabilities'] as List<dynamic>?)?.map((e) => e.toString()).toList() ?? [],
      termsUrl: json['terms_url'] as String? ?? '',
      termsAcceptedAt: json['terms_accepted_at'] as String? ?? '',
      termsVersion: json['terms_version'] as String? ?? '',
      connectedAt: json['connected_at'] as String? ?? '',
      configuration: (json['configuration'] as Map<String, dynamic>?)?.map((k, v) => MapEntry(k, v.toString())) ?? {},
      isDefault: json['is_default'] == true,
      source: json['source'] as String? ?? '',
    );
  }

  String get categoryLabel {
    switch (category) {
      case 'infrastructure': return 'Infrastructure';
      case 'witness': return 'Witness';
      case 'cloud_hsm': return 'Cloud HSM';
      case 'tunneling': return 'Tunneling';
      default: return category;
    }
  }

  bool get isConnected => status == 'connected';
  bool get isHealthy => health == 'healthy';
}

class ServiceProvidersListResponse {
  final List<ServiceProviderResponse> providers;
  final int count;

  ServiceProvidersListResponse({required this.providers, required this.count});

  factory ServiceProvidersListResponse.fromJson(Map<String, dynamic> json) {
    return ServiceProvidersListResponse(
      providers: (json['providers'] as List<dynamic>?)
          ?.map((e) => ServiceProviderResponse.fromJson(e as Map<String, dynamic>))
          .toList() ?? [],
      count: (json['count'] as num?)?.toInt() ?? 0,
    );
  }
}

// ── Asset models (credential-gated access) ───────────────────────────────────

// EnrollmentPolicy is the per-asset access gate. `mode` is enforced by OSS core
// along with `requiredAal`; the credential-gating fields (`requiredCredSchema`
// /`requiredCredIssuer`) authorize a sign-in only when the assertion presents a
// valid, unrevoked ACDC of that schema (and, if set, issued by that AID).
// `requiredBadge`/`requiredOfaScore` are stored+returned but enforced by the
// commercial layer on top.
class EnrollmentPolicy {
  final String mode; // "open" | "request" | "invite"
  final int requiredAal; // NIST 800-63B level 1/2/3; 0 = not required
  final String requiredBadge; // ""|"green"|"yellow"|"red"
  final int requiredOfaScore; // 0 = not required
  final String requiredCredSchema; // schema SAID; "" = no credential required
  final String requiredCredIssuer; // issuer AID; "" = any issuer
  // "" | "asset" = gate on this asset's own members; "employees" = gate on the
  // org's ACTIVE employee list (the AID method for an employee portal).
  final String membershipSource;

  const EnrollmentPolicy({
    this.mode = 'open',
    this.requiredAal = 0,
    this.requiredBadge = '',
    this.requiredOfaScore = 0,
    this.requiredCredSchema = '',
    this.requiredCredIssuer = '',
    this.membershipSource = '',
  });

  factory EnrollmentPolicy.fromJson(Map<String, dynamic> json) => EnrollmentPolicy(
    mode: json['mode'] as String? ?? 'open',
    requiredAal: (json['required_aal'] as num?)?.toInt() ?? 0,
    requiredBadge: json['required_badge'] as String? ?? '',
    requiredOfaScore: (json['required_ofa_score'] as num?)?.toInt() ?? 0,
    requiredCredSchema: json['required_cred_schema'] as String? ?? '',
    requiredCredIssuer: json['required_cred_issuer'] as String? ?? '',
    membershipSource: json['membership_source'] as String? ?? '',
  );

  Map<String, dynamic> toJson() => {
    'mode': mode,
    'required_aal': requiredAal,
    'required_badge': requiredBadge,
    'required_ofa_score': requiredOfaScore,
    'required_cred_schema': requiredCredSchema,
    'required_cred_issuer': requiredCredIssuer,
    'membership_source': membershipSource,
  };

  EnrollmentPolicy copyWith({
    String? mode,
    int? requiredAal,
    String? requiredBadge,
    int? requiredOfaScore,
    String? requiredCredSchema,
    String? requiredCredIssuer,
    String? membershipSource,
  }) => EnrollmentPolicy(
    mode: mode ?? this.mode,
    requiredAal: requiredAal ?? this.requiredAal,
    requiredBadge: requiredBadge ?? this.requiredBadge,
    requiredOfaScore: requiredOfaScore ?? this.requiredOfaScore,
    requiredCredSchema: requiredCredSchema ?? this.requiredCredSchema,
    requiredCredIssuer: requiredCredIssuer ?? this.requiredCredIssuer,
    membershipSource: membershipSource ?? this.membershipSource,
  );

  bool get gatesOnCredential => requiredCredSchema.isNotEmpty;
  bool get gatesOnEmployees => membershipSource == 'employees';
}

class AssetResponse {
  final String id;
  final String displayName;
  final String assetType; // "domain" | "application"
  final String origin;
  final String pairwiseAid;
  final String delegationModel; // "delegated" | "standalone"
  final String delegatorAid;
  final EnrollmentPolicy policy;
  final int signingIndex;
  final String createdAt;
  final String updatedAt;

  const AssetResponse({
    required this.id,
    required this.displayName,
    required this.assetType,
    required this.origin,
    required this.pairwiseAid,
    required this.delegationModel,
    this.delegatorAid = '',
    required this.policy,
    this.signingIndex = 0,
    this.createdAt = '',
    this.updatedAt = '',
  });

  /// The asset can sign login challenges once it has a derived signing key.
  bool get canSign => signingIndex > 0;

  factory AssetResponse.fromJson(Map<String, dynamic> json) => AssetResponse(
    id: json['id'] as String? ?? '',
    displayName: json['display_name'] as String? ?? '',
    assetType: json['asset_type'] as String? ?? '',
    origin: json['origin'] as String? ?? '',
    pairwiseAid: json['pairwise_aid'] as String? ?? '',
    delegationModel: json['delegation_model'] as String? ?? '',
    delegatorAid: json['delegator_aid'] as String? ?? '',
    policy: json['policy'] != null
        ? EnrollmentPolicy.fromJson(json['policy'] as Map<String, dynamic>)
        : const EnrollmentPolicy(),
    signingIndex: (json['signing_index'] as num?)?.toInt() ?? 0,
    createdAt: json['created_at'] as String? ?? '',
    updatedAt: json['updated_at'] as String? ?? '',
  );
}

// AssetListItem wraps an asset with its aggregate counts, as returned by the
// list endpoint (`{"assets": [{asset, member_count, pending_count}]}`).
class AssetListItem {
  final AssetResponse asset;
  final int memberCount;
  final int pendingCount;

  const AssetListItem({
    required this.asset,
    this.memberCount = 0,
    this.pendingCount = 0,
  });

  factory AssetListItem.fromJson(Map<String, dynamic> json) => AssetListItem(
    asset: AssetResponse.fromJson(json['asset'] as Map<String, dynamic>),
    memberCount: (json['member_count'] as num?)?.toInt() ?? 0,
    pendingCount: (json['pending_count'] as num?)?.toInt() ?? 0,
  );
}

class AssetsListResponse {
  final List<AssetListItem> assets;

  const AssetsListResponse({required this.assets});

  factory AssetsListResponse.fromJson(Map<String, dynamic> json) => AssetsListResponse(
    assets: (json['assets'] as List<dynamic>?)
        ?.map((e) => AssetListItem.fromJson(e as Map<String, dynamic>))
        .toList() ?? [],
  );
}

// AssetDetailResponse is returned by create/get (`{asset, sdk_config}`).
// sdkConfig carries the login-SDK env for the asset's site (pairwise AID, OOBI,
// asset id, enrollment mode).
class AssetDetailResponse {
  final AssetResponse asset;
  final Map<String, String> sdkConfig;

  const AssetDetailResponse({required this.asset, this.sdkConfig = const {}});

  factory AssetDetailResponse.fromJson(Map<String, dynamic> json) => AssetDetailResponse(
    asset: AssetResponse.fromJson(json['asset'] as Map<String, dynamic>),
    sdkConfig: (json['sdk_config'] as Map<String, dynamic>?)
        ?.map((k, v) => MapEntry(k, v?.toString() ?? '')) ?? {},
  );
}

class AssetInvite {
  final String token;
  final String assetId;
  final String label;
  final int maxUses; // 0 = unlimited
  final int useCount;
  final String createdAt;
  final bool revoked;

  const AssetInvite({
    required this.token,
    required this.assetId,
    this.label = '',
    this.maxUses = 0,
    this.useCount = 0,
    this.createdAt = '',
    this.revoked = false,
  });

  factory AssetInvite.fromJson(Map<String, dynamic> json) => AssetInvite(
    token: json['token'] as String? ?? '',
    assetId: json['asset_id'] as String? ?? '',
    label: json['label'] as String? ?? '',
    maxUses: (json['max_uses'] as num?)?.toInt() ?? 0,
    useCount: (json['use_count'] as num?)?.toInt() ?? 0,
    createdAt: json['created_at'] as String? ?? '',
    revoked: json['revoked'] == true,
  );
}

class AssetAccessRequest {
  final String id;
  final String assetId;
  final Map<String, String> requesterInfo;
  final String status; // "pending" | "approved" | "denied"
  final String createdAt;
  final String? resolvedAt;

  const AssetAccessRequest({
    required this.id,
    required this.assetId,
    this.requesterInfo = const {},
    this.status = 'pending',
    this.createdAt = '',
    this.resolvedAt,
  });

  factory AssetAccessRequest.fromJson(Map<String, dynamic> json) => AssetAccessRequest(
    id: json['id'] as String? ?? '',
    assetId: json['asset_id'] as String? ?? '',
    requesterInfo: (json['requester_info'] as Map<String, dynamic>?)
        ?.map((k, v) => MapEntry(k, v?.toString() ?? '')) ?? {},
    status: json['status'] as String? ?? 'pending',
    createdAt: json['created_at'] as String? ?? '',
    resolvedAt: json['resolved_at'] as String?,
  );
}

class AssetMember {
  final String assetId;
  final String pairwiseAid;
  final String joinedAt;
  final String inviteToken;

  const AssetMember({
    required this.assetId,
    required this.pairwiseAid,
    this.joinedAt = '',
    this.inviteToken = '',
  });

  factory AssetMember.fromJson(Map<String, dynamic> json) => AssetMember(
    assetId: json['asset_id'] as String? ?? '',
    pairwiseAid: json['pairwise_aid'] as String? ?? '',
    joinedAt: json['joined_at'] as String? ?? '',
    inviteToken: json['invite_token'] as String? ?? '',
  );
}

/// Who an identity answers to, as its own key event log says.
class IdentityOwners {
  final String aid;
  final List<String> owners;

  const IdentityOwners({required this.aid, this.owners = const []});

  factory IdentityOwners.fromJson(Map<String, dynamic> json) => IdentityOwners(
        aid: json['aid'] ?? '',
        owners: ((json['owners'] as List<dynamic>?) ?? const [])
            .map((o) => o.toString())
            .toList(),
      );
}

/// One attempt to change who controls an identity.
///
/// The identity keeps working throughout. Nothing changes until every
/// invited owner has accepted — a half-applied ownership change would leave
/// some people believing they own something they do not.
class OwnerCeremony {
  final String id;
  final int threshold;
  final List<CeremonyInvitee> invited;

  /// collecting · applied · failed · abandoned
  final String status;

  /// Why it failed, in words somebody can act on. A ceremony that failed and
  /// does not say why leaves everyone unsure whether control actually
  /// changed.
  final String detail;

  /// The rotation that made it real, so this and the key log can be reconciled.
  final String rotationSaid;

  const OwnerCeremony({
    required this.id,
    this.threshold = 0,
    this.invited = const [],
    this.status = '',
    this.detail = '',
    this.rotationSaid = '',
  });

  bool get isCollecting => status == 'collecting';
  bool get isApplied => status == 'applied';
  bool get hasFailed => status == 'failed';

  /// Who has not scanned yet.
  List<CeremonyInvitee> get outstanding =>
      invited.where((i) => !i.accepted).toList();

  factory OwnerCeremony.fromJson(Map<String, dynamic> json) => OwnerCeremony(
        id: json['id'] ?? '',
        threshold: json['threshold'] ?? 0,
        invited: ((json['invited'] as List<dynamic>?) ?? const [])
            .map((i) => CeremonyInvitee.fromJson(i as Map<String, dynamic>))
            .toList(),
        status: json['status'] ?? '',
        detail: json['detail'] ?? '',
        rotationSaid: json['rotation_said'] ?? '',
      );
}

/// One person being brought in as an owner.
class CeremonyInvitee {
  final String name;

  /// What becomes their QR code. One each — a shared code could be scanned
  /// twice by the same person and leave a place at the table unfilled.
  final String inviteUrl;

  /// Filled in when they accept, from their own device. No key material ever
  /// crosses the wire; these are public halves.
  final String pairwiseAid;
  final String publicKey;
  final String acceptedAt;

  const CeremonyInvitee({
    this.name = '',
    this.inviteUrl = '',
    this.pairwiseAid = '',
    this.publicKey = '',
    this.acceptedAt = '',
  });

  bool get accepted => pairwiseAid.isNotEmpty && publicKey.isNotEmpty;

  factory CeremonyInvitee.fromJson(Map<String, dynamic> json) => CeremonyInvitee(
        name: json['name'] ?? '',
        inviteUrl: json['invite_url'] ?? '',
        pairwiseAid: json['pairwise_aid'] ?? '',
        publicKey: json['public_key'] ?? '',
        acceptedAt: json['accepted_at'] ?? '',
      );
}

/// This agent exists, and you are not the one who may set it up.
///
/// Thrown when the agent refuses a request that only its owner may make. It is
/// a distinct type rather than a status code because the right thing to show
/// somebody is completely different: an agent nobody has claimed is waiting to
/// be claimed by whoever it was set up for, and telling them to create an
/// identity here is both wrong and a dead end.
class AgentNotYoursException implements Exception {
  const AgentNotYoursException();

  @override
  String toString() =>
      'This agent will only answer to the person it was set up for.';
}

/// A machine this identity has adopted, as its owner knows it.
///
/// The identifier is the one the machine minted for itself before any owner
/// existed — the only stable thing about it. Its address moves over its life
/// and its name is whatever a person decided to call it.
class AdoptedAgent {
  const AdoptedAgent({
    required this.aid,
    required this.signsAsAid,
    required this.url,
    required this.kind,
    this.label = '',
    this.sealed = false,
    this.measurement = '',
    this.ownerAid = '',
    this.adoptedAt = '',
    this.lastSeenAt = '',
  });

  final String aid;

  /// What it signs as, under this owner's authority.
  final String signsAsAid;

  /// Where it is reached. Expected to change; the identifier is not.
  final String url;

  /// 'individual' or 'organization' — which agent it runs.
  final String kind;

  /// What its owner calls it. Empty until somebody names it, which is better
  /// than inventing a name they then have to correct.
  final String label;

  /// Whether the hardware proved itself when this machine was adopted, and
  /// what it was running. Recorded then rather than asked for now: asking the
  /// machine means trusting what it says about itself.
  final bool sealed;
  final String measurement;

  /// Which identity of yours this machine answers to. Needed to speak to it at
  /// all: it recognises this one and no other.
  final String ownerAid;

  final String adoptedAt;
  final String lastSeenAt;

  factory AdoptedAgent.fromJson(Map<String, dynamic> json) => AdoptedAgent(
        aid: (json['aid'] ?? '') as String,
        signsAsAid: (json['signs_as_aid'] ?? json['delegated_aid'] ?? '') as String,
        url: (json['url'] ?? '') as String,
        kind: (json['kind'] ?? 'individual') as String,
        label: (json['label'] ?? '') as String,
        sealed: (json['sealed'] ?? false) as bool,
        measurement: (json['measurement'] ?? '') as String,
        ownerAid: (json['owner_aid'] ?? '') as String,
        adoptedAt: (json['adopted_at'] ?? '') as String,
        lastSeenAt: (json['last_seen_at'] ?? '') as String,
      );

  /// What to call this machine on screen. Falls back to something a person can
  /// recognise rather than an identifier they cannot.
  String get displayName {
    if (label.isNotEmpty) return label;
    if (url.isNotEmpty) {
      final host = Uri.tryParse(url)?.host ?? '';
      if (host.isNotEmpty) return host;
    }
    return kind == 'organization' ? 'Organisation agent' : 'Agent';
  }
}


/// What an agent reports about its own foundations.
///
/// Every field that can be checked carries one of three answers — verified,
/// unknown, absent — because "nobody could check" and "checked, and it is not
/// there" are different facts and only one of them is a reason to stop.
class AttestationLineageDto {
  const AttestationLineageDto({
    required this.deviceName,
    required this.sealedHardware,
    this.chipVendor = '',
    this.chipId = '',
    this.chainVerified = 'unknown',
    this.reportSignatureVerified = 'unknown',
    this.measurement = '',
    this.buildName = '',
    this.measurementMatchesExpected = 'unknown',
    this.debugDisabled = 'unknown',
    this.diskEncrypted = 'unknown',
    this.ownerRecoveryPresent = 'unknown',
    this.hardwareKeyProtection = 'unknown',
    this.hardwareKeyName = '',
    this.signsAsAid = '',
    this.ownerAid = '',
    this.checkedAt = '',
  });

  final String deviceName;
  final bool sealedHardware;
  final String chipVendor;
  final String chipId;
  final String chainVerified;
  final String reportSignatureVerified;
  final String measurement;
  final String buildName;
  final String measurementMatchesExpected;
  final String debugDisabled;
  final String diskEncrypted;
  final String ownerRecoveryPresent;
  final String hardwareKeyProtection;
  final String hardwareKeyName;
  final String signsAsAid;
  final String ownerAid;
  final String checkedAt;

  static String _s(Map<String, dynamic> j, String k, [String d = '']) =>
      (j[k] ?? d) as String;

  factory AttestationLineageDto.fromJson(Map<String, dynamic> json) =>
      AttestationLineageDto(
        deviceName: _s(json, 'device_name', 'This computer'),
        sealedHardware: (json['sealed_hardware'] ?? false) as bool,
        chipVendor: _s(json, 'chip_vendor'),
        chipId: _s(json, 'chip_id'),
        chainVerified: _s(json, 'chain_verified', 'unknown'),
        reportSignatureVerified: _s(json, 'report_signature_verified', 'unknown'),
        measurement: _s(json, 'measurement'),
        buildName: _s(json, 'build_name'),
        measurementMatchesExpected:
            _s(json, 'measurement_matches_expected', 'unknown'),
        debugDisabled: _s(json, 'debug_disabled', 'unknown'),
        diskEncrypted: _s(json, 'disk_encrypted', 'unknown'),
        ownerRecoveryPresent: _s(json, 'owner_recovery_present', 'unknown'),
        hardwareKeyProtection: _s(json, 'hardware_key_protection', 'unknown'),
        hardwareKeyName: _s(json, 'hardware_key_name'),
        signsAsAid: _s(json, 'signs_as_aid').isNotEmpty
            ? _s(json, 'signs_as_aid')
            : _s(json, 'delegated_aid'),
        ownerAid: _s(json, 'owner_aid'),
        checkedAt: _s(json, 'checked_at'),
      );
}

/// A standing offer to pair the computer it came from.
class ComputerPairingOffer {
  const ComputerPairingOffer({
    required this.code,
    required this.validFor,
    this.address = '',
  });

  /// Shown on this computer's screen and typed or scanned into the device
  /// holding the identity that will own it. Never sent anywhere by this app.
  final String code;

  /// How long it stands, shown as a countdown so somebody who walked away
  /// knows to ask for a new one.
  final Duration validFor;

  /// Where another device can reach this computer.
  ///
  /// From the agent rather than from this app: the app talks to it over
  /// loopback, which is the one address that would send a phone to itself.
  final String address;
}

/// What has become of the code a computer is showing.
class ThisComputersPairing {
  const ThisComputersPairing({
    required this.code,
    required this.remaining,
    required this.claimedBy,
    required this.paired,
    this.address = '',
  });

  final String code;
  final Duration remaining;

  /// The identity that said it will claim this machine. Empty until somebody
  /// scans. Shown on screen so a claim by anybody else is visible at once.
  final String claimedBy;

  /// Whether the machine now has an identity of its own.
  final bool paired;

  /// Where another device can reach this computer.
  final String address;
}
