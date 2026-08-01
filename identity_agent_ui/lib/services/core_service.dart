import 'dart:convert';
import 'package:http/http.dart' as http;
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

  InceptionResponse({
    required this.aid,
    required this.publicKey,
    required this.created,
  });

  factory InceptionResponse.fromJson(Map<String, dynamic> json) {
    return InceptionResponse(
      aid: json['aid'] ?? '',
      publicKey: json['public_key'] ?? '',
      created: json['created'] ?? '',
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

class CoreService {
  final String baseUrl;
  final http.Client _client;

  CoreService({String? baseUrl})
      : baseUrl = baseUrl ?? AgentConfig.coreBaseUrl,
        _client = http.Client();

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
    } else {
      throw Exception('Identity request failed: ${response.statusCode}');
    }
  }

  Future<InceptionResponse> createInception({
    required String publicKey,
    required String nextPublicKey,
  }) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/inception'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'public_key': publicKey,
        'next_public_key': nextPublicKey,
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

  /// Who owns this organisation, read from its own key event log rather than
  /// from any record beside it — so it is the same answer anybody outside the
  /// machine would get.
  Future<OrgOwners> getOwners() async {
    final response = await _client.get(Uri.parse('$baseUrl/api/owners/'));
    if (response.statusCode == 200) {
      return OrgOwners.fromJson(jsonDecode(response.body) as Map<String, dynamic>);
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

  void dispose() {
    _client.close();
  }
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

  EnclaveStatusResponse({
    required this.hardwareBacked,
    required this.backingType,
    required this.backingLabel,
    this.tpmPresent,
    this.tpmEnabled,
  });

  factory EnclaveStatusResponse.fromJson(Map<String, dynamic> json) {
    return EnclaveStatusResponse(
      hardwareBacked: json['hardwareBacked'] as bool? ?? false,
      backingType: json['backingType'] as String? ?? 'software',
      backingLabel: json['backingLabel'] as String? ?? 'Software',
      tpmPresent: json['tpmPresent'] as bool?,
      tpmEnabled: json['tpmEnabled'] as bool?,
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

/// Who owns an organisation, as its own key event log says.
class OrgOwners {
  final String aid;
  final List<String> owners;

  const OrgOwners({required this.aid, this.owners = const []});

  factory OrgOwners.fromJson(Map<String, dynamic> json) => OrgOwners(
        aid: json['aid'] ?? '',
        owners: ((json['owners'] as List<dynamic>?) ?? const [])
            .map((o) => o.toString())
            .toList(),
      );
}

/// One attempt to change who owns an organisation.
///
/// The organisation keeps working throughout. Nothing changes until every
/// invited owner has accepted — a half-applied ownership change would leave
/// some people believing they own something they do not.
class OwnerCeremony {
  final String id;
  final int threshold;
  final List<CeremonyInvitee> invited;

  /// collecting · applied · failed · abandoned
  final String status;

  /// Why it failed, in words somebody can act on. A ceremony that failed and
  /// does not say why leaves an organisation unsure whether its ownership
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
