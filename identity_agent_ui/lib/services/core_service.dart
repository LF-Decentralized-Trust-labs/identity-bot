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

class AlertsResponse {
  final List<ContactResponse> alerts;
  final List<PendingRequestResponse> pendingRequests;
  final int count;

  AlertsResponse({required this.alerts, this.pendingRequests = const [], required this.count});

  factory AlertsResponse.fromJson(Map<String, dynamic> json) {
    return AlertsResponse(
      alerts: (json['alerts'] as List<dynamic>?)?.map((c) => ContactResponse.fromJson(c)).toList() ?? [],
      pendingRequests: (json['pending_requests'] as List<dynamic>?)?.map((p) => PendingRequestResponse.fromJson(p)).toList() ?? [],
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
