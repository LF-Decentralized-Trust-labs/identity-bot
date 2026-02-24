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

  OobiResponse({required this.oobiUrl, required this.aid, required this.publicKey, required this.baseUrl});

  factory OobiResponse.fromJson(Map<String, dynamic> json) {
    return OobiResponse(
      oobiUrl: json['oobi_url'] ?? '',
      aid: json['aid'] ?? '',
      publicKey: json['public_key'] ?? '',
      baseUrl: json['base_url'] ?? '',
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

class ContactResponse {
  final String aid;
  final String alias;
  final String publicKey;
  final String oobiUrl;
  final bool verified;
  final String discoveredAt;
  final String status;
  final String role;
  final JCardResponse? jcard;

  ContactResponse({
    required this.aid,
    required this.alias,
    required this.publicKey,
    required this.oobiUrl,
    required this.verified,
    required this.discoveredAt,
    this.status = '',
    this.role = 'agent',
    this.jcard,
  });

  bool get isMutual => status == 'mutual';
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
      role: json['role'] ?? 'agent',
      jcard: json['jcard'] != null ? JCardResponse.fromJson(json['jcard']) : null,
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
  final int count;

  AlertsResponse({required this.alerts, required this.count});

  factory AlertsResponse.fromJson(Map<String, dynamic> json) {
    return AlertsResponse(
      alerts: (json['alerts'] as List<dynamic>?)?.map((c) => ContactResponse.fromJson(c)).toList() ?? [],
      count: json['count'] ?? 0,
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

  Future<OobiResponse> getOobi() async {
    final response = await _client.get(Uri.parse('$baseUrl/api/oobi'));
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

  Future<ContactResponse> addContact({required String oobiUrl, String? alias}) async {
    final response = await _client.post(
      Uri.parse('$baseUrl/api/contacts'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'oobi_url': oobiUrl, if (alias != null) 'alias': alias}),
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

  Future<ContactResponse> acceptContact(String aid) async {
    final response = await _client.post(Uri.parse('$baseUrl/api/contacts/$aid/accept'));
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

  Future<void> saveTunnelSettings({
    required String provider,
    String? ngrokAuthToken,
    String? cloudflareTunnelToken,
  }) async {
    final response = await _client.put(
      Uri.parse('$baseUrl/api/settings/tunnel'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'provider': provider,
        if (ngrokAuthToken != null) 'ngrok_auth_token': ngrokAuthToken,
        if (cloudflareTunnelToken != null) 'cloudflare_tunnel_token': cloudflareTunnelToken,
      }),
    );
    if (response.statusCode != 200) {
      final body = jsonDecode(response.body);
      throw Exception(body['error'] ?? 'Save settings failed: ${response.statusCode}');
    }
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

  void dispose() {
    _client.close();
  }
}
