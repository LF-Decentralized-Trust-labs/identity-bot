import 'dart:async';
import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import '../config/agent_config.dart';
import 'pin_password_service.dart';
import 'local_auth_service.dart';

/// Identity assurance tier levels.
///
/// Maps to NIST IAL/AAL as follows:
///   0 → Pre-IAL-1  (nothing set up)
///   1 → IAL-1/AAL-1 (PIN or password — self-asserted)
///   2 → IAL-1/AAL-2 (PIN/password + biometric — authenticated)
///   3 → IAL-2/AAL-2 (all above + 3 trusted witnesses — verified)
///   4 → IAL-3/AAL-3 (all above + third-party ACDC credential — highly verified)
enum IdentityTier {
  notVerified,      // 0 — red
  selfAsserted,     // 1 — amber
  authenticated,    // 2 — amber
  verified,         // 3 — green
  highlyVerified,   // 4 — green
}

extension IdentityTierX on IdentityTier {
  int get level => index;

  String get label {
    switch (this) {
      case IdentityTier.notVerified:    return 'Not Verified';
      case IdentityTier.selfAsserted:   return 'Basic';
      case IdentityTier.authenticated:  return 'Authenticated';
      case IdentityTier.verified:       return 'Verified';
      case IdentityTier.highlyVerified: return 'Highly Verified';
    }
  }

  String get nistLabel {
    switch (this) {
      case IdentityTier.notVerified:    return '';
      case IdentityTier.selfAsserted:   return 'NIST IAL-1 · AAL-1';
      case IdentityTier.authenticated:  return 'NIST IAL-1 · AAL-2';
      case IdentityTier.verified:       return 'NIST IAL-2 · AAL-2';
      case IdentityTier.highlyVerified: return 'NIST IAL-3 · AAL-3';
    }
  }

  /// Red for tiers 0; amber for 1–2; green for 3–4.
  bool get isRed    => this == IdentityTier.notVerified;
  bool get isAmber  => this == IdentityTier.selfAsserted || this == IdentityTier.authenticated;
  bool get isGreen  => this == IdentityTier.verified || this == IdentityTier.highlyVerified;
}

/// Which factors are currently active (enrolled + working).
class ActiveFactors {
  final bool hasPin;
  final bool hasPassword;
  final bool hasBiometric;
  final int witnessCount;      // how many confirmed witnesses (max relevant = 3)
  final bool hasCredential;    // externally-issued ACDC verifiable credential

  const ActiveFactors({
    required this.hasPin,
    required this.hasPassword,
    required this.hasBiometric,
    required this.witnessCount,
    required this.hasCredential,
  });

  bool get hasKnowledgeFactor => hasPin || hasPassword;
}

class IdentityLevelService {
  static const _witnessCountKey = 'identity_level_witness_count';
  static const _hasCredentialKey = 'identity_level_has_credential';
  static const _lastAuthKey = 'identity_level_last_auth_ts';

  // Stream controller so widgets can react to tier changes.
  static final _controller = StreamController<IdentityTier>.broadcast();
  static Stream<IdentityTier> get tierStream => _controller.stream;

  // ── Factor state ──────────────────────────────────────────────────────────

  static Future<ActiveFactors> loadFactors() async {
    final prefs = await SharedPreferences.getInstance();
    final witnessCount = prefs.getInt(_witnessCountKey) ?? 0;
    final hasCredential = await _checkHasCredentialFromDB();
    final hasPin = await PinPasswordService.hasPin();
    final hasPassword = await PinPasswordService.hasPassword();
    final biometricState = await LocalAuthService.fingerprintAvailability();
    final faceState = await LocalAuthService.faceAvailability();
    final hasBiometric =
        biometricState == BiometricAvailability.available ||
        faceState == BiometricAvailability.available;

    return ActiveFactors(
      hasPin: hasPin,
      hasPassword: hasPassword,
      hasBiometric: hasBiometric,
      witnessCount: witnessCount,
      hasCredential: hasCredential,
    );
  }

  /// Checks the credentials database via the backend API for any held
  /// externally-issued credential, replacing the old SharedPreferences flag.
  static Future<bool> _checkHasCredentialFromDB() async {
    try {
      final baseUrl = AgentConfig.coreBaseUrl;
      final uri = Uri.parse('$baseUrl/api/credentials?role=holder&status=valid');
      final response = await http.get(uri).timeout(const Duration(seconds: 3));
      if (response.statusCode == 200) {
        final data = jsonDecode(response.body) as Map<String, dynamic>;
        final list = data['credentials'] as List<dynamic>? ?? [];
        return list.isNotEmpty;
      }
    } catch (_) {
      // Backend unavailable — fall back to SharedPreferences cache
      final prefs = await SharedPreferences.getInstance();
      return prefs.getBool(_hasCredentialKey) ?? false;
    }
    return false;
  }

  // ── Tier computation ──────────────────────────────────────────────────────

  static IdentityTier computeTier(ActiveFactors f) {
    if (!f.hasKnowledgeFactor) return IdentityTier.notVerified;
    if (!f.hasBiometric)       return IdentityTier.selfAsserted;
    if (f.witnessCount < 3)    return IdentityTier.authenticated;
    if (!f.hasCredential)      return IdentityTier.verified;
    return IdentityTier.highlyVerified;
  }

  static Future<IdentityTier> currentTier() async {
    final factors = await loadFactors();
    return computeTier(factors);
  }

  /// Recomputes and pushes an updated tier to [tierStream].
  static Future<void> refresh() async {
    final tier = await currentTier();
    _controller.add(tier);
  }

  // ── Factor mutations (call refresh() after each) ──────────────────────────

  static Future<void> setWitnessCount(int count) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setInt(_witnessCountKey, count);
    await refresh();
  }

  static Future<int> getWitnessCount() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getInt(_witnessCountKey) ?? 0;
  }

  static Future<void> setHasCredential({required bool value}) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool(_hasCredentialKey, value);
    await refresh();
  }

  // ── Last-auth timestamp ───────────────────────────────────────────────────

  static Future<void> recordAuthEvent() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setInt(_lastAuthKey, DateTime.now().millisecondsSinceEpoch);
  }

  static Future<DateTime?> lastAuthTime() async {
    final prefs = await SharedPreferences.getInstance();
    final ms = prefs.getInt(_lastAuthKey);
    if (ms == null) return null;
    return DateTime.fromMillisecondsSinceEpoch(ms);
  }

  /// Returns true if more than [thresholdMinutes] have passed since last auth.
  static Future<bool> isStale({int thresholdMinutes = 5}) async {
    final last = await lastAuthTime();
    if (last == null) return true;
    return DateTime.now().difference(last).inMinutes >= thresholdMinutes;
  }

  // ── Reset ─────────────────────────────────────────────────────────────────

  static Future<void> clearAll() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_witnessCountKey);
    await prefs.remove(_hasCredentialKey);
    await prefs.remove(_lastAuthKey);
    await PinPasswordService.clearAll();
    await refresh();
  }
}
