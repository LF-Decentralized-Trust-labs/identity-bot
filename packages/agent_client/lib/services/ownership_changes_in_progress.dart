import 'dart:convert';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import 'pairing_invitation.dart';

/// What this phone needs to follow an ownership change it agreed to: the
/// organisation's own address (the one the invitation was redeemed at), the
/// code that invitation carried, this phone's identifier among the owners, and
/// the organisation's name.
class AnOwnershipChange {
  const AnOwnershipChange(
      {required this.orgUrl,
      required this.token,
      required this.me,
      required this.orgName});
  final String orgUrl;
  final String token;
  final String me;
  final String orgName;

  Map<String, String> toJson() =>
      {'org_url': orgUrl, 'token': token, 'me': me, 'org_name': orgName};

  factory AnOwnershipChange.fromJson(Map<String, dynamic> j) => AnOwnershipChange(
      orgUrl: '${j['org_url']}',
      token: '${j['token']}',
      me: '${j['me']}',
      orgName: '${j['org_name'] ?? ''}');

  /// Reads it from the answer to agreeing to own an organisation (the
  /// `sign_org` ask's result), or null when that answer is not one of an
  /// ownership change or names an address this phone will not talk to.
  static AnOwnershipChange? from(Map<String, dynamic> agreed) {
    if (agreed['ceremony'] != true) return null;
    final token = '${agreed['invite_token'] ?? ''}';
    final me = '${agreed['pairwise_aid'] ?? ''}';
    final base = '${agreed['invited_by'] ?? ''}';
    if (token.isEmpty || me.isEmpty || base.isEmpty) return null;
    // The same reading, and the same refusals, as any address an invitation
    // names: one that is not a plain organisation address is not somewhere to go.
    final parsed = PairingInvitation.parse(PairingInvitation.link(
        host: base, code: 'x', kind: 'organisation', ownerAid: me, reportTo: base, name: ''));
    if (parsed == null) return null;
    final org = '${agreed['employer'] ?? ''}';
    return AnOwnershipChange(
        orgUrl: base.replaceAll(RegExp(r'/+$'), ''), token: token, me: me, orgName: org);
  }
}

/// The ownership changes this phone has agreed to and not yet seen finished.
///
/// A hand-over takes as long as people take, and asks this phone twice, with
/// other people's signatures in between. Without this record a phone that left
/// the screen, or was restarted, could never sign the second rotation, and the
/// first would already be in the log. In secure storage because the code in it
/// is what lets this phone's agent sign for that one change.
class OwnershipChangesInProgress {
  OwnershipChangesInProgress({FlutterSecureStorage? storage})
      : _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(encryptedSharedPreferences: true),
              mOptions: MacOsOptions(useDataProtectionKeyChain: false),
            );
  final FlutterSecureStorage _storage;
  static const _key = 'ownership_changes_in_progress';

  Future<List<AnOwnershipChange>> all() async {
    final raw = await _storage.read(key: _key);
    if (raw == null || raw.isEmpty) return const [];
    try {
      return [
        for (final j in jsonDecode(raw) as List)
          AnOwnershipChange.fromJson(Map<String, dynamic>.from(j as Map))
      ];
    } catch (_) {
      return const [];
    }
  }

  Future<void> add(AnOwnershipChange change) async {
    final kept = [for (final c in await all()) if (c.token != change.token) c, change];
    await _storage.write(key: _key, value: jsonEncode([for (final c in kept) c.toJson()]));
  }

  Future<void> remove(String token) async {
    final kept = [for (final c in await all()) if (c.token != token) c];
    await _storage.write(key: _key, value: jsonEncode([for (final c in kept) c.toJson()]));
  }
}
