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
///
/// **Readable after the first unlock, and not before.** A background look runs
/// while the phone is usually locked, and a keychain item kept "only while
/// unlocked" cannot be read then, so the look would never see a change. The
/// price is that the code can be read by this app while the phone is locked but
/// has been unlocked once since it started: the usual choice for a background
/// reader, and the code lets this phone sign only for that one change, and only
/// the rotation its person was shown. Entries kept before this are rewritten
/// once under the new setting ([all] does it the first time the phone can read
/// them).
///
/// Changes to the list are made under a short lease kept beside it, because a
/// background look and the app can both change it at once, and a change lost
/// there is the phone's only way back to that change.
class OwnershipChangesInProgress {
  OwnershipChangesInProgress({FlutterSecureStorage? storage, Duration lease = const Duration(seconds: 10)})
      : _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(encryptedSharedPreferences: true),
              iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock_this_device),
              mOptions: MacOsOptions(useDataProtectionKeyChain: false),
            ),
        _lease = lease;
  final FlutterSecureStorage _storage;
  final Duration _lease;
  static const _key = 'ownership_changes_in_progress';
  static const _upgraded = 'ownership_changes_readable_after_first_unlock';
  static const _lockKey = 'ownership_changes_lock';
  static const _beforeUpgrade = 'ownership_changes_before_upgrade';

  /// Rewrites what an earlier version kept under the old setting, once, under the
  /// lease (so a change added at the same moment is not overwritten by the old
  /// list) and without a moment at which the list exists nowhere: it is written
  /// to a second key first, and a list found there with none in its place is put
  /// back. A read that fails (the phone is locked and has not been unlocked since
  /// it started) leaves it for the next.
  Future<void> _upgradeOnce() async {
    try {
      if (await _storage.read(key: _upgraded) == '1') return;
      await _exclusively(() async {
        if (await _storage.read(key: _upgraded) == '1') return;
        var raw = await _storage.read(key: _key);
        raw ??= await _storage.read(key: _beforeUpgrade);
        if (raw != null) {
          await _storage.write(key: _beforeUpgrade, value: raw);
          await _storage.delete(key: _key);
          await _storage.write(key: _key, value: raw);
          await _storage.delete(key: _beforeUpgrade);
        }
        await _storage.write(key: _upgraded, value: '1');
      });
    } catch (_) {/* looked at again the next time */}
  }

  Future<List<AnOwnershipChange>> all() async {
    await _upgradeOnce();
    return _read();
  }

  /// The list as it is kept, without the upgrade (callers have made it).
  Future<List<AnOwnershipChange>> _read() async {
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
    await _upgradeOnce();
    await _exclusively(() => _change(
        (all) => [for (final c in all) if (c.token != change.token) c, change]));
  }

  Future<void> remove(String token) async {
    await _upgradeOnce();
    await _exclusively(() => _change((all) => [for (final c in all) if (c.token != token) c]));
  }

  /// Reads the list, makes [edit] of it, writes it, and reads it back: if what is
  /// there is not what was written, somebody wrote at the same moment (the lease
  /// is not a lock a second isolate is made to wait on), so the edit is made again
  /// to the list that is there now.
  Future<void> _change(List<AnOwnershipChange> Function(List<AnOwnershipChange> all) edit) async {
    for (var i = 0; i < 4; i++) {
      final written = jsonEncode([for (final c in edit(await _read())) c.toJson()]);
      await _storage.write(key: _key, value: written);
      if (await _storage.read(key: _key) == written) return;
    }
  }

  /// Runs [change] holding the lease, or without it if it cannot be had in a
  /// couple of seconds: a stuck holder must not stop a person agreeing to
  /// something. The lease expires on its own.
  Future<void> _exclusively(Future<void> Function() change) async {
    final me = '${DateTime.now().microsecondsSinceEpoch}-${identityHashCode(this)}';
    var held = false;
    for (var i = 0; i < 40 && !held; i++) {
      try {
        final cur = await _storage.read(key: _lockKey);
        final expires = cur == null ? 0 : int.tryParse(cur.split('|').last) ?? 0;
        if (cur == null || expires < DateTime.now().millisecondsSinceEpoch) {
          await _storage.write(
              key: _lockKey,
              value: '$me|${DateTime.now().add(_lease).millisecondsSinceEpoch}');
          held = (await _storage.read(key: _lockKey))?.startsWith('$me|') ?? false;
        }
      } catch (_) {
        break;
      }
      if (!held) await Future<void>.delayed(const Duration(milliseconds: 50));
    }
    try {
      await change();
    } finally {
      if (held) {
        try {
          // Only if it is still ours: a lease that ran out and was taken by
          // another must not be deleted from under them.
          if ((await _storage.read(key: _lockKey))?.startsWith('$me|') ?? false) {
            await _storage.delete(key: _lockKey);
          }
        } catch (_) {/* it expires */}
      }
    }
  }
}
