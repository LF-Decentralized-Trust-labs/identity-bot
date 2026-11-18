import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:login_dart/app_session.dart';

/// Keeps an app-key grant in the platform's secure storage, so an installed
/// front end stays signed in across restarts until the grant is ended (an
/// app-key grant has no lapse of its own, ADR-072 Amendment 3).
class SecureGrantStore implements GrantStore {
  final FlutterSecureStorage _storage;
  final String _slot;

  /// [slot] names the app and its link, so two apps (or two back ends) never
  /// share a grant: use `grantSlot(link)`.
  SecureGrantStore(this._slot, {FlutterSecureStorage? storage})
      : _storage = storage ?? const FlutterSecureStorage();

  @override
  Future<String?> read() => _storage.read(key: _slot);
  @override
  Future<void> write(String token) => _storage.write(key: _slot, value: token);
  @override
  Future<void> clear() => _storage.delete(key: _slot);
}

/// What a grant is kept under: the app, its relay identifier and its back end's
/// address, as the browser SDK's `linkSlot` does, so a crafted link naming the
/// same app with another relay or back end is another place.
String grantSlot(String aid, String rid, String api) =>
    'identity-agent.grant:$aid|$rid|$api';
