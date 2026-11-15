import 'package:agent_client/services/ownership_changes_in_progress.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:test/test.dart';

// The phone looks for owed signatures while it is usually locked, so the list of
// changes it agreed to must be readable then: entries kept under the old
// setting are rewritten once, under the new one. The app and a background look
// both change the list, and neither may lose the other's change.

/// A secure storage in memory that records what was done to it.
class Recording extends FlutterSecureStorage {
  Recording(this.values);
  final Map<String, String> values;
  final ops = <String>[];
  @override
  Future<String?> read({required String key, IOSOptions? iOptions, AndroidOptions? aOptions, LinuxOptions? lOptions, WebOptions? webOptions, MacOsOptions? mOptions, WindowsOptions? wOptions}) async {
    await Future<void>.delayed(Duration.zero);
    return values[key];
  }

  @override
  Future<void> write({required String key, required String? value, IOSOptions? iOptions, AndroidOptions? aOptions, LinuxOptions? lOptions, WebOptions? webOptions, MacOsOptions? mOptions, WindowsOptions? wOptions}) async {
    await Future<void>.delayed(Duration.zero);
    ops.add('write $key');
    if (value == null) {
      values.remove(key);
    } else {
      values[key] = value;
    }
  }

  @override
  Future<void> delete({required String key, IOSOptions? iOptions, AndroidOptions? aOptions, LinuxOptions? lOptions, WebOptions? webOptions, MacOsOptions? mOptions, WindowsOptions? wOptions}) async {
    await Future<void>.delayed(Duration.zero);
    ops.add('delete $key');
    values.remove(key);
  }
}

AnOwnershipChange change(int i) =>
    AnOwnershipChange(orgUrl: 'https://o$i.example', token: 'tok-$i', me: 'EMe', orgName: 'Org $i');

void main() {
  test('what an earlier version kept is rewritten once, and then left alone', () async {
    final storage = Recording({
      'ownership_changes_in_progress':
          '[{"org_url":"https://o.example","token":"tok","me":"EMe","org_name":"Acme"}]',
    });
    final store = OwnershipChangesInProgress(storage: storage);
    expect((await store.all()).single.token, 'tok');
    expect(storage.ops, ['delete ownership_changes_in_progress', 'write ownership_changes_in_progress',
      'write ownership_changes_readable_after_first_unlock']);
    storage.ops.clear();
    await store.all();
    await store.all();
    expect(storage.ops, isEmpty, reason: 'it was rewritten again');
  });

  test('a phone with nothing kept writes nothing but the mark', () async {
    final storage = Recording({});
    expect(await OwnershipChangesInProgress(storage: storage).all(), isEmpty);
    expect(storage.ops, ['write ownership_changes_readable_after_first_unlock']);
  });

  test('the app and a background look changing the list at once lose nothing', () async {
    final values = <String, String>{};
    final app = OwnershipChangesInProgress(storage: Recording(values));
    final background = OwnershipChangesInProgress(storage: Recording(values));
    await Future.wait([
      for (var i = 0; i < 8; i++) app.add(change(i)),
      for (var i = 8; i < 16; i++) background.add(change(i)),
    ]);
    expect((await app.all()).map((c) => c.token).toSet(), {for (var i = 0; i < 16; i++) 'tok-$i'});
    await Future.wait([
      for (var i = 0; i < 8; i++) background.remove('tok-$i'),
      app.add(change(99)),
    ]);
    expect((await app.all()).map((c) => c.token).toSet(), {for (var i = 8; i < 16; i++) 'tok-$i', 'tok-99'});
  });

  test('a lease nobody released does not stop a change being kept', () async {
    final values = {'ownership_changes_lock': 'someone|${DateTime.now().add(const Duration(minutes: 5)).millisecondsSinceEpoch}'};
    final store = OwnershipChangesInProgress(storage: Recording(values));
    await store.add(change(1));
    expect((await store.all()).single.token, 'tok-1');
  });
}
