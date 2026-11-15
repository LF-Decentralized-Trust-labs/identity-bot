import 'dart:async';

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

  /// Called after each write of a key, so a test can do something at that moment.
  void Function(String key)? afterWrite;

  /// While set, a read of the list waits for it after taking the value, so a test
  /// can have another change the list in between.
  Completer<void>? holdListRead;
  final reachedTheHold = Completer<void>();
  @override
  Future<String?> read({required String key, IOSOptions? iOptions, AndroidOptions? aOptions, LinuxOptions? lOptions, WebOptions? webOptions, MacOsOptions? mOptions, WindowsOptions? wOptions}) async {
    await Future<void>.delayed(Duration.zero);
    final v = values[key];
    final hold = holdListRead;
    if (hold != null && key == 'ownership_changes_in_progress') {
      if (!reachedTheHold.isCompleted) reachedTheHold.complete();
      await hold.future;
    }
    return v;
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
    afterWrite?.call(key);
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
    // Written to a second key first, so the list is never in no place at all.
    expect(storage.ops.where((o) => !o.contains('changes_lock')).toList(), [
      'write ownership_changes_before_upgrade',
      'delete ownership_changes_in_progress',
      'write ownership_changes_in_progress',
      'delete ownership_changes_before_upgrade',
      'write ownership_changes_readable_after_first_unlock',
    ]);
    storage.ops.clear();
    await store.all();
    await store.all();
    expect(storage.ops, isEmpty, reason: 'it was rewritten again');
  });

  test('a phone with nothing kept writes nothing but the mark', () async {
    final storage = Recording({});
    expect(await OwnershipChangesInProgress(storage: storage).all(), isEmpty);
    expect(storage.ops.where((o) => !o.contains('changes_lock')).toList(), ['write ownership_changes_readable_after_first_unlock']);
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

  const old = '[{"org_url":"https://old.example","token":"tok-old","me":"EMe","org_name":"Old"}]';

  test('a change added while the first look after an upgrade rewrites the list is not lost', () async {
    // The background look reads the old list and stalls; the app, meanwhile, adds a
    // change (and upgrades what is kept, if it is let to); then the look goes on.
    final values = {'ownership_changes_in_progress': old};
    final stalled = Recording(values)..holdListRead = Completer<void>();
    final background = OwnershipChangesInProgress(storage: stalled);
    final app = OwnershipChangesInProgress(storage: Recording(values));
    final looking = background.all();
    await stalled.reachedTheHold.future;
    final adding = app.add(change(1));
    await Future<void>.delayed(const Duration(milliseconds: 100));
    stalled.holdListRead!.complete();
    await Future.wait([looking, adding]);
    expect((await app.all()).map((c) => c.token).toSet(), {'tok-old', 'tok-1'});
  });

  test('a crash between deleting the list and writing it back loses nothing', () async {
    // What a crash leaves: the copy made first, and no list.
    final values = {'ownership_changes_before_upgrade': old};
    final store = OwnershipChangesInProgress(storage: Recording(values));
    expect((await store.all()).single.token, 'tok-old');
    expect(values['ownership_changes_before_upgrade'], isNull);
    expect(values['ownership_changes_in_progress'], old);
  });

  test('a lease that ran out and was taken by someone else is not deleted from under them', () async {
    final storage = Recording({'ownership_changes_readable_after_first_unlock': '1'});
    final theirs = 'someone-else|${DateTime.now().add(const Duration(minutes: 5)).millisecondsSinceEpoch}';
    storage.afterWrite = (key) {
      // As the change is written, the lease passes to another.
      if (key == 'ownership_changes_in_progress') storage.values['ownership_changes_lock'] = theirs;
    };
    await OwnershipChangesInProgress(storage: storage).add(change(1));
    expect(storage.values['ownership_changes_lock'], theirs);
  });
}
