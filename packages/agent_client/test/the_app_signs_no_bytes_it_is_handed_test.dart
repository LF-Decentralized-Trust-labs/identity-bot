import 'dart:io';

import 'package:test/test.dart';

/// Nothing the app offers signs bytes it is handed with the key in force
/// unchecked: a key event's bytes passed to such a call would be signed without
/// `ExpectedEvent` ever having judged them (ADR-061 section 5). An event is
/// signed in `TheKeyEventsThisDeviceMakes` and `signing_an_event.dart`, after
/// it is parsed and compared with the event this phrase makes; an owner request
/// and a presentation are signed in the two other places named here.
void main() {
  final lib = Directory('lib');

  test('KeriService and its implementation have no call that signs given bytes',
      () {
    for (final f in [
      'lib/services/keri_service.dart',
      'lib/services/local_core_keri_service.dart',
    ]) {
      expect(File(f).readAsStringSync(), isNot(contains('signPayload')),
          reason: f);
    }
  });

  test('every place the app signs with a key is one that judges what it signs',
      () {
    final signs = <String>{
      for (final f in lib.listSync(recursive: true).whereType<File>())
        if (f.path.endsWith('.dart') &&
            RegExp(r'\bed\.sign\(').hasMatch(f.readAsStringSync()))
          f.path.replaceAll('\\', '/')
    };
    expect(signs, {
      // An event, after ExpectedEvent has judged it.
      'lib/services/the_key_events_this_device_makes.dart',
      'lib/services/signing_an_event.dart',
      // A presentation, whose said is the credential's own.
      'lib/services/local_core_keri_service.dart',
      // An owner's request, over the path and key state it names.
      'lib/crypto/owner_signature.dart',
    }, reason: 'a new place that signs must be added here, and judge its bytes');
  });
}
