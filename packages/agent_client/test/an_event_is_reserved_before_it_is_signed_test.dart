import 'package:agent_client/services/the_events_this_device_signed.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:test/test.dart';

void main() {
  setUp(() {
    FlutterSecureStorage.setMockInitialValues({});
    SharedPreferences.setMockInitialValues({});
  });

  Future<Reservation> reserve(TheEventsThisDeviceSigned r, int sn, String d) =>
      r.reserve(
          aid: 'EA', sn: sn, prior: 'EP', digest: d, bytesB64: 'bytes-of-$d');

  test(
      'a second event at a reserved place is refused, and the same one is the same reservation',
      () async {
    final r = TheEventsThisDeviceSigned();
    final first = await reserve(r, 1, 'E1');
    await expectLater(
        reserve(r, 1, 'E2'), throwsA(isA<PlaceAlreadyReserved>()));
    final again = await reserve(r, 1, 'E1');
    expect(again.digest, first.digest);
    expect(await r.maySign('EA', 1, 'E1'), isTrue);
    expect(await r.maySign('EA', 1, 'E2'), isFalse);
    expect(await r.maySign('EA', 2, 'E9'), isTrue);
  });

  test(
      'after a crash between signing and committing only those bytes are there to finish',
      () async {
    final before = TheEventsThisDeviceSigned();
    final res = await reserve(before, 1, 'E1');
    await before.signedWith(res, ['AAsig']);

    // A new instance, as after a restart, reads what was written down.
    final after = TheEventsThisDeviceSigned();
    final left = await after.unfinished('EA');
    expect(left, hasLength(1));
    expect(left.single.bytesB64, 'bytes-of-E1');
    expect(left.single.signatures, ['AAsig']);
    await expectLater(
        reserve(after, 1, 'E2'), throwsA(isA<PlaceAlreadyReserved>()));

    await after.committed(left.single);
    expect(await after.unfinished('EA'), isEmpty);
    expect(await after.maySign('EA', 1, 'E2'), isTrue);
  });

  test('signed reservations are finished before unsigned ones', () async {
    final r = TheEventsThisDeviceSigned();
    await reserve(r, 2, 'E2');
    final one = await reserve(r, 1, 'E1');
    await r.signedWith(await reserve(r, 3, 'E3'), ['AAsig3']);
    await r.signedWith(one, ['AAsig1']);
    final order = [for (final x in await r.unfinished('EA')) x.sn];
    expect(order, [1, 3, 2]);
  });

  test('a recovery rotation marks the interactions it supersedes dead',
      () async {
    final r = TheEventsThisDeviceSigned();
    await r.signedWith(await reserve(r, 2, 'Eixn'), ['AAsig']);
    await reserve(r, 1, 'Ekept');
    await r.supersededBy('EA', 2);
    final left = await r.unfinished('EA');
    expect([for (final x in left) x.sn], [1]);
    // The rotation may now take the place.
    expect(await r.maySign('EA', 2, 'Erot'), isTrue);
    await reserve(r, 2, 'Erot');
  });
}
