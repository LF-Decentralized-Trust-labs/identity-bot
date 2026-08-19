// The client half of B5 and B6.
//
// Two things it must get right. The offer has to default to holding nothing,
// or a machine starts storing strangers' data because somebody upgraded it. And
// what a machine reports about what it holds has to be enough to manage disk
// and spot a backup that stopped arriving, and never enough to read anything.

import 'package:agent_client/services/backup_service.dart';
import 'package:test/test.dart';

void main() {
  group('the offer', () {
    test('a machine that has not been asked holds nothing for anyone', () {
      const fresh = HoldingOffer();
      expect(fresh.accepting, isFalse);
      expect(fresh.acceptingNewIdentities, isFalse);
    });

    test('a config written before this existed decodes to holding nothing', () {
      // The upgrade case. An older agent's config has no offer at all, and the
      // dangerous direction of a parsing default is "yes".
      final old = HoldingOffer.fromJson(<String, dynamic>{});
      expect(old.accepting, isFalse);
      expect(old.acceptingNewIdentities, isFalse);
      expect(old.reserveBytes, greaterThan(0),
          reason: 'a zero reserve means fill the disk completely');
    });

    test('taking on nobody new does not stop the ones already here', () {
      // Collapsing these two produces the failure the setting exists to
      // prevent: a destination somebody added, was confirmed, and that holds
      // only their first archive.
      const o = HoldingOffer(accepting: true, acceptingNewIdentities: false);
      expect(o.accepting, isTrue);
      expect(o.acceptingNewIdentities, isFalse);

      final reopened = o.copyWith(acceptingNewIdentities: true);
      expect(reopened.accepting, isTrue);
      expect(reopened.acceptingNewIdentities, isTrue);
      expect(reopened.reserveBytes, o.reserveBytes,
          reason: 'changing one setting silently changed the disk reserve');
    });
  });

  group('what a machine reports holding', () {
    test('carries when the last archive arrived, not only a count', () {
      // An identity that stopped pushing three months ago looks exactly like a
      // healthy one if all you show is how many archives there are.
      final held = HeldArchives.fromJson({
        'identity_aid': 'EAbc',
        'archives': 4,
        'total_bytes': 900000,
        'last_arrived_at': '2026-08-19T09:00:00Z',
      });

      expect(held.identityAid, 'EAbc');
      expect(held.archives, 4);
      expect(held.totalBytes, 900000);
      expect(held.lastArrivedAt, isNotNull);
    });

    test('an entry that never says when is not silently dated', () {
      final held = HeldArchives.fromJson({
        'identity_aid': 'EAbc',
        'archives': 1,
        'total_bytes': 10,
      });
      // Null, so a screen has to say it does not know rather than showing a
      // date it invented.
      expect(held.lastArrivedAt, isNull);
    });

    test('there is no way to ask for contents', () {
      // The arrangement only works because the holder cannot read what it
      // holds. If a method ever appears here that returns archive bytes for
      // somebody else's identity, that is the thing to argue about.
      final surface = BackupService.whatThisMachineHolds;
      expect(surface, isA<Future<List<HeldArchives>> Function()>());
    });
  });
}
