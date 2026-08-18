import 'package:agent_client/services/identity_profiles.dart';
import 'package:test/test.dart';

/// Which identity is open, and which one was deliberately left.
///
/// These two decisions are what signing out depends on, and the obvious
/// implementation of each is wrong in a way that only shows up on the NEXT
/// start-up — which is the worst place to find it. They are separated from
/// where the answers are stored so they can be examined directly; the storage
/// and the paths need a device and are exercised there.
void main() {
  const one = 'EIdentityOne';
  const two = 'EIdentityTwo';

  group('is this the identity we were in', () {
    test('a first run is let through, having nothing to contradict it', () {
      // Refusing the only identity present because nothing has been written
      // down yet would make a fresh install look broken.
      expect(IdentityProfiles.decideIsTheOneWeWereIn(null, one), isTrue);
      expect(IdentityProfiles.decideIsTheOneWeWereIn('', one), isTrue);
    });

    test('the one we were in is recognised again', () {
      expect(IdentityProfiles.decideIsTheOneWeWereIn(one, one), isTrue);
    });

    test('a different identity at the same address is not ours', () {
      // The reason an address is not an identity: same machine, same port,
      // somebody else's Identity Agent answering.
      expect(IdentityProfiles.decideIsTheOneWeWereIn(one, two), isFalse);
    });
  });

  group('did we leave this identity', () {
    test('signing out does not make the identity a stranger', () {
      // The trap, and the reason these are two separate questions. After
      // signing out the identity is still RECOGNISED — it is still the one we
      // were in, and has not been handed to anybody. Only the choice to leave
      // changed.
      //
      // If signing out were implemented by forgetting which identity was
      // opened, this pair would read (true, false): a forgotten identity is a
      // first run, a first run is let through, and somebody who signed out
      // would be signed straight back in on the next start-up.
      expect(IdentityProfiles.decideIsTheOneWeWereIn(one, one), isTrue);
      expect(IdentityProfiles.decideDidWeLeave(one, one), isTrue);
    });

    test('an identity nobody left opens normally', () {
      expect(IdentityProfiles.decideDidWeLeave(null, one), isFalse);
    });

    test('leaving one identity does not lock out another', () {
      // Why what is stored is WHICH identity rather than a flag. Point this
      // installation at a different identity afterwards and that one was never
      // left, so it should open.
      expect(IdentityProfiles.decideDidWeLeave(one, two), isFalse);
    });

    test('an empty identity is never one we left', () {
      expect(IdentityProfiles.decideDidWeLeave(one, ''), isFalse);
      expect(IdentityProfiles.decideDidWeLeave(null, ''), isFalse);
    });
  });
}
