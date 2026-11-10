import 'package:flutter/foundation.dart';

import 'core_service.dart';
import 'identity_profiles.dart';
import 'the_core_is_settled.dart';

/// For widget tests, which have no core beside them to ask: replaces the
/// question "does the open profile hold an identity". Never set outside a test:
/// it is honoured only in a debug build, so a release build ignores it.
@visibleForTesting
Future<bool> Function()? theOpenProfileHoldsAnIdentityForTests;

Future<bool> Function()? _theTestsAnswerIfDebug() =>
    kDebugMode ? theOpenProfileHoldsAnIdentityForTests : null;

/// Making room, before this app founds an identity or is connected to an
/// Identity Agent elsewhere,
/// so that what is recorded lands on a profile of its own.
///
/// An installation that already holds an identity must not be turned into a
/// front end for another one: the connection is recorded per profile, and the
/// open profile's own identity would be hidden behind it. So when the open
/// profile holds one, a fresh profile is begun first.
///
/// ONE IMPLEMENTATION FOR BOTH APPS ON EVERY PLATFORM. It was two: the
/// organisation app did it on desktop only and did nothing on a phone, and the
/// individual app swallowed a failure to begin a profile and carried on, so a
/// failure there went on to overwrite what it was meant to protect. A phone
/// stops its linked core and starts another through the same
/// [IdentityProfiles.beginANewOne], so there is no reason for it to differ.
///
/// Returns whether a new profile was begun. Throws when one was needed and could
/// not be, and the caller must NOT go on to connect: the connection would land
/// on the profile that holds the identity.
Future<bool> makeRoomOnAProfile({
  Future<bool> Function()? holdsAnIdentity,
  Future<void> Function()? beginAProfile,
}) async {
  if (!await (holdsAnIdentity ?? _theTestsAnswerIfDebug() ?? _theOpenProfileHoldsAnIdentity)()) {
    return false;
  }
  await TheCoreIsSettled.during(
      beginAProfile ?? () => IdentityProfiles.beginANewOne());
  return true;
}

/// Whether the open profile holds an identity. A failure to find out is NOT
/// "no identity held": connecting on a profile that does hold one hides it
/// behind the connection, so this throws and nothing is connected (the callers
/// say so in plain words and nothing was changed). An agent that answers that it
/// is not this person's is one that exists, so room is made.
Future<bool> _theOpenProfileHoldsAnIdentity() =>
    theOpenProfileHoldsAnIdentity();

/// [makeCore] is a seam for tests, which have no core.
@visibleForTesting
Future<bool> theOpenProfileHoldsAnIdentity({CoreService Function()? makeCore}) async {
  final core = (makeCore ?? CoreService.new)();
  try {
    final identity = await core.getIdentity();
    return identity.initialized && (identity.aid ?? '').isNotEmpty;
  } on AgentNotYoursException {
    return true;
  } catch (e) {
    debugPrint('[connect] could not tell whether this profile holds an '
        'identity, so nothing is connected: $e');
    rethrow;
  } finally {
    core.dispose();
  }
}
