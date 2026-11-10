import 'package:flutter/foundation.dart';

import 'core_service.dart';
import 'identity_profiles.dart';
import 'the_core_is_settled.dart';

/// Making room, before this app is connected to an Identity Agent elsewhere,
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
Future<bool> makeRoomToConnectToAnAgentElsewhere({
  Future<bool> Function()? holdsAnIdentity,
  Future<void> Function()? beginAProfile,
}) async {
  if (!await (holdsAnIdentity ?? _theOpenProfileHoldsAnIdentity)()) {
    return false;
  }
  await TheCoreIsSettled.during(
      beginAProfile ?? () => IdentityProfiles.beginANewOne());
  return true;
}

Future<bool> _theOpenProfileHoldsAnIdentity() async {
  final core = CoreService();
  try {
    final identity = await core.getIdentity();
    return identity.initialized && (identity.aid ?? '').isNotEmpty;
  } catch (e) {
    // Nothing answering is not a reason to abandon this profile: the core may
    // simply not be up yet, and starting a second profile would strand the
    // first.
    debugPrint('[connect] could not tell whether this profile holds an '
        'identity, so it is used as it is: $e');
    return false;
  } finally {
    core.dispose();
  }
}
