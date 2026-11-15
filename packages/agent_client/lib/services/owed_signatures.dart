import 'dart:convert';

import 'package:crypto/crypto.dart';

import 'ownership_changes_in_progress.dart';
import 'the_ceremony_this_device_agreed_to.dart';
import 'the_event_this_device_expects.dart' show CeremonyStage;

/// How a person's device finds out, with the Identity Agent app closed, that a
/// signature is owed to a change of owners it agreed to, and tells its person.
///
/// It reads what the open sign screen reads (the organisation's public
/// `ceremony-terms`, reached by the code the invitation carried) and decides one
/// of four things per change: a signature is owed, so tell the person once for
/// that change and rotation; the change is over, so forget it and take back any
/// notice; it stopped, so say so once; or nothing is owed yet. It signs nothing.
/// The person signs only on the screen that shows them what they agree to.

/// Reads where the ceremony a change belongs to has got to, as
/// `CeremonyDevice.read` does.
typedef ReadsACeremony = Future<CeremonyReading?> Function(
    String orgUrl, String token);

/// What can be shown to the person outside the app. Implemented with the
/// system's notifications; a test passes a recorder.
abstract class TellsThePerson {
  /// A signature is owed to [change]'s [rotation] (1 or 2).
  Future<void> signatureIsOwed(AnOwnershipChange change,
      {required int rotation, required bool handOver});

  /// [change] stopped, and nothing is asked of the person. Nothing is said of why:
  /// the organisation's own words are on the screen the person opens, where they
  /// can be read in full and are not put on a locked screen.
  Future<void> changeStopped(AnOwnershipChange change);

  /// Takes back any notice about [change]: it was signed, or it is over.
  Future<void> takeBack(AnOwnershipChange change);
}

/// What has already been said, kept across runs, so a change is told once for
/// each rotation however many times the phone looks.
abstract class RemembersWhatWasSaid {
  Future<bool> was(String key);
  Future<void> remember(String key);
}

/// An identifier for a change that is safe to put in a notification: not the
/// code the invitation carried, which lets the device sign for that one change.
String ownershipChangeNoticeId(AnOwnershipChange change) =>
    sha256.convert(utf8.encode('ownership-change:${change.token}')).toString().substring(0, 16);

/// A small whole number for the system's notification, the same for the same change.
int ownershipChangeNoticeNumber(AnOwnershipChange change) =>
    int.parse(ownershipChangeNoticeId(change).substring(0, 7), radix: 16);

/// What one look found, for a caller that wants to say so.
class OwedSignaturesFound {
  const OwedSignaturesFound(
      {this.owed = const [], this.stopped = const [], this.ended = const []});

  /// Changes a signature is owed to now.
  final List<AnOwnershipChange> owed;

  /// Changes that stopped, and were said so.
  final List<AnOwnershipChange> stopped;

  /// Changes that are over (made, stopped or gone), now forgotten.
  final List<AnOwnershipChange> ended;
}

class OwedSignatures {
  OwedSignatures({
    required this.changes,
    required this.read,
    required this.tells,
    required this.said,
  });

  final OwnershipChangesInProgress changes;
  final ReadsACeremony read;
  final TellsThePerson tells;
  final RemembersWhatWasSaid said;

  /// Looks at every change this phone agreed to and has not seen end.
  Future<OwedSignaturesFound> look() async {
    final owed = <AnOwnershipChange>[];
    final stopped = <AnOwnershipChange>[];
    final ended = <AnOwnershipChange>[];
    for (final c in await changes.all()) {
      CeremonyReading? reading;
      try {
        reading = await read(c.orgUrl, c.token);
      } catch (_) {
        // A look that fails is not an answer: the organisation may be out of
        // reach for a while. Nothing changes, and the next look tries again.
        continue;
      }
      final id = ownershipChangeNoticeId(c);
      if (reading == null) {
        // The organisation knows no change for this code any more.
        await _over(c, id, stopped, ended, say: true);
        continue;
      }
      switch (reading.status) {
        case 'applied':
          await _over(c, id, stopped, ended, say: false);
        case 'failed':
        case 'abandoned':
          await _over(c, id, stopped, ended, say: true);
        case 'signing':
          final terms = reading.terms;
          if (terms == null) continue;
          final mine = terms.owners.where((o) => o.aid == c.me);
          if (mine.isEmpty) continue;
          final rotation = terms.stage == CeremonyStage.second ? 2 : 1;
          if (mine.first.signed) {
            await tells.takeBack(c);
            continue;
          }
          owed.add(c);
          final key = 'owed:$id:$rotation';
          if (!await said.was(key)) {
            // Remembered before it is said: a notice that failed to show is not
            // said again at every look.
            await said.remember(key);
            await tells.signatureIsOwed(c,
                rotation: rotation, handOver: terms.handOver);
          }
        default:
          break; // others have still to accept: nothing is asked of this phone yet
      }
    }
    return OwedSignaturesFound(owed: owed, stopped: stopped, ended: ended);
  }

  Future<void> _over(AnOwnershipChange c, String id, List<AnOwnershipChange> stopped,
      List<AnOwnershipChange> ended,
      {required bool say}) async {
    await changes.remove(c.token);
    await tells.takeBack(c);
    ended.add(c);
    if (say && !await said.was('stopped:$id')) {
      await said.remember('stopped:$id');
      await tells.changeStopped(c);
      stopped.add(c);
    }
  }
}
