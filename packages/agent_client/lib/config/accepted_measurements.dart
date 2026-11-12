/// Handing the publisher's signed measurement list to the core.
///
/// A machine that proves what it launched has said what it is. Whether the
/// owner accepts that software is a different question, and the CORE answers
/// it, not this app: the core checks the list against the publisher key pinned
/// in its own build, refuses a list older than one it already accepted, honours
/// the list's expiry and each entry's validity window, and never falls back to
/// its bootstrap once a list was accepted (`identity-agent-core/server`,
/// `measurementPolicy`; ADR-076).
///
/// So this app only SUPPLIES the list. [refreshMeasurementList] writes the
/// signed bytes to `measurement_list.json` in the active identity's data
/// directory, where the core reads them (and re-reads them on every decision,
/// so a refresh reaches a core that is already running). Nothing here is sent
/// to the core as the owner's `accepted_measurements`: that field is only for
/// an owner's explicit statement about an image they built themselves, and an
/// adoption that carried the app's own list there would bypass the core's
/// floor, expiry and retirement, leaving security the weaker of two sides.
///
/// This app does keep a check of its own, with the same rules as the core and
/// tested against the core's vectors ([verifyMeasurementList]), but only to
/// avoid replacing a good staged list with a damaged, expired or older one.
/// It holds no floor of its own (the core's, in the data directory, decides),
/// so there is nothing here for another process of the user to delete in order
/// to reopen an older list.
///
/// Where the list comes from, in order: `MEASUREMENT_LIST_URL` (the address
/// the publisher tool writes to), then the bundled `assets/measurement_list/measurement_list.json`
/// for a first start with no network. Both are signed, so neither is trusted
/// for where it came from. The key is `MEASUREMENT_PUBLISHER_KEY_HEX` and
/// `MEASUREMENT_PUBLISHER_KEY_ID` at build time, and a production build fails
/// without them (the build scripts).
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:flutter/services.dart' show rootBundle;
import 'package:http/http.dart' as http;

import '../services/identity_profiles.dart';
import 'measurement_list.dart';

/// The publisher key pinned in this build. Empty verifies no list. Not read
/// from anywhere at run time: whoever starts the app is not who decides whom
/// the owner trusts.
const String _publisherKeyHex = String.fromEnvironment('MEASUREMENT_PUBLISHER_KEY_HEX');
const String _publisherKeyId = String.fromEnvironment('MEASUREMENT_PUBLISHER_KEY_ID');
const String _listUrl = String.fromEnvironment('MEASUREMENT_LIST_URL');

const String bundledMeasurementListAsset = 'assets/measurement_list/measurement_list.json';

/// The file the core reads when AGENT_MEASUREMENT_LIST_FILE is not set. Must
/// match `defaultMeasurementListFile` in the core's server package.
const String stagedMeasurementListName = 'measurement_list.json';

/// Where lists come from, in order. Each is tried until one is usable.
typedef MeasurementListSource = Future<Uint8List?> Function();

Future<Uint8List?> _fromUrl() async {
  if (_listUrl.isEmpty) return null;
  final r = await http.get(Uri.parse(_listUrl)).timeout(const Duration(seconds: 10));
  return r.statusCode == 200 ? r.bodyBytes : null;
}

Future<Uint8List?> _fromAsset() async =>
    (await rootBundle.load(bundledMeasurementListAsset)).buffer.asUint8List();

/// Leave the newest usable signed list where the core of [dataDir] reads it.
///
/// Returns the sequence now staged, or null when there is none. Never throws
/// for a source that fails; a failed refresh leaves what was staged.
///
/// A candidate replaces the staged list only if it verifies now against the
/// pinned key and is not older than the staged one (and is the same list if
/// it has the same sequence). The core makes its own decision from whatever is
/// in the file; this only keeps a bad fetch from displacing a good file.
/// Every parameter but [dataDir] is a seam for tests.
Future<int?> stageMeasurementList(
  String dataDir, {
  DateTime? now,
  String publisherKeyHex = _publisherKeyHex,
  String publisherKeyId = _publisherKeyId,
  List<MeasurementListSource>? sources,
}) async {
  final at = (now ?? DateTime.now()).toUtc();
  final target = File('$dataDir${Platform.pathSeparator}$stagedMeasurementListName');

  VerifiedMeasurementList? staged;
  try {
    staged = verifyMeasurementList(await target.readAsBytes(),
        publisherKeyHex: publisherKeyHex, publisherKeyId: publisherKeyId, now: at);
  } catch (_) {
    // Absent, damaged or expired: nothing to protect from replacement.
  }

  for (final source in sources ?? const [_fromUrl, _fromAsset]) {
    try {
      final raw = await source();
      if (raw == null) continue;
      final list = verifyMeasurementList(raw,
          publisherKeyHex: publisherKeyHex,
          publisherKeyId: publisherKeyId,
          now: at,
          minSequence: staged?.sequence ?? 0,
          seenDigest: staged?.digest ?? '');
      if (staged != null && list.digest == staged.digest) return staged.sequence;
      final tmp = File('${target.path}.new');
      await tmp.writeAsBytes(raw, flush: true);
      await tmp.rename(target.path);
      return list.sequence;
    } catch (_) {
      // This source did not give a usable list; try the next.
    }
  }
  return staged?.sequence;
}

/// [stageMeasurementList] for the active identity's data directory. Call
/// before an adoption, and before the core starts.
///
/// Never throws: a list that cannot be refreshed leaves the one already staged,
/// and the core decides from that.
Future<int?> refreshMeasurementList() async {
  try {
    return await stageMeasurementList(await IdentityProfiles.dataDirectoryForActive());
  } catch (_) {
    return null;
  }
}
