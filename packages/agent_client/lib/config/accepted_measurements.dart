/// Handing the publisher's list of accepted software to the core.
///
/// A machine that proves what it launched has said what it is. Whether the
/// owner accepts that software is a different question, and the CORE answers
/// it, not this app: the list is a credential issued under the publisher's
/// identity and anchored in that identity's witnessed key history, which this
/// build's core pins (an identifier, never a key). The core asks the publisher's
/// witnesses for the publisher's latest state, checks the bundle against that and
/// against the floors it keeps, honours the list's expiry and each entry's
/// window, and never falls back to its bootstrap once a list was accepted
/// (`identity-agent-core/server`, `measurementLists.policy`; ADR-078).
///
/// So this app only SUPPLIES a bundle. It has no verifier of its own, no key and
/// no floor: whatever it fetches goes to the core, and a bad fetch can displace
/// nothing. [refreshMeasurementList] must run before an adoption is offered,
/// because the core uses a list for an hour after its witnesses were asked and
/// uses none after a restart until it is asked again.
///
/// Where the bundle comes from, in order: `MEASUREMENT_LIST_URL` (the address
/// the publisher writes the bundle to), then the bundled
/// `assets/measurement_list/measurement_bundle.json` for a first start with no
/// network. Neither is trusted for where it came from.
library;

import 'dart:typed_data';

import 'package:flutter/services.dart' show rootBundle;
import 'package:http/http.dart' as http;

import '../services/core_service.dart';
import 'the_publishers_list_verdict.dart';

const String _bundleUrl = String.fromEnvironment('MEASUREMENT_LIST_URL');

const String bundledMeasurementBundleAsset = 'assets/measurement_list/measurement_bundle.json';

/// Where bundles come from, in order. Each is tried until the core accepts one.
typedef MeasurementBundleSource = Future<Uint8List?> Function();

Future<Uint8List?> _fromUrl() async {
  if (_bundleUrl.isEmpty) return null;
  final r = await http.get(Uri.parse(_bundleUrl)).timeout(const Duration(seconds: 10));
  return r.statusCode == 200 ? r.bodyBytes : null;
}

Future<Uint8List?> _fromAsset() async =>
    (await rootBundle.load(bundledMeasurementBundleAsset)).buffer.asUint8List();

/// Hand the core a bundle until it accepts one, and say what it said.
///
/// Returns the core's verdict on the last bundle it was given, or null when no
/// source produced a bundle. Never throws for a source or a refusal: a list that
/// cannot be refreshed leaves what the core already uses, and the core decides
/// from that. A source is not asked again once the core has said the list is
/// wrong for a reason another copy of the same publisher's bundle would not
/// change (a conflicting history, a build with no publisher).
/// [sources] is a seam for tests.
Future<MeasurementListVerdict?> refreshMeasurementList(
  CoreService core, {
  List<MeasurementBundleSource>? sources,
}) async {
  MeasurementListVerdict? last;
  for (final source in sources ?? const [_fromUrl, _fromAsset]) {
    try {
      final bundle = await source();
      if (bundle == null) continue;
      last = await core.submitMeasurementList(bundle);
      if (last.accepted) return last;
      if (!last.worthTryingAgain) return last;
    } catch (_) {
      // This source or the core did not answer; try the next.
    }
  }
  return last;
}
