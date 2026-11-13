import 'dart:convert';

import 'package:login_dart/app_checks.dart';
import 'package:login_dart/seal.dart';

// The sealing key's statement checks, run as JavaScript. Compiled by
// tool/statements_under_dart2js.sh, which passes the vectors in; read
// there, never here, so this file needs no file access. dart2js numbers are
// JavaScript numbers, so `1.0` is an `int` here: a rule that decides by Dart type
// alone passes a native run and fails this one. Exits non-zero (an uncaught
// throw) on the first case that is not as the vectors say.

const vectors = String.fromEnvironment('STATEMENT_VECTORS');

void main() {
  if (vectors.isEmpty) throw StateError('no vectors were passed in');
  final cases = (jsonDecode(vectors) as Map<String, dynamic>);
  final seal = cases['seal_key'] as Map<String, dynamic>;
  final rid = cases['rid'] as String;
  final ok = checkSealKey(rid, seal['statement'] as String);
  if (ok.log != cases['relay_log']) {
    throw StateError('the vouched statement gave another log');
  }
  final refusals = (cases['statement_refusals'] as List).cast<Map<String, dynamic>>();
  if (refusals.length < 10) throw StateError('too few refusal cases: ${refusals.length}');
  for (final c in refusals) {
    try {
      checkSealKey(c['rid'] as String, c['statement'] as String,
          known: c['known_log'] as String?, min: c['min'] as String?);
    } on TrustRefused catch (e) {
      if (!e.message.contains('sealing key is refused')) {
        throw StateError('${c['name']}: refused for another reason: ${e.message}');
      }
      continue;
    }
    throw StateError('${c['name']}: a statement the core refuses was taken');
  }
  print('dart2js: the vouched statement and ${refusals.length} refusals are as the vectors say');
}
