import 'package:agent_client/services/key_math.dart';

/// The key arithmetic of [_inner], noting each operation it is asked for, so a
/// test can show a signature was never made.
class AKeyMathThatCounts implements KeyMath {
  AKeyMathThatCounts(this._inner);
  final KeyMath _inner;

  /// The operations asked for, in order.
  final List<String> asked = [];

  /// How many ML-DSA-65 signatures were made.
  int get postQuantumSignatures =>
      asked.where((o) => o == 'sign_mldsa65').length;

  @override
  Future<Map<String, dynamic>> run(String op, Map<String, dynamic> request) {
    asked.add(op);
    return _inner.run(op, request);
  }
}
