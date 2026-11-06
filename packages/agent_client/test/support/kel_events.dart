import 'dart:convert';

import 'package:agent_client/crypto/owner_signature.dart';

/// A KERI 1.0 JSON event with its digest (and, for a founding, identifier)
/// filled in, from fields in order. The core's parser then confirms the digest,
/// so an event made here that the parser accepts is a real event.
///
/// [fields] carries `d` (and, for a founding, `i`) at the place the event
/// serialises them, with any value: both are overwritten.
List<int> saidified(Map<String, Object?> fields) {
  const placeholder = '############################################';
  final m = <String, Object?>{'v': 'KERI10JSON000000_', ...fields};
  m['d'] = placeholder;
  if (m['t'] == 'icp') m['i'] = placeholder;
  final size = utf8.encode(jsonEncode(m)).length;
  m['v'] = 'KERI10JSON${size.toRadixString(16).padLeft(6, '0')}_';
  final said = OwnerSignature.blake3QB64(utf8.encode(jsonEncode(m)));
  m['d'] = said;
  if (m['t'] == 'icp') m['i'] = said;
  return utf8.encode(jsonEncode(m));
}
