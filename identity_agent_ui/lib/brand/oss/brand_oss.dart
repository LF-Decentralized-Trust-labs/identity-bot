import 'package:flutter/material.dart';

import '../brand.dart';

/// OSS / public brand (IdentityBot).
/// Source of truth for public identity-bot builds.
class IdentityBotBrand implements Brand {
  const IdentityBotBrand();

  @override
  String get name => 'IdentityBot';

  @override
  String get displayName => 'Identity Agent';

  @override
  Color get primary => const Color(0xFF4589FF);

  @override
  Color get primaryLight => const Color(0xFF78A9FF);

  @override
  Color get primaryDark => const Color(0xFF0F62FE);
}
