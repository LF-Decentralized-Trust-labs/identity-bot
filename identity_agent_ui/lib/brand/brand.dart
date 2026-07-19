import 'package:flutter/material.dart';

import 'oss/brand_oss.dart';

/// Brand interface — selected at compile time via --dart-define=BRAND .
/// 
/// The interface + the OSS (IdentityBot) implementation live in this public repo.
/// Non-default brands are supplied by downstream builds via a build-time overlay
/// and are not present in this public source.
abstract class Brand {
  /// Canonical short brand name for the build (e.g. "IdentityBot").
  String get name;

  /// Human-facing display / window / title name (e.g. "Identity Agent").
  String get displayName;

  /// Primary brand color.
  Color get primary;

  /// Primary light variant.
  Color get primaryLight;

  /// Primary dark variant.
  Color get primaryDark;
}

/// Current brand for this build. Const-evaluated from dart-define.
/// Defaults to 'oss' (IdentityBot).
Brand get currentBrand {
  const flavor = String.fromEnvironment('BRAND', defaultValue: 'oss');
  return const IdentityBotBrand();
}
