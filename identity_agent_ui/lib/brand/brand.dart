import 'package:flutter/material.dart';

import 'oss/brand_oss.dart';

/// Brand interface — selected at compile time via --dart-define=BRAND=oss|grapeid.
/// 
/// The interface + OSS (IdentityBot) implementation live in the public `identity-bot`
/// repo so every build (OSS and private overlays) can select a brand flavor.
/// 
/// Grape ID (and future) brand implementations live **only** in the private
/// `grapeid/*` overlay repos and are overlaid at build time for those variants.
/// No Grape ID strings, assets, or impls are present in this public source.
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
/// Default is 'oss' (IdentityBot). Private builds (grapeid/*) overlay
/// their brand/ directory (including a selector that handles 'grapeid').
Brand get currentBrand {
  const flavor = String.fromEnvironment('BRAND', defaultValue: 'oss');
  // OSS source only knows the IdentityBot impl. Grape ID etc. are supplied
  // by overlays in the private repos (see grapeid/individual prepare scripts).
  return const IdentityBotBrand();
}
