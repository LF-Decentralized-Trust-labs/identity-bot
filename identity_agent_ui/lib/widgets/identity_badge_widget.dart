import 'package:flutter/material.dart';

/// Abstract interface for the identity card badge slot.
///
/// Two implementations:
///   - [IdentityLevelBadge]  — default open-source NIST tier badge
///   - GrapeScoreBadge       — Grape ID proprietary score gauge (future sandbox app)
///
/// Both must implement this interface so the identity card widget can accept
/// either without modification.
abstract class IdentityBadgeWidget extends StatelessWidget {
  const IdentityBadgeWidget({super.key});

  /// Short label shown in the badge (e.g., "Verified" or "87").
  String get primaryLabel;

  /// Secondary context text (e.g., "NIST IAL-2 · AAL-2" or "Grape Score™").
  String get secondaryLabel;

  /// The semantic color: red / amber / green.
  IdentityBadgeColor get badgeColor;
}

enum IdentityBadgeColor { red, amber, green }
