import 'package:flutter/material.dart';
import '../services/identity_level_service.dart';
import 'identity_badge_widget.dart';

/// The default identity card badge — shows the NIST-based assurance tier.
///
/// Colors:
///   Red   → Not Verified (tier 0)
///   Amber → Basic or Authenticated (tiers 1–2)
///   Green → Verified or Highly Verified (tiers 3–4)
///
/// Tapping opens the authentication setup screen (handled by the parent card).
class IdentityLevelBadge extends IdentityBadgeWidget {
  final IdentityTier tier;
  final VoidCallback? onTap;

  const IdentityLevelBadge({
    super.key,
    required this.tier,
    this.onTap,
  });

  @override
  String get primaryLabel => tier.label;

  @override
  String get secondaryLabel => tier.nistLabel;

  @override
  IdentityBadgeColor get badgeColor {
    if (tier.isGreen) return IdentityBadgeColor.green;
    if (tier.isAmber) return IdentityBadgeColor.amber;
    return IdentityBadgeColor.red;
  }

  Color get _color {
    switch (badgeColor) {
      case IdentityBadgeColor.green: return const Color(0xFF24A148); // IBM Carbon green-50
      case IdentityBadgeColor.amber: return const Color(0xFFFF832B); // IBM Carbon orange-40
      case IdentityBadgeColor.red:   return const Color(0xFFDA1E28); // IBM Carbon red-60
    }
  }

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.end,
        mainAxisSize: MainAxisSize.min,
        children: [
          // Colored pill with shield icon + tier label
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
            decoration: BoxDecoration(
              color: _color.withOpacity(0.12),
              borderRadius: BorderRadius.circular(20),
              border: Border.all(color: _color.withOpacity(0.4), width: 1),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(
                  tier.isGreen ? Icons.shield : Icons.shield_outlined,
                  color: _color,
                  size: 14,
                ),
                const SizedBox(width: 5),
                Text(
                  tier.label,
                  style: TextStyle(
                    color: _color,
                    fontSize: 12,
                    fontWeight: FontWeight.w700,
                  ),
                ),
              ],
            ),
          ),
          // NIST subtext — only shown when there's something to show
          if (tier.nistLabel.isNotEmpty) ...[
            const SizedBox(height: 3),
            Text(
              tier.nistLabel,
              style: TextStyle(
                color: _color.withOpacity(0.7),
                fontSize: 9,
                fontWeight: FontWeight.w500,
                letterSpacing: 0.3,
              ),
            ),
          ],
        ],
      ),
    );
  }
}

/// A live-updating version that subscribes to [IdentityLevelService.tierStream].
class LiveIdentityLevelBadge extends StatefulWidget {
  final VoidCallback? onTap;

  const LiveIdentityLevelBadge({super.key, this.onTap});

  @override
  State<LiveIdentityLevelBadge> createState() => _LiveIdentityLevelBadgeState();
}

class _LiveIdentityLevelBadgeState extends State<LiveIdentityLevelBadge> {
  IdentityTier _tier = IdentityTier.notVerified;

  @override
  void initState() {
    super.initState();
    _load();
    IdentityLevelService.tierStream.listen((tier) {
      if (mounted) setState(() => _tier = tier);
    });
  }

  Future<void> _load() async {
    final tier = await IdentityLevelService.currentTier();
    if (mounted) setState(() => _tier = tier);
  }

  @override
  Widget build(BuildContext context) {
    return IdentityLevelBadge(tier: _tier, onTap: widget.onTap);
  }
}
