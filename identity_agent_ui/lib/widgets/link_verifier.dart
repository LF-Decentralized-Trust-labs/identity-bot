import 'package:flutter/material.dart';
import '../services/link_verification_service.dart';

/// Trust badge widget — renders from `outcome` only, matching the link verification contract.
class LinkVerifier extends StatefulWidget {
  final String input;
  final String flow;
  final String tier;
  final bool showOwnership;
  final LinkVerificationService? service;
  final VoidCallback? onTap;

  const LinkVerifier({
    super.key,
    required this.input,
    this.flow = 'link',
    this.tier = 'free',
    this.showOwnership = true,
    this.service,
    this.onTap,
  });

  @override
  State<LinkVerifier> createState() => _LinkVerifierState();
}

class _LinkVerifierState extends State<LinkVerifier> {
  late final LinkVerificationService _service;
  VerificationResult? _result;
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _service = widget.service ?? LinkVerificationService();
    _load();
  }

  @override
  void didUpdateWidget(LinkVerifier oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.input != widget.input ||
        oldWidget.flow != widget.flow ||
        oldWidget.tier != widget.tier) {
      _load();
    }
  }

  Future<void> _load() async {
    setState(() => _loading = true);
    final result = await _service.verify(
      input: widget.input,
      flow: widget.flow,
      tier: widget.tier,
    );
    if (mounted) {
      setState(() {
        _result = result;
        _loading = false;
      });
    }
  }

  Color _colorForOutcome(String outcome) {
    switch (outcome) {
      case 'verified':
        return const Color(0xFF16A34A);
      case 'tampered':
        return const Color(0xFFDC2626);
      case 'incomplete':
        return const Color(0xFFD97706);
      default:
        return const Color(0xFF6B7280);
    }
  }

  String _labelForOutcome(String outcome) {
    switch (outcome) {
      case 'verified':
        return 'Verified';
      case 'tampered':
        return 'Tampered';
      case 'incomplete':
        return 'Incomplete';
      default:
        return 'Unverified';
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const SizedBox(
        width: 16,
        height: 16,
        child: CircularProgressIndicator(strokeWidth: 2),
      );
    }
    final result = _result ?? VerificationResult.neutral();
    final color = _colorForOutcome(result.outcome);
    final label = _labelForOutcome(result.outcome);

    return InkWell(
      onTap: widget.onTap,
      borderRadius: BorderRadius.circular(4),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 2),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(Icons.circle, size: 8, color: color),
                const SizedBox(width: 6),
                Text(
                  label,
                  style: TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                    color: color,
                  ),
                ),
                if (result.badge == 'grape_branded' && result.grapeScore != null)
                  Padding(
                    padding: const EdgeInsets.only(left: 6),
                    child: Text(
                      '${result.grapeScore}',
                      style: TextStyle(fontSize: 11, color: color),
                    ),
                  ),
              ],
            ),
            if (widget.showOwnership &&
                widget.flow == 'link' &&
                result.outcome == 'verified' &&
                result.ownership != null)
              Padding(
                padding: const EdgeInsets.only(left: 14, top: 2),
                child: Text(
                  'Registered to ${result.ownership!.registeredTo}',
                  style: const TextStyle(fontSize: 11, color: Color(0xFF374151)),
                ),
              ),
          ],
        ),
      ),
    );
  }
}