import 'dart:convert';
import 'package:flutter/material.dart';
import '../theme/mobile_theme.dart';

class ContactActionPopup extends StatefulWidget {
  final String name;
  final String photo;
  final String aid;
  final String actionLabel;
  final String confirmLabel;
  final String dismissLabel;
  final int confidenceScore;
  final bool? kelVerified;
  final VoidCallback onConfirm;
  final VoidCallback onDismiss;
  final VoidCallback? onBackdropTap;

  const ContactActionPopup({
    super.key,
    required this.name,
    this.photo = '',
    required this.aid,
    this.actionLabel = 'Wants to add you as a contact',
    this.confirmLabel = 'Add Contact',
    this.dismissLabel = 'Dismiss',
    this.confidenceScore = 82,
    this.kelVerified,
    required this.onConfirm,
    required this.onDismiss,
    this.onBackdropTap,
  });

  @override
  State<ContactActionPopup> createState() => _ContactActionPopupState();
}

class _ContactActionPopupState extends State<ContactActionPopup>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller;
  late final Animation<double> _scaleAnimation;
  late final Animation<double> _fadeAnimation;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 300),
    );
    _scaleAnimation = Tween<double>(begin: 0.8, end: 1.0)
        .animate(CurvedAnimation(parent: _controller, curve: Curves.easeOutBack));
    _fadeAnimation = Tween<double>(begin: 0.0, end: 1.0)
        .animate(CurvedAnimation(parent: _controller, curve: Curves.easeOut));
    _controller.forward();
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Widget _buildAvatar() {
    if (widget.photo.isNotEmpty) {
      try {
        final photoData = widget.photo.contains(',')
            ? widget.photo.split(',').last
            : widget.photo;
        return CircleAvatar(
          radius: 32,
          backgroundImage: MemoryImage(base64Decode(photoData)),
        );
      } catch (_) {}
    }
    final initials = widget.name
        .split(' ')
        .where((w) => w.isNotEmpty)
        .take(2)
        .map((w) => w[0].toUpperCase())
        .join();
    return CircleAvatar(
      radius: 32,
      backgroundColor: MobileColors.primary.withOpacity(0.12),
      child: Text(
        initials.isNotEmpty ? initials : '?',
        style: const TextStyle(
          color: MobileColors.primary,
          fontWeight: FontWeight.w700,
          fontSize: 22,
        ),
      ),
    );
  }

  String _truncatedAid() {
    if (widget.aid.length > 24) {
      return '${widget.aid.substring(0, 24)}...';
    }
    return widget.aid;
  }

  @override
  Widget build(BuildContext context) {
    final backdropHandler = widget.onBackdropTap ?? widget.onDismiss;

    return Material(
      color: Colors.transparent,
      child: FadeTransition(
        opacity: _fadeAnimation,
        child: GestureDetector(
          onTap: backdropHandler,
          child: Container(
            color: Colors.black.withOpacity(0.5),
            child: Center(
              child: GestureDetector(
                onTap: () {},
                child: ScaleTransition(
                  scale: _scaleAnimation,
                  child: Container(
                    margin: const EdgeInsets.symmetric(horizontal: 32),
                    padding: const EdgeInsets.all(24),
                    decoration: BoxDecoration(
                      color: MobileColors.surface,
                      borderRadius: BorderRadius.circular(20),
                      border: Border.all(color: MobileColors.primary.withOpacity(0.3)),
                      boxShadow: [
                        BoxShadow(
                          color: MobileColors.primary.withOpacity(0.15),
                          blurRadius: 24,
                          offset: const Offset(0, 8),
                        ),
                      ],
                    ),
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        _buildAvatar(),
                        const SizedBox(height: 12),
                        Text(
                          widget.name,
                          style: const TextStyle(
                            fontSize: 18,
                            fontWeight: FontWeight.w700,
                            color: MobileColors.textPrimary,
                          ),
                          textAlign: TextAlign.center,
                          maxLines: 2,
                          overflow: TextOverflow.ellipsis,
                        ),
                        const SizedBox(height: 8),
                        if (widget.aid.isNotEmpty)
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                            decoration: BoxDecoration(
                              color: MobileColors.surfaceSecondary,
                              borderRadius: BorderRadius.circular(8),
                            ),
                            child: Text(
                              _truncatedAid(),
                              style: const TextStyle(
                                fontSize: 11,
                                color: MobileColors.textMuted,
                                fontFamily: 'monospace',
                              ),
                            ),
                          ),
                        const SizedBox(height: 8),
                        Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            // A "KEL Verified" badge used to sit here. It named something nobody
                            // outside this project knows, and it read as a verdict on a person
                            // when it meant only that their key history was internally
                            // consistent. It also appeared where nothing had been checked at
                            // all — a phone has no engine to check with, and it said verified
                            // anyway. What somebody sees now is the identity level, which this
                            // feeds into as one input rather than standing in for.
                            Container(
                              width: 20,
                              height: 20,
                              decoration: const BoxDecoration(
                                color: MobileColors.success,
                                shape: BoxShape.circle,
                              ),
                              child: const Icon(
                                Icons.check,
                                color: Colors.white,
                                size: 14,
                              ),
                            ),
                            const SizedBox(width: 6),
                            Text(
                              '${widget.confidenceScore}%',
                              style: const TextStyle(
                                fontSize: 14,
                                fontWeight: FontWeight.w600,
                                color: MobileColors.success,
                              ),
                            ),
                          ],
                        ),
                        const SizedBox(height: 12),
                        Text(
                          widget.actionLabel,
                          style: const TextStyle(
                            fontSize: 14,
                            color: MobileColors.textSecondary,
                          ),
                          textAlign: TextAlign.center,
                        ),
                        const SizedBox(height: 24),
                        Row(
                          children: [
                            Expanded(
                              child: OutlinedButton(
                                onPressed: widget.onDismiss,
                                style: OutlinedButton.styleFrom(
                                  foregroundColor: MobileColors.textSecondary,
                                  side: const BorderSide(color: MobileColors.border),
                                  padding: const EdgeInsets.symmetric(vertical: 12),
                                  shape: RoundedRectangleBorder(
                                    borderRadius: BorderRadius.circular(10),
                                  ),
                                ),
                                child: Text(widget.dismissLabel),
                              ),
                            ),
                            const SizedBox(width: 12),
                            Expanded(
                              child: ElevatedButton(
                                onPressed: widget.onConfirm,
                                style: ElevatedButton.styleFrom(
                                  backgroundColor: MobileColors.primary,
                                  foregroundColor: MobileColors.textOnPrimary,
                                  padding: const EdgeInsets.symmetric(vertical: 12),
                                  shape: RoundedRectangleBorder(
                                    borderRadius: BorderRadius.circular(10),
                                  ),
                                ),
                                child: Text(widget.confirmLabel),
                              ),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}
