import 'package:flutter/material.dart';

/// A lightweight, self-dismissing confirmation overlay that appears centered
/// on screen, displays for [displayDuration] then fades out over
/// [fadeDuration]. Use [ConfirmationToast.show] from any alert action handler.
class ConfirmationToast {
  /// Shows a confirmation toast overlay.
  ///
  /// [message] — short label, e.g. "Accepted", "Contact Added", "Rejected".
  /// [icon] — leading icon, defaults to a checkmark.
  /// [color] — icon and border accent color.
  /// [displayDuration] — how long the toast stays fully visible (default 1.2s).
  /// [fadeDuration] — how long the fade-out animation takes (default 0.8s).
  static void show(
    BuildContext context, {
    required String message,
    IconData icon = Icons.check_circle_rounded,
    Color? color,
    Duration displayDuration = const Duration(milliseconds: 1200),
    Duration fadeDuration = const Duration(milliseconds: 800),
  }) {
    final overlay = Overlay.of(context);
    late final OverlayEntry entry;

    entry = OverlayEntry(
      builder: (_) => _ConfirmationToastWidget(
        message: message,
        icon: icon,
        color: color ?? const Color(0xFF24A148), // AppColors.success
        displayDuration: displayDuration,
        fadeDuration: fadeDuration,
        onDismissed: () {
          entry.remove();
        },
      ),
    );

    overlay.insert(entry);
  }
}

class _ConfirmationToastWidget extends StatefulWidget {
  final String message;
  final IconData icon;
  final Color color;
  final Duration displayDuration;
  final Duration fadeDuration;
  final VoidCallback onDismissed;

  const _ConfirmationToastWidget({
    required this.message,
    required this.icon,
    required this.color,
    required this.displayDuration,
    required this.fadeDuration,
    required this.onDismissed,
  });

  @override
  State<_ConfirmationToastWidget> createState() => _ConfirmationToastWidgetState();
}

class _ConfirmationToastWidgetState extends State<_ConfirmationToastWidget>
    with SingleTickerProviderStateMixin {
  late final AnimationController _controller;
  late final Animation<double> _opacity;
  late final Animation<double> _scale;

  @override
  void initState() {
    super.initState();
    final totalMs = widget.displayDuration.inMilliseconds + widget.fadeDuration.inMilliseconds;
    _controller = AnimationController(
      vsync: this,
      duration: Duration(milliseconds: totalMs),
    );

    // Fraction of total time spent fully visible vs fading out
    final visibleFraction = widget.displayDuration.inMilliseconds / totalMs;

    _opacity = TweenSequence<double>([
      // Quick fade in (first 150ms of visible phase)
      TweenSequenceItem(tween: Tween(begin: 0.0, end: 1.0), weight: 150 / totalMs * 100),
      // Hold fully visible
      TweenSequenceItem(
        tween: ConstantTween(1.0),
        weight: (visibleFraction * 100) - (150 / totalMs * 100),
      ),
      // Fade out
      TweenSequenceItem(
        tween: Tween(begin: 1.0, end: 0.0)
            .chain(CurveTween(curve: Curves.easeOut)),
        weight: (1.0 - visibleFraction) * 100,
      ),
    ]).animate(_controller);

    _scale = TweenSequence<double>([
      // Pop in
      TweenSequenceItem(tween: Tween(begin: 0.8, end: 1.0)
          .chain(CurveTween(curve: Curves.easeOutBack)), weight: 150 / totalMs * 100),
      // Hold
      TweenSequenceItem(
        tween: ConstantTween(1.0),
        weight: (visibleFraction * 100) - (150 / totalMs * 100),
      ),
      // Shrink slightly on fade
      TweenSequenceItem(
        tween: Tween(begin: 1.0, end: 0.95)
            .chain(CurveTween(curve: Curves.easeOut)),
        weight: (1.0 - visibleFraction) * 100,
      ),
    ]).animate(_controller);

    _controller.forward().then((_) {
      if (mounted) widget.onDismissed();
    });
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Positioned.fill(
      child: IgnorePointer(
        child: Center(
          child: AnimatedBuilder(
            animation: _controller,
            builder: (context, child) {
              return Opacity(
                opacity: _opacity.value,
                child: Transform.scale(
                  scale: _scale.value,
                  child: child,
                ),
              );
            },
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 28, vertical: 18),
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(16),
                border: Border.all(color: widget.color.withOpacity(0.3), width: 1.5),
                boxShadow: [
                  BoxShadow(
                    color: Colors.black.withOpacity(0.12),
                    blurRadius: 24,
                    offset: const Offset(0, 4),
                  ),
                ],
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(widget.icon, color: widget.color, size: 28),
                  const SizedBox(width: 12),
                  Text(
                    widget.message,
                    style: TextStyle(
                      fontSize: 16,
                      fontWeight: FontWeight.w600,
                      color: widget.color,
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
