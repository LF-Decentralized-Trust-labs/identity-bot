import 'dart:math';
import 'package:flutter/material.dart';
import '../theme/mobile_theme.dart';

class ConfidenceRing extends StatelessWidget {
  final int score;
  final double size;
  final double strokeWidth;

  const ConfidenceRing({
    super.key,
    required this.score,
    this.size = 72,
    this.strokeWidth = 6,
  });

  Color get _color {
    if (score >= 80) return MobileColors.confidenceHigh;
    if (score >= 50) return MobileColors.confidenceMedium;
    return MobileColors.confidenceLow;
  }

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: size,
      height: size,
      child: Stack(
        alignment: Alignment.center,
        children: [
          CustomPaint(
            size: Size(size, size),
            painter: _RingPainter(
              progress: score / 100.0,
              color: _color,
              strokeWidth: strokeWidth,
              backgroundColor: MobileColors.borderLight,
            ),
          ),
          Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                '$score%',
                style: TextStyle(
                  fontSize: size * 0.22,
                  fontWeight: FontWeight.w700,
                  color: _color,
                ),
              ),
              Text(
                'Score',
                style: TextStyle(
                  fontSize: size * 0.13,
                  color: MobileColors.textMuted,
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _RingPainter extends CustomPainter {
  final double progress;
  final Color color;
  final double strokeWidth;
  final Color backgroundColor;

  _RingPainter({
    required this.progress,
    required this.color,
    required this.strokeWidth,
    required this.backgroundColor,
  });

  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    final radius = (size.width - strokeWidth) / 2;

    final bgPaint = Paint()
      ..color = backgroundColor
      ..style = PaintingStyle.stroke
      ..strokeWidth = strokeWidth
      ..strokeCap = StrokeCap.round;

    canvas.drawCircle(center, radius, bgPaint);

    final fgPaint = Paint()
      ..color = color
      ..style = PaintingStyle.stroke
      ..strokeWidth = strokeWidth
      ..strokeCap = StrokeCap.round;

    final sweepAngle = 2 * pi * progress;
    canvas.drawArc(
      Rect.fromCircle(center: center, radius: radius),
      -pi / 2,
      sweepAngle,
      false,
      fgPaint,
    );
  }

  @override
  bool shouldRepaint(_RingPainter oldDelegate) {
    return oldDelegate.progress != progress || oldDelegate.color != color;
  }
}
