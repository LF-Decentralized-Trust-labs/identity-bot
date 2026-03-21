import 'dart:convert';
import 'dart:typed_data';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';

/// A pan-and-zoom avatar crop dialog.
///
/// Shows [imageBytes] inside a circular crop guide. The user can pinch-to-zoom
/// and drag to position. Tapping "Use Photo" captures the visible area at 2×
/// pixel density and returns it as PNG bytes.
///
/// Returns `null` if cancelled.
class AvatarCropDialog extends StatefulWidget {
  final Uint8List imageBytes;

  const AvatarCropDialog({super.key, required this.imageBytes});

  /// Convenience: show the dialog and return PNG bytes, or null if cancelled.
  static Future<Uint8List?> show(
      BuildContext context, Uint8List imageBytes) {
    return showDialog<Uint8List>(
      context: context,
      barrierDismissible: false,
      builder: (_) => AvatarCropDialog(imageBytes: imageBytes),
    );
  }

  /// Convenience: pick, crop, and return a base64-encoded PNG string.
  /// Returns null if the user cancels at any step.
  static Future<String?> toBase64(
      BuildContext context, Uint8List imageBytes) async {
    final cropped = await show(context, imageBytes);
    if (cropped == null) return null;
    return base64Encode(cropped);
  }

  @override
  State<AvatarCropDialog> createState() => _AvatarCropDialogState();
}

class _AvatarCropDialogState extends State<AvatarCropDialog> {
  static const double _cropSize = 280;
  final _captureKey = GlobalKey();
  bool _capturing = false;

  Future<void> _capture() async {
    if (_capturing) return;
    setState(() => _capturing = true);
    try {
      final boundary = _captureKey.currentContext!.findRenderObject()
          as RenderRepaintBoundary;
      final image = await boundary.toImage(pixelRatio: 2.0);
      final byteData =
          await image.toByteData(format: ui.ImageByteFormat.png);
      if (byteData != null && mounted) {
        Navigator.of(context).pop(byteData.buffer.asUint8List());
        return;
      }
    } catch (_) {}
    if (mounted) setState(() => _capturing = false);
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Adjust Photo'),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Text(
            'Drag to reposition · Pinch or scroll to zoom',
            style: TextStyle(fontSize: 12),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 16),
          SizedBox(
            width: _cropSize,
            height: _cropSize,
            child: Stack(
              children: [
                // ── Captured area ──────────────────────────────────────────
                RepaintBoundary(
                  key: _captureKey,
                  child: ClipRect(
                    child: SizedBox(
                      width: _cropSize,
                      height: _cropSize,
                      child: InteractiveViewer(
                        constrained: false,
                        minScale: 0.5,
                        maxScale: 8.0,
                        child: Image.memory(
                          widget.imageBytes,
                          width: _cropSize,
                          height: _cropSize,
                          fit: BoxFit.cover,
                          gaplessPlayback: true,
                        ),
                      ),
                    ),
                  ),
                ),
                // ── Circular crop overlay (not captured) ───────────────────
                IgnorePointer(
                  child: CustomPaint(
                    size: const Size(_cropSize, _cropSize),
                    painter: _CropOverlayPainter(),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(null),
          child: const Text('Cancel'),
        ),
        ElevatedButton(
          onPressed: _capturing ? null : _capture,
          child: _capturing
              ? const SizedBox(
                  width: 18,
                  height: 18,
                  child: CircularProgressIndicator(strokeWidth: 2),
                )
              : const Text('Use Photo'),
        ),
      ],
    );
  }
}

class _CropOverlayPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    final radius = size.width / 2 - 2;

    // Semi-transparent overlay outside the circle
    final path = Path()
      ..addRect(Rect.fromLTWH(0, 0, size.width, size.height))
      ..addOval(Rect.fromCircle(center: center, radius: radius))
      ..fillType = PathFillType.evenOdd;
    canvas.drawPath(path, Paint()..color = Colors.black54);

    // Circle border guide
    canvas.drawCircle(
      center,
      radius,
      Paint()
        ..color = Colors.white60
        ..style = PaintingStyle.stroke
        ..strokeWidth = 2,
    );
  }

  @override
  bool shouldRepaint(_) => false;
}
