import 'dart:convert';
import 'dart:typed_data';
import 'dart:ui' as ui;

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';

/// Pan-and-zoom avatar crop dialog. Works on mobile (touch) and desktop (mouse).
///
/// Shows the image inside a square crop area with a circular guide overlay.
/// The image is auto-scaled to fill the crop area on open (cover behaviour).
/// The user can pinch/scroll to zoom and drag to reposition before confirming.
///
/// Returns the cropped square PNG as [Uint8List], or null if cancelled.
class AvatarCropDialog extends StatefulWidget {
  final Uint8List imageBytes;

  const AvatarCropDialog({super.key, required this.imageBytes});

  /// Shows the dialog and returns the cropped PNG bytes, or null if cancelled.
  static Future<Uint8List?> show(BuildContext context, Uint8List imageBytes) {
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
  final _captureKey = GlobalKey();
  final _transformController = TransformationController();
  ui.Image? _decodedImage;
  bool _capturing = false;

  @override
  void initState() {
    super.initState();
    _decodeImage();
  }

  Future<void> _decodeImage() async {
    final codec = await ui.instantiateImageCodec(widget.imageBytes);
    final frame = await codec.getNextFrame();
    if (mounted) {
      setState(() => _decodedImage = frame.image);
      // Apply initial transform after layout so _cropSize has a valid context.
      WidgetsBinding.instance.addPostFrameCallback((_) => _centerImage());
    }
  }

  /// Scales and centres the image so it covers the crop square (like CSS cover).
  void _centerImage() {
    final image = _decodedImage;
    if (image == null) return;
    final size = _cropSize;
    final imgW = image.width.toDouble();
    final imgH = image.height.toDouble();
    // Scale so the shorter side fills the crop square.
    final scale = size / (imgW < imgH ? imgW : imgH);
    final scaledW = imgW * scale;
    final scaledH = imgH * scale;
    // Centre the overflowing dimension.
    final dx = (size - scaledW) / 2;
    final dy = (size - scaledH) / 2;
    _transformController.value = Matrix4.identity()
      ..scale(scale)
      ..setTranslationRaw(dx, dy, 0);
  }

  /// Responsive crop area: fills the dialog width on mobile, capped for desktop.
  double get _cropSize {
    final screenW = MediaQuery.of(context).size.width;
    return (screenW - 80).clamp(200.0, 340.0);
  }

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
  void dispose() {
    _transformController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final size = _cropSize;
    final theme = Theme.of(context);

    return Dialog(
      insetPadding: const EdgeInsets.symmetric(horizontal: 20, vertical: 40),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Padding(
            padding: EdgeInsets.fromLTRB(20, 20, 20, 4),
            child: Text(
              'Adjust Photo',
              style: TextStyle(fontSize: 17, fontWeight: FontWeight.w700),
            ),
          ),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 20),
            child: Text(
              'Pinch or scroll to zoom · drag to reposition',
              style: TextStyle(
                fontSize: 12,
                color: theme.colorScheme.onSurface.withAlpha(140),
              ),
              textAlign: TextAlign.center,
            ),
          ),
          const SizedBox(height: 16),

          // ── Crop area ───────────────────────────────────────────────────
          if (_decodedImage == null)
            SizedBox(
              width: size,
              height: size,
              child: const Center(child: CircularProgressIndicator()),
            )
          else
            SizedBox(
              width: size,
              height: size,
              child: Stack(
                children: [
                  // Captured square area
                  RepaintBoundary(
                    key: _captureKey,
                    child: ClipRect(
                      child: SizedBox(
                        width: size,
                        height: size,
                        child: InteractiveViewer(
                          transformationController: _transformController,
                          constrained: false,
                          minScale: 0.1,
                          maxScale: 8.0,
                          // Allow free panning beyond the natural boundary.
                          boundaryMargin: EdgeInsets.all(size),
                          child: Image.memory(
                            widget.imageBytes,
                            fit: BoxFit.contain,
                            gaplessPlayback: true,
                          ),
                        ),
                      ),
                    ),
                  ),
                  // Circular guide overlay (not captured).
                  IgnorePointer(
                    child: CustomPaint(
                      size: Size(size, size),
                      painter: _CropOverlayPainter(),
                    ),
                  ),
                ],
              ),
            ),

          // ── Buttons ─────────────────────────────────────────────────────
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 20, 20, 20),
            child: Row(
              children: [
                Expanded(
                  child: OutlinedButton(
                    onPressed:
                        _capturing ? null : () => Navigator.of(context).pop(null),
                    child: const Text('Cancel'),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: ElevatedButton(
                    onPressed: (_capturing || _decodedImage == null)
                        ? null
                        : _capture,
                    child: _capturing
                        ? const SizedBox(
                            width: 18,
                            height: 18,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Text('Use Photo'),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _CropOverlayPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    final radius = size.width / 2 - 2;

    // Darken everything outside the circle.
    final path = Path()
      ..addRect(Rect.fromLTWH(0, 0, size.width, size.height))
      ..addOval(Rect.fromCircle(center: center, radius: radius))
      ..fillType = PathFillType.evenOdd;
    canvas.drawPath(path, Paint()..color = Colors.black54);

    // Circle border guide.
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
