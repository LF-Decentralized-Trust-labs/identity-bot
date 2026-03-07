import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import '../../theme/mobile_theme.dart';
import '../../services/core_service.dart';
import '../../config/agent_config.dart';

class MobileQrScanner extends StatefulWidget {
  final String? serverUrl;

  const MobileQrScanner({super.key, this.serverUrl});

  @override
  State<MobileQrScanner> createState() => _MobileQrScannerState();
}

class _MobileQrScannerState extends State<MobileQrScanner> with SingleTickerProviderStateMixin {
  late final CoreService _coreService;
  late final AnimationController _scanLineController;
  bool _processing = false;

  @override
  void initState() {
    super.initState();
    _coreService = CoreService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);
    _scanLineController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    )..repeat();
  }

  @override
  void dispose() {
    _scanLineController.dispose();
    _coreService.dispose();
    super.dispose();
  }

  void _onDetect(BarcodeCapture capture) {
    if (_processing) return;
    final barcodes = capture.barcodes;
    if (barcodes.isEmpty) return;

    final code = barcodes.first.rawValue;
    if (code == null || code.isEmpty) return;

    if (code.contains('/oobi/')) {
      setState(() => _processing = true);
      _resolveAndAddContact(code);
    }
  }

  Future<void> _resolveAndAddContact(String oobiUrl) async {
    try {
      final resolved = await _coreService.resolveOobiContact(oobiUrl: oobiUrl);

      if (!mounted) return;

      final confirmed = await showDialog<bool>(
        context: context,
        barrierDismissible: false,
        builder: (ctx) => _ConsentDialog(resolved: resolved),
      );

      if (confirmed == true) {
        await _coreService.addContact(
          oobiUrl: oobiUrl,
          alias: resolved.alias,
        );
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Contact "${resolved.displayName}" added'),
              backgroundColor: MobileColors.success,
            ),
          );
          Navigator.of(context).pop();
        }
      } else {
        setState(() => _processing = false);
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to resolve: $e'),
            backgroundColor: MobileColors.error,
          ),
        );
        setState(() => _processing = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Theme(
      data: ThemeData.dark(),
      child: Scaffold(
        backgroundColor: MobileColors.scannerBackground,
        body: Stack(
          children: [
            MobileScanner(onDetect: _onDetect),
            _buildScanOverlay(),
            _buildTopBar(),
            if (_processing) _buildProcessingOverlay(),
          ],
        ),
      ),
    );
  }

  Widget _buildTopBar() {
    return SafeArea(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(
          children: [
            const Expanded(
              child: Text(
                'Scan QR Code',
                style: TextStyle(
                  color: Colors.white,
                  fontSize: 20,
                  fontWeight: FontWeight.w700,
                ),
              ),
            ),
            GestureDetector(
              onTap: () => Navigator.of(context).pop(),
              child: Container(
                width: 36,
                height: 36,
                decoration: BoxDecoration(
                  color: Colors.white24,
                  borderRadius: BorderRadius.circular(18),
                ),
                child: const Icon(Icons.close, color: Colors.white, size: 20),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildScanOverlay() {
    return Center(
      child: SizedBox(
        width: 260,
        height: 260,
        child: Stack(
          children: [
            _CornerBracket(alignment: Alignment.topLeft),
            _CornerBracket(alignment: Alignment.topRight),
            _CornerBracket(alignment: Alignment.bottomLeft),
            _CornerBracket(alignment: Alignment.bottomRight),
            _ScanLineAnimated(
              animation: _scanLineController,
              builder: (context, child) {
                return Positioned(
                  top: _scanLineController.value * 250,
                  left: 10,
                  right: 10,
                  child: Container(
                    height: 2,
                    decoration: BoxDecoration(
                      gradient: LinearGradient(
                        colors: [
                          MobileColors.scannerLine.withOpacity(0),
                          MobileColors.scannerLine,
                          MobileColors.scannerLine.withOpacity(0),
                        ],
                      ),
                    ),
                  ),
                );
              },
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildProcessingOverlay() {
    return Container(
      color: Colors.black54,
      child: const Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            CircularProgressIndicator(color: MobileColors.primary),
            SizedBox(height: 16),
            Text(
              'Resolving identity...',
              style: TextStyle(color: Colors.white, fontSize: 16),
            ),
          ],
        ),
      ),
    );
  }
}

class _ScanLineAnimated extends AnimatedWidget {
  final Widget Function(BuildContext context, Widget? child) builder;

  const _ScanLineAnimated({
    required Animation<double> animation,
    required this.builder,
  }) : super(listenable: animation);

  @override
  Widget build(BuildContext context) {
    return builder(context, null);
  }
}

class _CornerBracket extends StatelessWidget {
  final Alignment alignment;

  const _CornerBracket({required this.alignment});

  @override
  Widget build(BuildContext context) {
    final isTop = alignment.y < 0;
    final isLeft = alignment.x < 0;

    return Positioned(
      top: isTop ? 0 : null,
      bottom: isTop ? null : 0,
      left: isLeft ? 0 : null,
      right: isLeft ? null : 0,
      child: Container(
        width: 30,
        height: 30,
        decoration: BoxDecoration(
          border: Border(
            top: isTop ? const BorderSide(color: MobileColors.scannerFrame, width: 3) : BorderSide.none,
            bottom: isTop ? BorderSide.none : const BorderSide(color: MobileColors.scannerFrame, width: 3),
            left: isLeft ? const BorderSide(color: MobileColors.scannerFrame, width: 3) : BorderSide.none,
            right: isLeft ? BorderSide.none : const BorderSide(color: MobileColors.scannerFrame, width: 3),
          ),
        ),
      ),
    );
  }
}

class _ConsentDialog extends StatelessWidget {
  final ResolvedContactResponse resolved;

  const _ConsentDialog({required this.resolved});

  Widget _buildAvatar() {
    if (resolved.photo.isNotEmpty) {
      try {
        final photoData = resolved.photo.contains(',')
            ? resolved.photo.split(',').last
            : resolved.photo;
        return CircleAvatar(
          radius: 32,
          backgroundImage: MemoryImage(base64Decode(photoData)),
        );
      } catch (_) {}
    }
    final initials = resolved.displayName
        .split(' ')
        .where((w) => w.isNotEmpty)
        .take(2)
        .map((w) => w[0].toUpperCase())
        .join();
    return CircleAvatar(
      radius: 32,
      backgroundColor: MobileColors.primary.withOpacity(0.15),
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

  @override
  Widget build(BuildContext context) {
    final jcard = resolved.jcard;
    return AlertDialog(
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      title: const Text(
        'Add Contact?',
        style: TextStyle(
          fontWeight: FontWeight.w700,
          color: MobileColors.textPrimary,
        ),
      ),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          _buildAvatar(),
          const SizedBox(height: 12),
          Text(
            resolved.displayName,
            style: const TextStyle(
              fontSize: 18,
              fontWeight: FontWeight.w700,
              color: MobileColors.textPrimary,
            ),
            textAlign: TextAlign.center,
          ),
          if (jcard != null && jcard.org.isNotEmpty) ...[
            const SizedBox(height: 4),
            Text(
              jcard.org,
              style: const TextStyle(
                fontSize: 13,
                color: MobileColors.textSecondary,
              ),
              textAlign: TextAlign.center,
            ),
          ],
          if (jcard != null && jcard.title.isNotEmpty) ...[
            const SizedBox(height: 2),
            Text(
              jcard.title,
              style: const TextStyle(
                fontSize: 12,
                color: MobileColors.textMuted,
              ),
              textAlign: TextAlign.center,
            ),
          ],
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
            decoration: BoxDecoration(
              color: MobileColors.surfaceSecondary,
              borderRadius: BorderRadius.circular(8),
            ),
            child: Text(
              resolved.aid.length > 24
                  ? '${resolved.aid.substring(0, 24)}...'
                  : resolved.aid,
              style: const TextStyle(
                fontSize: 11,
                color: MobileColors.textMuted,
                fontFamily: 'monospace',
              ),
            ),
          ),
          const SizedBox(height: 10),
          Row(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Icon(
                resolved.kelVerified ? Icons.verified : Icons.warning_amber,
                size: 16,
                color: resolved.kelVerified ? MobileColors.success : MobileColors.warning,
              ),
              const SizedBox(width: 6),
              Text(
                resolved.kelVerified ? 'KEL Verified' : 'Unverified',
                style: TextStyle(
                  fontSize: 13,
                  color: resolved.kelVerified ? MobileColors.success : MobileColors.warning,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(false),
          child: const Text('Cancel'),
        ),
        ElevatedButton(
          onPressed: () => Navigator.of(context).pop(true),
          style: ElevatedButton.styleFrom(
            backgroundColor: MobileColors.primary,
            foregroundColor: MobileColors.textOnPrimary,
          ),
          child: const Text('Add Contact'),
        ),
      ],
    );
  }
}
