import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';
import '../../theme/mobile_theme.dart';
import '../../services/core_service.dart';
import '../../services/nfc_service.dart';
import '../../config/agent_config.dart';
import '../../widgets/contact_action_popup.dart';

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
  bool _nfcActive = false;

  @override
  void initState() {
    super.initState();
    _coreService = CoreService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);
    _scanLineController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    )..repeat();
    _startNfcListen();
  }

  Future<void> _startNfcListen() async {
    final available = await NfcService.isAvailable();
    if (!available || !mounted) return;
    setState(() => _nfcActive = true);
    await NfcService.startOobiReadSession(
      onSuccess: (oobiUrl) {
        if (!mounted || _processing) return;
        // Only handle add_contact action (or no explicit action — default intent)
        final uri = Uri.tryParse(oobiUrl);
        final action = uri?.queryParameters['action'] ?? 'add_contact';
        if (action == 'add_contact' && oobiUrl.contains('/oobi/')) {
          setState(() => _processing = true);
          _resolveAndAddContact(oobiUrl);
        }
      },
      onError: (_) {
        // Ignore NFC errors silently — camera scan is the primary path
      },
    );
  }

  @override
  void dispose() {
    NfcService.stopSession();
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
        builder: (ctx) => ContactActionPopup(
          name: resolved.displayName,
          photo: resolved.photo,
          aid: resolved.aid,
          kelVerified: resolved.kelVerified,
          intentLabel: 'Wants to add you as a contact',
          confirmLabel: 'Add Contact',
          dismissLabel: 'Dismiss',
          onConfirm: () => Navigator.of(ctx).pop(true),
          onDismiss: () => Navigator.of(ctx).pop(false),
        ),
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
          Navigator.of(context).pop(true);
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
            if (_nfcActive) _buildNfcBadge(),
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

  Widget _buildNfcBadge() {
    return Positioned(
      bottom: 100,
      left: 0,
      right: 0,
      child: Center(
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
          decoration: BoxDecoration(
            color: Colors.black54,
            borderRadius: BorderRadius.circular(20),
          ),
          child: const Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(Icons.nfc, color: Colors.white70, size: 16),
              SizedBox(width: 6),
              Text(
                'NFC tap also accepted',
                style: TextStyle(color: Colors.white70, fontSize: 12),
              ),
            ],
          ),
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

