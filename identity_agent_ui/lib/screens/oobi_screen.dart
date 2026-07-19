import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:qr_flutter/qr_flutter.dart';
import '../theme/app_theme.dart';
import 'package:agent_client/services/core_service.dart';
import 'package:agent_client/services/keri_service.dart';
import 'package:agent_client/services/mobile_on_device_keri_service.dart';

class OobiScreen extends StatefulWidget {
  final KeriService keriService;
  final String? serverUrl;
  final ValueNotifier<int>? refreshNotifier;

  const OobiScreen({super.key, required this.keriService, this.serverUrl, this.refreshNotifier});

  @override
  State<OobiScreen> createState() => _OobiScreenState();
}

class _OobiScreenState extends State<OobiScreen> {
  late final CoreService _coreService = CoreService(baseUrl: _resolveServerUrl());

  String? _resolveServerUrl() {
    if (widget.serverUrl != null) return widget.serverUrl;
    if (widget.keriService is MobileOnDeviceKeriService) {
      final standalone = widget.keriService as MobileOnDeviceKeriService;
      if (standalone.isCoreReady) {
        return standalone.mobileCore.baseUrl;
      }
    }
    return null;
  }
  OobiResponse? _oobi;
  bool _loading = true;
  String? _error;
  bool _copied = false;

  @override
  void initState() {
    super.initState();
    _loadOobi();
    widget.refreshNotifier?.addListener(_onRefreshNotified);
  }

  @override
  void dispose() {
    widget.refreshNotifier?.removeListener(_onRefreshNotified);
    _coreService.dispose();
    super.dispose();
  }

  void _onRefreshNotified() {
    _loadOobi();
  }

  Future<void> _loadOobi() async {
    setState(() {
      _loading = true;
      _error = null;
    });

    try {
      final result = await _coreService.getOobi();
      setState(() {
        _oobi = result;
        _loading = false;
      });
    } catch (e) {
      setState(() {
        _error = e.toString();
        _loading = false;
      });
    }
  }

  void _copyToClipboard() {
    if (_oobi == null) return;
    Clipboard.setData(ClipboardData(text: _oobi!.oobiUrl));
    setState(() => _copied = true);
    Future.delayed(const Duration(seconds: 2), () {
      if (mounted) setState(() => _copied = false);
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildHeader(),
            Expanded(
              child: _loading
                  ? Center(
                      child: SizedBox(
                        width: 30,
                        height: 30,
                        child: CircularProgressIndicator(
                          strokeWidth: 2,
                          color: AppColors.accent,
                        ),
                      ),
                    )
                  : _error != null
                      ? _buildErrorState()
                      : _buildContent(),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildHeader() {
    return Padding(
      padding: const EdgeInsets.fromLTRB(32, 32, 32, 0),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('OOBI', style: Theme.of(context).textTheme.headlineMedium),
                const SizedBox(height: 4),
                const Text(
                  'Out-of-band introduction URL.',
                  style: TextStyle(color: AppColors.textSecondary, fontSize: 14),
                ),
              ],
            ),
          ),
          IconButton(
            onPressed: _loadOobi,
            icon: const Icon(Icons.refresh),
            color: AppColors.textSecondary,
            tooltip: 'Refresh',
          ),
        ],
      ),
    );
  }

  Widget _buildErrorState() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.error_outline, color: AppColors.coreInactive, size: 40),
            const SizedBox(height: 16),
            const Text(
              'No identity found',
              style: TextStyle(
                color: AppColors.coreInactive,
                fontSize: 14,
                fontWeight: FontWeight.w600,
              ),
            ),
            const SizedBox(height: 8),
            const Text(
              'Create an identity first to generate an OOBI URL.',
              style: TextStyle(
                color: AppColors.textMuted,
                fontSize: 13,
              ),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildContent() {
    return SingleChildScrollView(
      padding: const EdgeInsets.fromLTRB(32, 16, 32, 32),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (_oobi != null)
            _buildEndpointSourceBanner(),
          const SizedBox(height: 16),
          _buildOobiUrlCard(),
          const SizedBox(height: 20),
          _buildAidCard(),
          const SizedBox(height: 20),
          _buildQrCode(),
          const SizedBox(height: 24),
        ],
      ),
    );
  }

  Widget _buildOobiUrlCard() {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: AppColors.accent.withOpacity(0.3),
          width: 1,
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Text(
                'OOBI URL',
                style: TextStyle(
                  color: AppColors.textSecondary,
                  fontSize: 13,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const Spacer(),
              InkWell(
                onTap: _copyToClipboard,
                borderRadius: BorderRadius.circular(6),
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                  decoration: BoxDecoration(
                    color: _copied
                        ? AppColors.coreActive.withOpacity(0.15)
                        : AppColors.surfaceLight,
                    borderRadius: BorderRadius.circular(6),
                    border: _copied
                        ? Border.all(color: AppColors.coreActive.withOpacity(0.3), width: 1)
                        : null,
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(
                        _copied ? Icons.check : Icons.copy,
                        color: _copied ? AppColors.coreActive : AppColors.textSecondary,
                        size: 14,
                      ),
                      const SizedBox(width: 4),
                      Text(
                        _copied ? 'COPIED' : 'COPY',
                        style: TextStyle(
                          color: _copied ? AppColors.coreActive : AppColors.textSecondary,
                          fontSize: 10,
                          fontWeight: FontWeight.w600,
                          letterSpacing: 1.0,
                          fontFamily: 'monospace',
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 14),
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: AppColors.surfaceLight,
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: AppColors.border, width: 1),
            ),
            child: SelectableText(
              _oobi?.oobiUrl ?? '',
              style: const TextStyle(
                color: AppColors.accent,
                fontSize: 11,
                fontFamily: 'monospace',
                height: 1.5,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildAidCard() {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppColors.border, width: 1),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 28,
                height: 28,
                decoration: BoxDecoration(
                  color: AppColors.coreActive.withOpacity(0.15),
                  borderRadius: BorderRadius.circular(6),
                ),
                child: const Icon(
                  Icons.fingerprint,
                  color: AppColors.coreActive,
                  size: 16,
                ),
              ),
              const SizedBox(width: 10),
              const Text(
                'Autonomous Identifier',
                style: TextStyle(
                  color: AppColors.textSecondary,
                  fontSize: 13,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ],
          ),
          const SizedBox(height: 14),
          Container(
            width: double.infinity,
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: AppColors.surfaceLight,
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: AppColors.border, width: 1),
            ),
            child: SelectableText(
              _oobi?.aid ?? '',
              style: const TextStyle(
                color: AppColors.accent,
                fontSize: 11,
                fontFamily: 'monospace',
                height: 1.5,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildQrCode() {
    final oobiUrl = _oobi?.oobiUrl ?? '';
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: AppColors.border, width: 1),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'QR Code',
            style: TextStyle(
              color: AppColors.textSecondary,
              fontSize: 13,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 6),
          const Text(
            'Scan this code from another device to add this identity as a contact.',
            style: TextStyle(
              color: AppColors.textMuted,
              fontSize: 12,
              height: 1.4,
            ),
          ),
          const SizedBox(height: 14),
          Center(
            child: Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(12),
              ),
              child: QrImageView(
                data: oobiUrl,
                version: QrVersions.auto,
                size: 200,
                backgroundColor: Colors.white,
                eyeStyle: const QrEyeStyle(
                  eyeShape: QrEyeShape.square,
                  color: Color(0xFF0a0e1a),
                ),
                dataModuleStyle: const QrDataModuleStyle(
                  dataModuleShape: QrDataModuleShape.square,
                  color: Color(0xFF0a0e1a),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildEndpointSourceBanner() {
    final source = _oobi!.endpointSource;
    final isTunnel = source.startsWith('tunnel:');
    final isLocal = source.startsWith('local:') || source == 'localhost';
    final isEnv = source.startsWith('env:');
    final isOverride = source == 'override';

    Color bannerColor;
    IconData bannerIcon;
    String bannerLabel;
    String? subtitle;

    if (isTunnel) {
      final provider = source.replaceFirst('tunnel:', '').toUpperCase();
      bannerColor = AppColors.coreActive;
      bannerIcon = Icons.cloud_done;
      bannerLabel = '$provider TUNNEL ACTIVE';
    } else if (isEnv || isOverride) {
      bannerColor = AppColors.coreActive;
      bannerIcon = Icons.dns;
      bannerLabel = 'CONFIGURED ENDPOINT';
    } else if (isLocal) {
      bannerColor = AppColors.warning;
      bannerIcon = Icons.wifi;
      bannerLabel = 'LOCAL NETWORK ONLY';
      subtitle = 'Your OOBI URL is only reachable on your local network. To share it externally, configure a tunnel provider in Settings.';
      if (_oobi!.tunnelProvider.isNotEmpty && _oobi!.tunnelProvider != 'none') {
        final provider = _oobi!.tunnelProvider.toUpperCase();
        final errorDetail = _oobi!.tunnelError.isNotEmpty
            ? _oobi!.tunnelError
            : 'The $provider tunnel is not connected.';
        subtitle = '$errorDetail\nFalling back to local network address — not reachable externally.';
      }
    } else {
      bannerColor = AppColors.coreInactive;
      bannerIcon = Icons.cloud_off;
      bannerLabel = 'NO EXTERNAL URL';
      subtitle = 'No tunnel or network address available. Go to Settings and configure a Grape ID tunnel so others can reach your agent.';
    }

    return Container(
      margin: const EdgeInsets.only(top: 8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: bannerColor.withOpacity(0.08),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: bannerColor.withOpacity(0.3), width: 1),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(bannerIcon, color: bannerColor, size: 16),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  bannerLabel,
                  style: TextStyle(
                    color: bannerColor,
                    fontSize: 11,
                    fontWeight: FontWeight.w700,
                    letterSpacing: 1.0,
                    fontFamily: 'monospace',
                  ),
                ),
                if (subtitle != null) ...[
                  const SizedBox(height: 4),
                  Text(
                    subtitle,
                    style: const TextStyle(
                      color: AppColors.textSecondary,
                      fontSize: 10,
                      fontFamily: 'monospace',
                      height: 1.4,
                    ),
                  ),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }
}
