import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../../theme/app_theme.dart';
import '../../services/core_service.dart';
import '../../services/keri_service.dart';
import '../../config/agent_config.dart';

class KeyRotationScreen extends StatefulWidget {
  final KeriService keriService;
  final String? serverUrl;
  const KeyRotationScreen({super.key, required this.keriService, this.serverUrl});

  @override
  State<KeyRotationScreen> createState() => _KeyRotationScreenState();
}

class _KeyRotationScreenState extends State<KeyRotationScreen> {
  late final CoreService _coreService =
      CoreService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);

  IdentityResponse? _identity;
  bool _loading = true;
  bool _rotating = false;
  String? _error;
  String? _successMessage;

  @override
  void initState() {
    super.initState();
    _loadIdentity();
  }

  @override
  void dispose() {
    _coreService.dispose();
    super.dispose();
  }

  Future<void> _loadIdentity() async {
    setState(() { _loading = true; _error = null; });
    try {
      final identity = await _coreService.getIdentity();
      setState(() { _identity = identity; _loading = false; });
    } catch (e) {
      setState(() { _error = e.toString(); _loading = false; });
    }
  }

  Future<void> _rotate() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Confirm Key Rotation'),
        content: const Text(
          'Rotating your keys will generate a new key pair and publish a rotation event to your Key Event Log. '
          'This is an irreversible operation.\n\nDo you want to continue?',
        ),
        actions: [
          TextButton(onPressed: () => Navigator.of(context).pop(false), child: const Text('Cancel')),
          ElevatedButton(onPressed: () => Navigator.of(context).pop(true), child: const Text('Rotate Keys')),
        ],
      ),
    );
    if (confirmed != true) return;

    setState(() { _rotating = true; _error = null; _successMessage = null; });
    try {
      await widget.keriService.rotateAid(name: _identity?.aid ?? '');
      await _loadIdentity();
      setState(() {
        _successMessage = 'Key rotation successful. Your new key pair is now active.';
        _rotating = false;
      });
    } catch (e) {
      setState(() { _error = e.toString(); _rotating = false; });
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Scaffold(
      backgroundColor: cs.surface,
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : SingleChildScrollView(
              padding: const EdgeInsets.fromLTRB(32, 32, 32, 32),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('Key Rotation', style: Theme.of(context).textTheme.headlineMedium),
                  const SizedBox(height: 4),
                  Text(
                    'Rotate your KERI keys to generate a new cryptographic key pair.',
                    style: TextStyle(color: AppColors.textSecondary, fontSize: 14),
                  ),
                  const SizedBox(height: 32),

                  if (_error != null) _buildBanner(context, _error!, isError: true),
                  if (_successMessage != null) _buildBanner(context, _successMessage!, isError: false),

                  _buildIdentityCard(context),
                  const SizedBox(height: 24),
                  _buildRotationCard(context),
                ],
              ),
            ),
    );
  }

  Widget _buildBanner(BuildContext context, String message, {required bool isError}) {
    final color = isError ? AppColors.error : AppColors.success;
    return Container(
      margin: const EdgeInsets.only(bottom: 20),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: color.withOpacity(0.08),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: color.withOpacity(0.3)),
      ),
      child: Row(
        children: [
          Icon(isError ? Icons.error_outline : Icons.check_circle_outline, color: color, size: 20),
          const SizedBox(width: 12),
          Expanded(child: Text(message, style: TextStyle(color: color, fontSize: 14))),
        ],
      ),
    );
  }

  Widget _buildIdentityCard(BuildContext context) {
    final id = _identity;
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        border: Border.all(color: AppColors.border),
        borderRadius: BorderRadius.circular(12),
        color: Theme.of(context).colorScheme.surface,
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('Current Identity', style: TextStyle(fontSize: 13, fontWeight: FontWeight.w600, color: AppColors.textSecondary)),
          const SizedBox(height: 16),
          _infoRow('AID', id?.aid ?? '—'),
          const SizedBox(height: 12),
          _infoRow('Public Key', id?.publicKey ?? '—'),
          const SizedBox(height: 12),
          _infoRow('Next Key Digest', id?.nextKeyDigest ?? '—'),
          const SizedBox(height: 12),
          _infoRow('Event Count', '${id?.eventCount ?? 0}'),
        ],
      ),
    );
  }

  Widget _infoRow(String label, String value) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(label, style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w600, color: AppColors.textMuted, letterSpacing: 0.5)),
        const SizedBox(height: 4),
        Row(
          children: [
            Expanded(
              child: Text(
                value.length > 72 ? '${value.substring(0, 72)}…' : value,
                style: const TextStyle(fontSize: 13, fontFamily: 'monospace', color: AppColors.textPrimary),
              ),
            ),
            if (value != '—')
              IconButton(
                icon: const Icon(Icons.copy, size: 16),
                color: AppColors.textMuted,
                onPressed: () => Clipboard.setData(ClipboardData(text: value)),
                tooltip: 'Copy',
                padding: EdgeInsets.zero,
                constraints: const BoxConstraints(),
              ),
          ],
        ),
      ],
    );
  }

  Widget _buildRotationCard(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        border: Border.all(color: AppColors.warning.withOpacity(0.4)),
        borderRadius: BorderRadius.circular(12),
        color: AppColors.warning.withOpacity(0.04),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(Icons.rotate_right, color: AppColors.warning, size: 20),
              const SizedBox(width: 8),
              Text('Rotate Keys', style: TextStyle(fontSize: 15, fontWeight: FontWeight.w600, color: AppColors.textPrimary)),
            ],
          ),
          const SizedBox(height: 12),
          Text(
            'Key rotation publishes a rotation event to your Key Event Log, '
            'activates your pre-committed next key pair, and pre-commits a new next key. '
            'Your AID (identity address) does not change.',
            style: TextStyle(fontSize: 14, color: AppColors.textSecondary, height: 1.5),
          ),
          const SizedBox(height: 20),
          ElevatedButton.icon(
            onPressed: _rotating ? null : _rotate,
            icon: _rotating
                ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                : const Icon(Icons.rotate_right, size: 18),
            label: Text(_rotating ? 'Rotating…' : 'Rotate Keys'),
            style: ElevatedButton.styleFrom(
              backgroundColor: AppColors.warning,
              foregroundColor: Colors.white,
            ),
          ),
        ],
      ),
    );
  }
}
