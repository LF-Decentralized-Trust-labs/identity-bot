import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:http/http.dart' as http;
import '../../theme/app_theme.dart';
import '../../services/core_service.dart';
import '../../services/keri_service.dart';
import '../../config/agent_config.dart';

/// KERI Protocol settings screen.
///
/// Shows the user's AID, OOBI URL, Key Event Log, and key rotation controls.
class KeriProtocolScreen extends StatefulWidget {
  final KeriService keriService;
  final String? serverUrl;

  const KeriProtocolScreen({super.key, required this.keriService, this.serverUrl});

  @override
  State<KeriProtocolScreen> createState() => _KeriProtocolScreenState();
}

class _KeriProtocolScreenState extends State<KeriProtocolScreen> {
  late final CoreService _coreService =
      CoreService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);

  String get _baseUrl => widget.serverUrl ?? AgentConfig.coreBaseUrl;

  bool _loading = true;
  String? _error;

  String _aid = '';
  String _oobiUrl = '';
  String _oobiSource = '';
  int _eventCount = 0;
  List<Map<String, dynamic>> _kelEvents = [];
  bool _kelExpanded = false;

  bool _rotating = false;
  String? _rotateError;
  String? _rotateSuccess;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _coreService.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    setState(() { _loading = true; _error = null; });
    try {
      final results = await Future.wait([
        _coreService.getIdentity(),
        _coreService.getOobi(),
      ]);
      final identity = results[0] as IdentityResponse;
      final oobi = results[1] as OobiResponse;

      if (!identity.initialized || identity.aid == null) {
        setState(() { _error = 'No identity found. Complete setup first.'; _loading = false; });
        return;
      }

      final aid = identity.aid!;
      // Fetch KEL
      List<Map<String, dynamic>> kelEvents = [];
      try {
        final uri = Uri.parse('$_baseUrl/api/kel').replace(queryParameters: {'name': aid});
        final resp = await http.get(uri);
        if (resp.statusCode == 200) {
          final body = json.decode(resp.body) as Map<String, dynamic>;
          kelEvents = List<Map<String, dynamic>>.from(body['events'] ?? []);
        }
      } catch (_) {}

      if (mounted) {
        setState(() {
          _aid = aid;
          _oobiUrl = oobi.oobiUrl;
          _oobiSource = oobi.endpointSource;
          _eventCount = identity.eventCount ?? kelEvents.length;
          _kelEvents = kelEvents;
          _loading = false;
        });
      }
    } catch (e) {
      if (mounted) setState(() { _error = e.toString(); _loading = false; });
    }
  }

  Future<void> _rotateKeys() async {
    setState(() { _rotating = true; _rotateError = null; _rotateSuccess = null; });
    try {
      await widget.keriService.rotateAid(name: _aid);
      if (mounted) {
        setState(() {
          _rotating = false;
          _rotateSuccess = 'Key rotation successful. Your AID remains the same; the signing keys have been updated.';
        });
        _load();
      }
    } catch (e) {
      if (mounted) setState(() { _rotating = false; _rotateError = e.toString(); });
    }
  }

  Future<void> _confirmRotate() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Rotate Keys'),
        content: const Text(
          'Key rotation replaces your current signing keys with a new pre-rotation key pair. '
          'Your AID remains unchanged. Contacts will need to resolve your OOBI again to see the new key.\n\n'
          'Continue?',
        ),
        actions: [
          TextButton(onPressed: () => Navigator.of(context).pop(false), child: const Text('Cancel')),
          ElevatedButton(
            onPressed: () => Navigator.of(context).pop(true),
            style: ElevatedButton.styleFrom(backgroundColor: AppColors.warning, foregroundColor: Colors.white),
            child: const Text('Rotate Keys'),
          ),
        ],
      ),
    );
    if (confirmed == true) _rotateKeys();
  }

  void _copy(String text, String label) {
    Clipboard.setData(ClipboardData(text: text));
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text('$label copied'), behavior: SnackBarBehavior.floating),
    );
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Scaffold(
      backgroundColor: cs.surface,
      body: SingleChildScrollView(
        padding: const EdgeInsets.fromLTRB(32, 32, 32, 32),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text('KERI Protocol', style: Theme.of(context).textTheme.headlineMedium),
                      const SizedBox(height: 4),
                      Text('Your identifier, OOBI, key event log, and key rotation.',
                          style: TextStyle(color: AppColors.textSecondary, fontSize: 14)),
                    ],
                  ),
                ),
                IconButton(
                  onPressed: _load,
                  icon: const Icon(Icons.refresh),
                  color: AppColors.textSecondary,
                  tooltip: 'Refresh',
                ),
              ],
            ),
            const SizedBox(height: 32),
            if (_loading)
              const Center(child: CircularProgressIndicator())
            else if (_error != null)
              _errorBanner(_error!)
            else ...[
              _buildAidCard(),
              const SizedBox(height: 20),
              _buildOobiCard(),
              const SizedBox(height: 20),
              _buildKelCard(),
              const SizedBox(height: 20),
              _buildRotateCard(),
            ],
          ],
        ),
      ),
    );
  }

  Widget _errorBanner(String msg) => Container(
    padding: const EdgeInsets.all(16),
    decoration: BoxDecoration(
      color: AppColors.error.withOpacity(0.08),
      borderRadius: BorderRadius.circular(10),
      border: Border.all(color: AppColors.error.withOpacity(0.3)),
    ),
    child: Row(
      children: [
        const Icon(Icons.error_outline, color: AppColors.error, size: 20),
        const SizedBox(width: 12),
        Expanded(child: Text(msg, style: const TextStyle(color: AppColors.error, fontSize: 13))),
      ],
    ),
  );

  Widget _buildAidCard() => _card(
    icon: Icons.fingerprint,
    title: 'Autonomous Identifier (AID)',
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SelectableText(
          _aid,
          style: const TextStyle(
            color: AppColors.primary,
            fontSize: 12,
            fontFamily: 'monospace',
            height: 1.5,
          ),
        ),
        const SizedBox(height: 10),
        Row(
          children: [
            Text('$_eventCount key event${_eventCount == 1 ? '' : 's'}',
                style: const TextStyle(color: AppColors.textMuted, fontSize: 11)),
            const Spacer(),
            _copyButton(() => _copy(_aid, 'AID')),
          ],
        ),
      ],
    ),
  );

  Widget _buildOobiCard() {
    final isTunnel = _oobiSource.startsWith('tunnel:');
    final isLocal = _oobiSource.startsWith('local:') || _oobiSource == 'localhost';
    Color statusColor = isTunnel ? AppColors.success : isLocal ? AppColors.warning : AppColors.textMuted;
    String statusLabel = isTunnel
        ? '${_oobiSource.replaceFirst('tunnel:', '').toUpperCase()} TUNNEL'
        : isLocal ? 'LOCAL ONLY' : 'NO TUNNEL';

    return _card(
      icon: Icons.link,
      title: 'OOBI URL',
      trailing: Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
        decoration: BoxDecoration(
          color: statusColor.withOpacity(0.12),
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: statusColor.withOpacity(0.3)),
        ),
        child: Text(statusLabel,
            style: TextStyle(color: statusColor, fontSize: 9, fontWeight: FontWeight.w700,
                letterSpacing: 0.8, fontFamily: 'monospace')),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SelectableText(
            _oobiUrl,
            style: const TextStyle(
              color: AppColors.accent,
              fontSize: 11,
              fontFamily: 'monospace',
              height: 1.5,
            ),
          ),
          const SizedBox(height: 10),
          Align(
            alignment: Alignment.centerRight,
            child: _copyButton(() => _copy(_oobiUrl, 'OOBI URL')),
          ),
          if (isLocal) ...[
            const SizedBox(height: 10),
            Container(
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: AppColors.warning.withOpacity(0.08),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: AppColors.warning.withOpacity(0.3)),
              ),
              child: Row(
                children: [
                  const Icon(Icons.warning_amber_rounded, color: AppColors.warning, size: 14),
                  const SizedBox(width: 8),
                  const Expanded(
                    child: Text(
                      'This OOBI URL is only reachable on your local network. '
                      'Configure a tunnel in Settings → Tunneling to share externally.',
                      style: TextStyle(color: AppColors.textSecondary, fontSize: 11),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildKelCard() => _card(
    icon: Icons.history,
    title: 'Key Event Log',
    trailing: TextButton(
      onPressed: () => setState(() => _kelExpanded = !_kelExpanded),
      child: Text(_kelExpanded ? 'Collapse' : 'Expand',
          style: const TextStyle(color: AppColors.primary, fontSize: 12)),
    ),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Text('${_kelEvents.isEmpty ? _eventCount : _kelEvents.length} event${_eventCount == 1 ? '' : 's'}',
                style: const TextStyle(color: AppColors.textSecondary, fontSize: 13)),
          ],
        ),
        if (_kelExpanded && _kelEvents.isNotEmpty) ...[
          const SizedBox(height: 12),
          ...(_kelEvents.take(20).map((event) => _kelEventRow(event))),
          if (_kelEvents.length > 20)
            Padding(
              padding: const EdgeInsets.only(top: 8),
              child: Text('… ${_kelEvents.length - 20} more events',
                  style: const TextStyle(color: AppColors.textMuted, fontSize: 11)),
            ),
        ],
      ],
    ),
  );

  Widget _kelEventRow(Map<String, dynamic> event) {
    final type = (event['t'] ?? event['type'] ?? 'unknown').toString();
    final seq = event['s'] ?? event['sn'] ?? '?';
    return Container(
      margin: const EdgeInsets.only(bottom: 6),
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: AppColors.surfaceLight,
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: AppColors.border),
      ),
      child: Row(
        children: [
          Container(
            width: 28,
            padding: const EdgeInsets.symmetric(vertical: 2),
            decoration: BoxDecoration(
              color: AppColors.primary.withOpacity(0.1),
              borderRadius: BorderRadius.circular(4),
            ),
            alignment: Alignment.center,
            child: Text('#$seq',
                style: const TextStyle(color: AppColors.primary, fontSize: 10,
                    fontWeight: FontWeight.w700, fontFamily: 'monospace')),
          ),
          const SizedBox(width: 10),
          Text(type.toUpperCase(),
              style: const TextStyle(color: AppColors.textPrimary, fontSize: 11,
                  fontWeight: FontWeight.w600, fontFamily: 'monospace')),
          const Spacer(),
          if (event['d'] != null)
            Text(
              (event['d'] as String).length > 12
                  ? '${(event['d'] as String).substring(0, 12)}…'
                  : event['d'].toString(),
              style: const TextStyle(color: AppColors.textMuted, fontSize: 10, fontFamily: 'monospace'),
            ),
        ],
      ),
    );
  }

  Widget _buildRotateCard() => Container(
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
            const Icon(Icons.rotate_right, color: AppColors.warning, size: 20),
            const SizedBox(width: 8),
            const Text('Rotate Keys',
                style: TextStyle(fontSize: 15, fontWeight: FontWeight.w600, color: AppColors.textPrimary)),
          ],
        ),
        const SizedBox(height: 10),
        const Text(
          'Key rotation replaces your current signing keys with the pre-committed next key pair. '
          'Your AID stays the same; only the active signing keys change. '
          'Your contacts will verify your new keys automatically via KERI.',
          style: TextStyle(fontSize: 13, color: AppColors.textSecondary, height: 1.5),
        ),
        if (_rotateError != null) ...[
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: AppColors.error.withOpacity(0.08),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Text(_rotateError!,
                style: const TextStyle(color: AppColors.error, fontSize: 12)),
          ),
        ],
        if (_rotateSuccess != null) ...[
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: AppColors.success.withOpacity(0.08),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Text(_rotateSuccess!,
                style: const TextStyle(color: AppColors.success, fontSize: 12)),
          ),
        ],
        const SizedBox(height: 16),
        OutlinedButton.icon(
          onPressed: _rotating ? null : _confirmRotate,
          icon: _rotating
              ? const SizedBox(width: 14, height: 14, child: CircularProgressIndicator(strokeWidth: 2))
              : const Icon(Icons.rotate_right, size: 18),
          label: Text(_rotating ? 'Rotating…' : 'Rotate Keys'),
          style: OutlinedButton.styleFrom(
            foregroundColor: AppColors.warning,
            side: BorderSide(color: AppColors.warning),
          ),
        ),
      ],
    ),
  );

  Widget _copyButton(VoidCallback onTap) => InkWell(
    onTap: onTap,
    borderRadius: BorderRadius.circular(6),
    child: Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(
        color: AppColors.surfaceLight,
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: AppColors.border),
      ),
      child: const Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.copy, color: AppColors.textSecondary, size: 13),
          SizedBox(width: 4),
          Text('COPY',
              style: TextStyle(color: AppColors.textSecondary, fontSize: 10,
                  fontWeight: FontWeight.w600, letterSpacing: 1.0, fontFamily: 'monospace')),
        ],
      ),
    ),
  );

  Widget _card({
    required IconData icon,
    required String title,
    required Widget child,
    Widget? trailing,
  }) {
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
          Row(
            children: [
              Icon(icon, size: 16, color: AppColors.textSecondary),
              const SizedBox(width: 8),
              Text(title,
                  style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600,
                      color: AppColors.textSecondary)),
              const Spacer(),
              if (trailing != null) trailing,
            ],
          ),
          const Divider(height: 20),
          child,
        ],
      ),
    );
  }
}
