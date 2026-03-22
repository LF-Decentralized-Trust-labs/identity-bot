import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import '../../theme/app_theme.dart';
import '../../services/core_service.dart';
import '../../config/agent_config.dart';

class HistoryScreen extends StatefulWidget {
  final String? serverUrl;
  final int initialTab; // 0=Activity, 1=Key Events, 2=System

  const HistoryScreen({super.key, this.serverUrl, this.initialTab = 0});

  @override
  State<HistoryScreen> createState() => _HistoryScreenState();
}

class _HistoryScreenState extends State<HistoryScreen> with SingleTickerProviderStateMixin {
  late final TabController _tabController;
  late final CoreService _coreService =
      CoreService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);

  String get _baseUrl => widget.serverUrl ?? AgentConfig.coreBaseUrl;

  bool _kelLoading = true;
  String? _kelError;
  String _aid = '';
  List<Map<String, dynamic>> _kelEvents = [];

  @override
  void initState() {
    super.initState();
    _tabController = TabController(
        length: 3, vsync: this, initialIndex: widget.initialTab);
    _loadKel();
  }

  @override
  void dispose() {
    _tabController.dispose();
    _coreService.dispose();
    super.dispose();
  }

  Future<void> _loadKel() async {
    setState(() { _kelLoading = true; _kelError = null; });
    try {
      final identity = await _coreService.getIdentity();
      if (!identity.initialized || identity.aid == null) {
        setState(() { _kelError = 'No identity found. Complete setup first.'; _kelLoading = false; });
        return;
      }
      final aid = identity.aid!;
      List<Map<String, dynamic>> events = [];
      try {
        final uri = Uri.parse('$_baseUrl/api/kel')
            .replace(queryParameters: {'name': aid});
        final resp = await http.get(uri);
        if (resp.statusCode == 200) {
          final body = json.decode(resp.body) as Map<String, dynamic>;
          events = List<Map<String, dynamic>>.from(body['events'] ?? []);
        }
      } catch (_) {}
      if (mounted) setState(() { _aid = aid; _kelEvents = events; _kelLoading = false; });
    } catch (e) {
      if (mounted) setState(() { _kelError = e.toString(); _kelLoading = false; });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Theme.of(context).colorScheme.surface,
      body: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(32, 32, 32, 0),
            child: Row(
              children: [
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text('History', style: Theme.of(context).textTheme.headlineMedium),
                      const SizedBox(height: 4),
                      const Text('Activity, key events, and system logs.',
                          style: TextStyle(color: AppColors.textSecondary, fontSize: 14)),
                    ],
                  ),
                ),
                IconButton(
                  onPressed: _loadKel,
                  icon: const Icon(Icons.refresh),
                  color: AppColors.textSecondary,
                  tooltip: 'Refresh',
                ),
              ],
            ),
          ),
          Container(
            margin: const EdgeInsets.fromLTRB(32, 16, 32, 0),
            decoration: const BoxDecoration(
              border: Border(bottom: BorderSide(color: AppColors.border)),
            ),
            child: TabBar(
              controller: _tabController,
              labelColor: AppColors.primary,
              unselectedLabelColor: AppColors.textSecondary,
              indicatorColor: AppColors.primary,
              indicatorWeight: 2,
              tabs: const [
                Tab(text: 'Activity'),
                Tab(text: 'Key Events'),
                Tab(text: 'System'),
              ],
            ),
          ),
          Expanded(
            child: TabBarView(
              controller: _tabController,
              children: [
                _buildActivityTab(),
                _buildKeyEventsTab(),
                _buildSystemTab(),
              ],
            ),
          ),
        ],
      ),
    );
  }

  // ── Activity tab ─────────────────────────────────────────────────────────

  Widget _buildActivityTab() {
    const events = [
      _ActivityEvent(icon: Icons.fingerprint, label: 'Identity created',
          detail: 'AID generated and stored locally', color: AppColors.success, time: 'Setup'),
      _ActivityEvent(icon: Icons.vpn_key, label: 'Keys generated',
          detail: 'Ed25519 signing key pair initialized', color: AppColors.primary, time: 'Setup'),
    ];

    return SingleChildScrollView(
      padding: const EdgeInsets.fromLTRB(32, 20, 32, 32),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
            decoration: BoxDecoration(
              color: AppColors.surfaceLight,
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: AppColors.border),
            ),
            child: const Row(
              children: [
                Icon(Icons.info_outline, color: AppColors.textMuted, size: 14),
                SizedBox(width: 8),
                Expanded(
                  child: Text(
                    'Live activity tracking is coming soon. Showing known events.',
                    style: TextStyle(color: AppColors.textMuted, fontSize: 12),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),
          ...events.map((e) => _activityRow(e)),
        ],
      ),
    );
  }

  Widget _activityRow(_ActivityEvent e) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: AppColors.border),
      ),
      child: Row(
        children: [
          Container(
            width: 34, height: 34,
            decoration: BoxDecoration(
              color: e.color.withOpacity(0.1),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Icon(e.icon, color: e.color, size: 17),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(e.label,
                    style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600,
                        color: AppColors.textPrimary)),
                const SizedBox(height: 2),
                Text(e.detail,
                    style: const TextStyle(fontSize: 11, color: AppColors.textMuted)),
              ],
            ),
          ),
          Text(e.time, style: const TextStyle(fontSize: 11, color: AppColors.textMuted)),
        ],
      ),
    );
  }

  // ── Key Events tab ───────────────────────────────────────────────────────

  Widget _buildKeyEventsTab() {
    if (_kelLoading) return const Center(child: CircularProgressIndicator());
    if (_kelError != null) {
      return Center(
        child: Padding(
          padding: const EdgeInsets.all(32),
          child: Text(_kelError!,
              style: const TextStyle(color: AppColors.error, fontSize: 13)),
        ),
      );
    }

    return SingleChildScrollView(
      padding: const EdgeInsets.fromLTRB(32, 20, 32, 32),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: AppColors.surfaceLight,
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: AppColors.border),
            ),
            child: Row(
              children: [
                const Icon(Icons.fingerprint, size: 14, color: AppColors.textMuted),
                const SizedBox(width: 8),
                Expanded(
                  child: SelectableText(_aid,
                      style: const TextStyle(color: AppColors.primary, fontSize: 11,
                          fontFamily: 'monospace')),
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),
          Text(
            '${_kelEvents.length} event${_kelEvents.length == 1 ? '' : 's'}',
            style: const TextStyle(
                fontSize: 13, fontWeight: FontWeight.w600, color: AppColors.textSecondary),
          ),
          const SizedBox(height: 12),
          if (_kelEvents.isEmpty)
            const Text('No key events found.',
                style: TextStyle(color: AppColors.textMuted, fontSize: 13))
          else
            ..._kelEvents.map((e) => _kelEventRow(e)),
        ],
      ),
    );
  }

  Widget _kelEventRow(Map<String, dynamic> event) {
    final type = (event['t'] ?? event['type'] ?? 'unknown').toString();
    final seq = event['s'] ?? event['sn'] ?? '?';
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: AppColors.surfaceLight,
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: AppColors.border),
      ),
      child: Row(
        children: [
          Container(
            width: 32,
            padding: const EdgeInsets.symmetric(vertical: 3),
            decoration: BoxDecoration(
              color: AppColors.primary.withOpacity(0.1),
              borderRadius: BorderRadius.circular(4),
            ),
            alignment: Alignment.center,
            child: Text('#$seq',
                style: const TextStyle(
                    color: AppColors.primary,
                    fontSize: 10,
                    fontWeight: FontWeight.w700,
                    fontFamily: 'monospace')),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Text(type.toUpperCase(),
                style: const TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                    fontFamily: 'monospace')),
          ),
          if (event['d'] != null)
            Text(
              (event['d'] as String).length > 16
                  ? '${(event['d'] as String).substring(0, 16)}…'
                  : event['d'].toString(),
              style: const TextStyle(
                  color: AppColors.textMuted, fontSize: 10, fontFamily: 'monospace'),
            ),
        ],
      ),
    );
  }

  // ── System tab ───────────────────────────────────────────────────────────

  Widget _buildSystemTab() {
    return SingleChildScrollView(
      padding: const EdgeInsets.fromLTRB(32, 20, 32, 32),
      child: Container(
        padding: const EdgeInsets.all(20),
        decoration: BoxDecoration(
          color: AppColors.surfaceLight,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: AppColors.border),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Row(
              children: [
                Icon(Icons.terminal, color: AppColors.textSecondary, size: 16),
                SizedBox(width: 8),
                Text('System Logs',
                    style: TextStyle(
                        fontSize: 13,
                        fontWeight: FontWeight.w600,
                        color: AppColors.textSecondary)),
              ],
            ),
            const SizedBox(height: 12),
            const Text(
              'Backend system logs — server events, process lifecycle, and errors — will be streamed here in a future update.\n\n'
              'For current backend status, health, and version information, see Settings → Developer Tools.',
              style: TextStyle(
                  color: AppColors.textMuted, fontSize: 13, height: 1.65),
            ),
          ],
        ),
      ),
    );
  }
}

// ── Data classes ─────────────────────────────────────────────────────────────

class _ActivityEvent {
  final IconData icon;
  final String label;
  final String detail;
  final Color color;
  final String time;

  const _ActivityEvent({
    required this.icon,
    required this.label,
    required this.detail,
    required this.color,
    required this.time,
  });
}
