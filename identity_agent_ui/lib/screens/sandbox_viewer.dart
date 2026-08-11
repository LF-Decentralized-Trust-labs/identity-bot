import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import '../theme/app_theme.dart';
import 'package:agent_client/models/sandbox_app.dart';
import '../widgets/sandbox_webview.dart';
import '../widgets/sandbox_terminal.dart';

class SandboxViewer extends StatefulWidget {
  final SandboxApp app;
  final SandboxInstance instance;
  final String serverUrl;

  const SandboxViewer({
    super.key,
    required this.app,
    required this.instance,
    required this.serverUrl,
  });

  @override
  State<SandboxViewer> createState() => _SandboxViewerState();
}

class _SandboxViewerState extends State<SandboxViewer> with SingleTickerProviderStateMixin {
  late TabController _tabController;
  AppStatus? _status;
  List<dynamic> _proxyLogs = [];
  List<dynamic> _heldRequests = [];
  List<dynamic> _pendingResources = [];
  Timer? _pollTimer;
  String? _displayUrl;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 4, vsync: this);
    _loadDisplayUrl();
    _refreshAll();
    _pollTimer = Timer.periodic(const Duration(seconds: 3), (_) => _refreshAll());
  }

  @override
  void dispose() {
    _pollTimer?.cancel();
    _tabController.dispose();
    super.dispose();
  }

  Future<void> _loadDisplayUrl() async {
    try {
      final res = await http.get(
        Uri.parse('${widget.serverUrl}/api/apps/${widget.app.id}/display'),
      );
      if (res.statusCode == 200) {
        final data = jsonDecode(res.body);
        setState(() => _displayUrl = data['display_url']);
      }
    } catch (_) {}
  }

  Future<void> _refreshAll() async {
    try {
      final statusRes = await http.get(
        Uri.parse('${widget.serverUrl}/api/apps/${widget.app.id}/status'),
      );
      if (statusRes.statusCode == 200) {
        setState(() => _status = AppStatus.fromJson(jsonDecode(statusRes.body)));
      }

      final logsRes = await http.get(
        Uri.parse('${widget.serverUrl}/api/apps/${widget.app.id}/logs?limit=50'),
      );
      if (logsRes.statusCode == 200) {
        setState(() => _proxyLogs = jsonDecode(logsRes.body));
      }

      final heldRes = await http.get(
        Uri.parse('${widget.serverUrl}/api/apps/${widget.app.id}/logs/held'),
      );
      if (heldRes.statusCode == 200) {
        setState(() => _heldRequests = jsonDecode(heldRes.body));
      }

      final resRes = await http.get(
        Uri.parse('${widget.serverUrl}/api/apps/${widget.app.id}/resources'),
      );
      if (resRes.statusCode == 200) {
        setState(() => _pendingResources = jsonDecode(resRes.body));
      }
    } catch (_) {}
  }

  Future<void> _approveLog(int logId) async {
    try {
      await http.post(
        Uri.parse('${widget.serverUrl}/api/apps/${widget.app.id}/logs/$logId/approve'),
      );
      _refreshAll();
    } catch (_) {}
  }

  Future<void> _blockLog(int logId) async {
    try {
      await http.post(
        Uri.parse('${widget.serverUrl}/api/apps/${widget.app.id}/logs/$logId/block'),
      );
      _refreshAll();
    } catch (_) {}
  }

  Future<void> _approveResource(int reqId) async {
    try {
      await http.post(
        Uri.parse('${widget.serverUrl}/api/apps/${widget.app.id}/resources/$reqId/approve'),
      );
      _refreshAll();
    } catch (_) {}
  }

  Future<void> _denyResource(int reqId) async {
    try {
      await http.post(
        Uri.parse('${widget.serverUrl}/api/apps/${widget.app.id}/resources/$reqId/deny'),
      );
      _refreshAll();
    } catch (_) {}
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.primary,
      appBar: AppBar(
        backgroundColor: AppColors.surface,
        title: Row(
          children: [
            Text(
              widget.app.name,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 16),
            ),
            const SizedBox(width: 12),
            _statusIndicator(),
          ],
        ),
        actions: [
          if (_heldRequests.isNotEmpty || _pendingResources.isNotEmpty)
            Padding(
              padding: const EdgeInsets.only(right: 8),
              child: Badge(
                label: Text('${_heldRequests.length + _pendingResources.length}'),
                child: const Icon(Icons.notification_important, color: AppColors.warning),
              ),
            ),
        ],
      ),
      body: Row(
        children: [
          Expanded(flex: 3, child: _buildDisplayPanel()),
          Container(width: 1, color: AppColors.border),
          Expanded(flex: 2, child: _buildControlPanel()),
        ],
      ),
    );
  }

  Widget _statusIndicator() {
    final isRunning = _status?.isRunning ?? false;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: (isRunning ? AppColors.coreActive : AppColors.coreInactive).withOpacity(0.15),
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(
        isRunning ? 'RUNNING' : 'STOPPED',
        style: TextStyle(
          color: isRunning ? AppColors.coreActive : AppColors.coreInactive,
          fontSize: 10,
          fontWeight: FontWeight.bold,
          fontFamily: 'monospace',
        ),
      ),
    );
  }

  Widget _buildDisplayPanel() {
    if (widget.app.displayMethod == 'terminal') {
      return SandboxTerminal(
        instanceId: widget.instance.id,
        appName: widget.app.name,
        serverUrl: widget.serverUrl,
      );
    }

    if (_displayUrl == null) {
      return const Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            CircularProgressIndicator(color: AppColors.accent),
            SizedBox(height: 16),
            Text(
              'Loading display...',
              style: TextStyle(color: AppColors.textMuted, fontFamily: 'monospace'),
            ),
          ],
        ),
      );
    }

    return SandboxWebView(
      url: _displayUrl!,
      appName: widget.app.name,
    );
  }

  Widget _buildControlPanel() {
    return Column(
      children: [
        TabBar(
          controller: _tabController,
          isScrollable: true,
          labelColor: AppColors.accent,
          unselectedLabelColor: AppColors.textMuted,
          indicatorColor: AppColors.accent,
          labelStyle: const TextStyle(fontFamily: 'monospace', fontSize: 11),
          tabs: [
            Tab(text: 'INTERCEPT (${_proxyLogs.length})'),
            Tab(text: 'REQUESTS (${_pendingResources.length})'),
            const Tab(text: 'HEALTH'),
            const Tab(text: 'SETTINGS'),
          ],
        ),
        Expanded(
          child: TabBarView(
            controller: _tabController,
            children: [
              _buildInterceptTab(),
              _buildResourcesTab(),
              _buildHealthTab(),
              _buildSettingsTab(),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildInterceptTab() {
    final allItems = [..._heldRequests, ..._proxyLogs];
    if (allItems.isEmpty) {
      return const Center(
        child: Text(
          'No proxy traffic yet',
          style: TextStyle(color: AppColors.textMuted, fontFamily: 'monospace'),
        ),
      );
    }

    return ListView.builder(
      padding: const EdgeInsets.all(8),
      itemCount: allItems.length,
      itemBuilder: (context, index) {
        final item = allItems[index] as Map<String, dynamic>;
        final isHeld = item['policy_action'] == 'held';
        final domain = item['domain'] ?? 'unknown';
        final method = item['method'] ?? '';
        final action = item['policy_action'] ?? '';

        Color actionColor;
        switch (action) {
          case 'auto_approved':
          case 'operator_approved':
            actionColor = AppColors.coreActive;
            break;
          case 'auto_blocked':
          case 'operator_blocked':
            actionColor = AppColors.error;
            break;
          case 'held':
            actionColor = AppColors.warning;
            break;
          default:
            actionColor = AppColors.textMuted;
        }

        return Container(
          margin: const EdgeInsets.only(bottom: 4),
          padding: const EdgeInsets.all(8),
          decoration: BoxDecoration(
            color: isHeld
                ? AppColors.warning.withOpacity(0.1)
                : AppColors.surfaceLight,
            borderRadius: BorderRadius.circular(4),
            border: isHeld
                ? Border.all(color: AppColors.warning.withOpacity(0.3))
                : null,
          ),
          child: Row(
            children: [
              Container(
                width: 6,
                height: 6,
                decoration: BoxDecoration(
                  color: actionColor,
                  shape: BoxShape.circle,
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      '$method $domain',
                      style: const TextStyle(
                        color: AppColors.textPrimary,
                        fontFamily: 'monospace',
                        fontSize: 11,
                      ),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                    Text(
                      action.toUpperCase(),
                      style: TextStyle(
                        color: actionColor,
                        fontFamily: 'monospace',
                        fontSize: 9,
                      ),
                    ),
                  ],
                ),
              ),
              if (isHeld) ...[
                IconButton(
                  icon: const Icon(Icons.check_circle, color: AppColors.coreActive, size: 18),
                  onPressed: () => _approveLog(item['id']),
                  padding: EdgeInsets.zero,
                  constraints: const BoxConstraints(minWidth: 28, minHeight: 28),
                  tooltip: 'Approve',
                ),
                IconButton(
                  icon: const Icon(Icons.block, color: AppColors.error, size: 18),
                  onPressed: () => _blockLog(item['id']),
                  padding: EdgeInsets.zero,
                  constraints: const BoxConstraints(minWidth: 28, minHeight: 28),
                  tooltip: 'Block',
                ),
              ],
            ],
          ),
        );
      },
    );
  }

  Widget _buildResourcesTab() {
    if (_pendingResources.isEmpty) {
      return const Center(
        child: Text(
          'No pending resource requests',
          style: TextStyle(color: AppColors.textMuted, fontFamily: 'monospace'),
        ),
      );
    }

    return ListView.builder(
      padding: const EdgeInsets.all(8),
      itemCount: _pendingResources.length,
      itemBuilder: (context, index) {
        final req = _pendingResources[index] as Map<String, dynamic>;
        final type = req['resource_type'] ?? '';
        final target = req['resource_target'] ?? '';
        final id = req['id'] ?? 0;

        return Container(
          margin: const EdgeInsets.only(bottom: 8),
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: AppColors.surfaceLight,
            borderRadius: BorderRadius.circular(6),
            border: Border.all(color: AppColors.warning.withOpacity(0.3)),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  const Icon(Icons.pending_actions, color: AppColors.warning, size: 16),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      '$type: $target',
                      style: const TextStyle(
                        color: AppColors.textPrimary,
                        fontFamily: 'monospace',
                        fontSize: 12,
                      ),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              Row(
                mainAxisAlignment: MainAxisAlignment.end,
                children: [
                  TextButton(
                    onPressed: () => _denyResource(id),
                    child: const Text(
                      'DENY',
                      style: TextStyle(
                        color: AppColors.error,
                        fontFamily: 'monospace',
                        fontSize: 11,
                      ),
                    ),
                  ),
                  const SizedBox(width: 8),
                  TextButton(
                    onPressed: () => _approveResource(id),
                    child: const Text(
                      'APPROVE',
                      style: TextStyle(
                        color: AppColors.coreActive,
                        fontFamily: 'monospace',
                        fontSize: 11,
                      ),
                    ),
                  ),
                ],
              ),
            ],
          ),
        );
      },
    );
  }

  Widget _buildHealthTab() {
    return Padding(
      padding: const EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _buildGauge('CPU', _status?.cpuPercent ?? 0, 100, '%'),
          const SizedBox(height: 12),
          _buildGauge(
            'Memory',
            (_status?.memoryUsedMb ?? 0).toDouble(),
            (_status?.memoryLimitMb ?? 1).toDouble(),
            'MB',
          ),
          const SizedBox(height: 12),
          _buildGauge(
            'Disk',
            (_status?.diskUsedMb ?? 0).toDouble(),
            (_status?.diskLimitMb ?? 1).toDouble(),
            'MB',
          ),
          const SizedBox(height: 16),
          _infoRow('Network TX', '${_status?.networkTxKb ?? 0} KB'),
          _infoRow('Network RX', '${_status?.networkRxKb ?? 0} KB'),
          _infoRow('State', _status?.state ?? 'unknown'),
        ],
      ),
    );
  }

  Widget _buildGauge(String label, double current, double max, String unit) {
    final percent = max > 0 ? (current / max).clamp(0.0, 1.0) : 0.0;
    final color = percent > 0.8
        ? AppColors.error
        : percent > 0.6
            ? AppColors.warning
            : AppColors.accent;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(
              label,
              style: const TextStyle(
                color: AppColors.textSecondary,
                fontFamily: 'monospace',
                fontSize: 11,
              ),
            ),
            Text(
              '${current.toStringAsFixed(0)} / ${max.toStringAsFixed(0)} $unit',
              style: const TextStyle(
                color: AppColors.textPrimary,
                fontFamily: 'monospace',
                fontSize: 11,
              ),
            ),
          ],
        ),
        const SizedBox(height: 4),
        LinearProgressIndicator(
          value: percent,
          backgroundColor: AppColors.surfaceLight,
          valueColor: AlwaysStoppedAnimation<Color>(color),
          minHeight: 6,
          borderRadius: BorderRadius.circular(3),
        ),
      ],
    );
  }

  Widget _infoRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            label,
            style: const TextStyle(
              color: AppColors.textSecondary,
              fontFamily: 'monospace',
              fontSize: 11,
            ),
          ),
          Text(
            value,
            style: const TextStyle(
              color: AppColors.textPrimary,
              fontFamily: 'monospace',
              fontSize: 11,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSettingsTab() {
    return const Padding(
      padding: EdgeInsets.all(16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'App Settings',
            style: TextStyle(
              color: AppColors.textPrimary,
              fontWeight: FontWeight.bold,
              fontFamily: 'monospace',
              fontSize: 14,
            ),
          ),
          SizedBox(height: 16),
          Text(
            'Log level, TLS mode, and resource limit adjustments will be available in a future update.',
            style: TextStyle(
              color: AppColors.textMuted,
              fontFamily: 'monospace',
              fontSize: 12,
            ),
          ),
        ],
      ),
    );
  }
}
