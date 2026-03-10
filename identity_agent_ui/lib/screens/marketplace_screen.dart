import 'dart:async';
import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:url_launcher/url_launcher.dart';
import '../theme/app_theme.dart';
import '../config/agent_config.dart';
import '../models/sandbox_app.dart';
import 'sandbox_viewer.dart';

class MarketplaceScreen extends StatefulWidget {
  final String? serverUrl;
  const MarketplaceScreen({super.key, this.serverUrl});
  @override
  State<MarketplaceScreen> createState() => _MarketplaceScreenState();
}

class _MarketplaceScreenState extends State<MarketplaceScreen> {
  List<SandboxApp> _apps = [];
  Map<String, AppStatus> _statuses = {};
  Map<String, _InstallProgress> _installProgress = {};
  bool _loading = true;
  String? _error;
  Map<String, dynamic>? _healthInfo;
  Timer? _pollTimer;
  Timer? _progressTimer;

  String get _baseUrl => widget.serverUrl ?? AgentConfig.coreBaseUrl;

  @override
  void initState() {
    super.initState();
    _loadData();
    _pollTimer = Timer.periodic(const Duration(seconds: 5), (_) => _refreshStatuses());
    _progressTimer = Timer.periodic(const Duration(seconds: 2), (_) => _refreshInstallProgress());
  }

  @override
  void dispose() {
    _pollTimer?.cancel();
    _progressTimer?.cancel();
    super.dispose();
  }

  Future<void> _loadData() async {
    setState(() { _loading = true; _error = null; });
    try {
      final healthRes = await http.get(Uri.parse('$_baseUrl/api/sandbox/health'));
      if (healthRes.statusCode == 200) {
        _healthInfo = jsonDecode(healthRes.body);
      }
      final appsRes = await http.get(Uri.parse('$_baseUrl/api/apps'));
      if (appsRes.statusCode == 200) {
        final List<dynamic> data = jsonDecode(appsRes.body);
        _apps = data.map((e) => SandboxApp.fromJson(e)).toList();
      } else {
        _error = 'Failed to load apps: ${appsRes.statusCode}';
      }
      await _refreshStatuses();
    } catch (e) {
      _error = 'Connection error: $e';
    }
    setState(() => _loading = false);
  }

  Future<void> _refreshStatuses() async {
    for (final app in _apps) {
      try {
        final res = await http.get(Uri.parse('$_baseUrl/api/apps/${app.id}/status'));
        if (res.statusCode == 200) {
          setState(() { _statuses[app.id] = AppStatus.fromJson(jsonDecode(res.body)); });
        }
      } catch (_) {}
    }
  }

  Future<void> _refreshInstallProgress() async {
    final installingApps = _apps.where((a) => _isAppInstalling(a)).toList();
    if (installingApps.isEmpty) return;
    for (final app in installingApps) {
      try {
        final res = await http.get(Uri.parse('$_baseUrl/api/apps/${app.id}/install-progress'));
        if (res.statusCode == 200) {
          final data = jsonDecode(res.body);
          final prog = _InstallProgress.fromJson(data);
          setState(() { _installProgress[app.id] = prog; });
          if (prog.done) {
            await _reloadApps();
          }
        }
      } catch (_) {}
    }
  }

  Future<void> _reloadApps() async {
    try {
      final appsRes = await http.get(Uri.parse('$_baseUrl/api/apps'));
      if (appsRes.statusCode == 200) {
        final List<dynamic> data = jsonDecode(appsRes.body);
        setState(() { _apps = data.map((e) => SandboxApp.fromJson(e)).toList(); });
      }
    } catch (_) {}
  }

  Future<void> _installApp(SandboxApp app) async {
    try {
      setState(() { _installProgress[app.id] = _InstallProgress(status: 'starting', progress: 0, done: false); });
      await http.post(Uri.parse('$_baseUrl/api/apps/${app.id}/install'));
      await _reloadApps();
    } catch (e) {
      _showError('Install failed: $e');
    }
  }

  Future<void> _launchApp(SandboxApp app) async {
    try {
      final res = await http.post(Uri.parse('$_baseUrl/api/apps/${app.id}/launch'));
      if (res.statusCode == 200) {
        final instance = SandboxInstance.fromJson(jsonDecode(res.body));
        _openViewer(app, instance);
      } else {
        _showError('Launch failed: ${res.body}');
      }
    } catch (e) {
      _showError('Launch failed: $e');
    }
  }

  Future<void> _stopApp(SandboxApp app) async {
    try {
      await http.post(Uri.parse('$_baseUrl/api/apps/${app.id}/stop'));
      await _reloadApps();
      await _refreshStatuses();
    } catch (e) {
      _showError('Stop failed: $e');
    }
  }

  Future<void> _uninstallApp(SandboxApp app) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppColors.surface,
        title: const Text('Uninstall App', style: TextStyle(color: AppColors.textPrimary, fontFamily: 'monospace')),
        content: Text(
          'Remove ${app.name}? This deletes the ${app.isContainer ? "container image" : "binary"} from this machine.',
          style: const TextStyle(color: AppColors.textSecondary, fontFamily: 'monospace', fontSize: 13),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('CANCEL', style: TextStyle(color: AppColors.textSecondary, fontFamily: 'monospace')),
          ),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('UNINSTALL', style: TextStyle(color: AppColors.error, fontFamily: 'monospace', fontWeight: FontWeight.bold)),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    try {
      await http.delete(Uri.parse('$_baseUrl/api/apps/${app.id}'));
      setState(() { _installProgress.remove(app.id); });
      await _reloadApps();
    } catch (e) {
      _showError('Uninstall failed: $e');
    }
  }

  void _openViewer(SandboxApp app, SandboxInstance instance) {
    Navigator.of(context).push(MaterialPageRoute(
      builder: (_) => SandboxViewer(app: app, instance: instance, serverUrl: _baseUrl),
    ));
  }

  Future<void> _viewRunningApp(SandboxApp app) async {
    try {
      final res = await http.get(Uri.parse('$_baseUrl/api/apps/${app.id}/status'));
      if (res.statusCode == 200) {
        final data = jsonDecode(res.body);
        final instanceData = data['instance'];
        if (instanceData != null) {
          _openViewer(app, SandboxInstance.fromJson(instanceData));
        }
      }
    } catch (e) {
      _showError('Failed to get instance: $e');
    }
  }

  bool _isAppInstalling(SandboxApp app) {
    if (app.isInstalling) return true;
    final progress = _installProgress[app.id];
    return progress != null && !progress.done;
  }

  void _showError(String msg) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(msg), backgroundColor: AppColors.error),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.primary,
      body: SafeArea(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildHeader(),
            if (_loading)
              const Expanded(child: Center(child: CircularProgressIndicator(color: AppColors.accent)))
            else if (_error != null)
              Expanded(child: _buildError())
            else if (_podmanNotAvailable)
              _buildPodmanSetup()
            else
              Expanded(child: _buildAppList()),
          ],
        ),
      ),
    );
  }

  bool get _podmanNotAvailable {
    if (_healthInfo == null) return false;
    final engine = _healthInfo!['container_engine'] as Map<String, dynamic>?;
    return engine != null && engine['available'] != true;
  }

  Widget _buildHeader() {
    return Padding(
      padding: const EdgeInsets.fromLTRB(20, 20, 12, 12),
      child: Row(
        children: [
          const Icon(Icons.apps, color: AppColors.accent, size: 24),
          const SizedBox(width: 10),
          const Text('MARKETPLACE', style: TextStyle(
            color: AppColors.textPrimary, fontSize: 18,
            fontWeight: FontWeight.bold, fontFamily: 'monospace', letterSpacing: 2,
          )),
          const Spacer(),
          IconButton(
            icon: const Icon(Icons.refresh, color: AppColors.textSecondary, size: 20),
            onPressed: _loadData,
            tooltip: 'Refresh',
          ),
        ],
      ),
    );
  }

  Widget _buildAppList() {
    if (_apps.isEmpty) {
      return const Center(
        child: Text('No apps available', style: TextStyle(color: AppColors.textMuted, fontFamily: 'monospace')),
      );
    }
    return ListView.separated(
      padding: const EdgeInsets.fromLTRB(16, 0, 16, 24),
      itemCount: _apps.length,
      separatorBuilder: (_, __) => const SizedBox(height: 8),
      itemBuilder: (context, index) => _buildAppCard(_apps[index]),
    );
  }

  Widget _buildAppCard(SandboxApp app) {
    final status = _statuses[app.id];
    final isRunning = status?.isRunning ?? false;
    final progress = _installProgress[app.id];

    return Container(
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(
          color: isRunning
              ? AppColors.accent.withOpacity(0.4)
              : _isAppInstalling(app)
                  ? AppColors.corePending.withOpacity(0.3)
                  : AppColors.border,
        ),
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(12, 10, 8, 10),
            child: Row(
              children: [
                _buildAppIcon(app, isRunning),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Row(
                        children: [
                          Expanded(
                            child: Text(
                              app.name,
                              style: const TextStyle(
                                color: AppColors.textPrimary,
                                fontWeight: FontWeight.bold,
                                fontFamily: 'monospace',
                                fontSize: 13,
                              ),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                          const SizedBox(width: 6),
                          _buildStatusBadge(app, isRunning),
                        ],
                      ),
                      const SizedBox(height: 2),
                      Row(
                        children: [
                          Text(
                            app.isContainer ? 'Container' : 'Binary',
                            style: const TextStyle(color: AppColors.textMuted, fontFamily: 'monospace', fontSize: 10),
                          ),
                          if (app.isContainer && app.imageSizeDisplay != 'Unknown size') ...[
                            const Text('  ·  ', style: TextStyle(color: AppColors.textMuted, fontSize: 10)),
                            Text(app.imageSizeDisplay, style: const TextStyle(color: AppColors.textMuted, fontFamily: 'monospace', fontSize: 10)),
                          ],
                          if (isRunning && status != null) ...[
                            const Text('  ·  ', style: TextStyle(color: AppColors.textMuted, fontSize: 10)),
                            _buildMiniResourceBar(status),
                          ],
                        ],
                      ),
                      const SizedBox(height: 3),
                      Text(
                        app.description ?? '',
                        style: const TextStyle(color: AppColors.textSecondary, fontFamily: 'monospace', fontSize: 11),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: 8),
                _buildActionButtons(app, isRunning),
              ],
            ),
          ),
          if (_isAppInstalling(app))
            _buildInstallProgressBar(app, progress),
        ],
      ),
    );
  }

  Widget _buildInstallProgressBar(SandboxApp app, _InstallProgress? progress) {
    final pct = progress?.progress ?? 0.0;
    final statusText = progress?.statusText ?? 'Preparing…';
    return Container(
      decoration: const BoxDecoration(
        border: Border(top: BorderSide(color: AppColors.border)),
      ),
      padding: const EdgeInsets.fromLTRB(12, 8, 12, 10),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(
                statusText,
                style: const TextStyle(color: AppColors.textMuted, fontFamily: 'monospace', fontSize: 10),
              ),
              Text(
                pct > 0 ? '${pct.toStringAsFixed(0)}%' : '',
                style: const TextStyle(color: AppColors.textMuted, fontFamily: 'monospace', fontSize: 10),
              ),
            ],
          ),
          const SizedBox(height: 4),
          ClipRRect(
            borderRadius: BorderRadius.circular(2),
            child: LinearProgressIndicator(
              value: pct > 0 ? pct / 100.0 : null,
              minHeight: 3,
              backgroundColor: AppColors.border,
              valueColor: const AlwaysStoppedAnimation<Color>(AppColors.accent),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildMiniResourceBar(AppStatus status) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Icon(Icons.memory, size: 9, color: AppColors.accent.withOpacity(0.7)),
        const SizedBox(width: 2),
        Text(
          '${status.cpuPercent.toStringAsFixed(0)}%',
          style: TextStyle(color: AppColors.accent.withOpacity(0.8), fontFamily: 'monospace', fontSize: 10),
        ),
        const SizedBox(width: 6),
        Icon(Icons.storage, size: 9, color: AppColors.textMuted),
        const SizedBox(width: 2),
        Text(
          '${status.memoryUsedMb}MB',
          style: const TextStyle(color: AppColors.textMuted, fontFamily: 'monospace', fontSize: 10),
        ),
      ],
    );
  }

  Widget _buildAppIcon(SandboxApp app, bool isRunning) {
    IconData icon;
    switch (app.iconType) {
      case IconType.browser: icon = Icons.public; break;
      case IconType.ai: icon = Icons.smart_toy; break;
      case IconType.code: icon = Icons.code; break;
      case IconType.terminal: icon = Icons.terminal; break;
      default: icon = Icons.apps; break;
    }
    return Container(
      width: 36,
      height: 36,
      decoration: BoxDecoration(
        color: isRunning ? AppColors.accent.withOpacity(0.2) : AppColors.accent.withOpacity(0.1),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Icon(icon, color: isRunning ? AppColors.accent : AppColors.accent.withOpacity(0.7), size: 18),
    );
  }

  Widget _buildStatusBadge(SandboxApp app, bool isRunning) {
    String label;
    Color color;
    if (isRunning) {
      label = 'RUNNING'; color = AppColors.coreActive;
    } else if (_isAppInstalling(app)) {
      label = 'INSTALLING'; color = AppColors.corePending;
    } else if (app.isInstalled) {
      label = 'INSTALLED'; color = AppColors.textSecondary;
    } else {
      label = 'AVAILABLE'; color = AppColors.textMuted;
    }
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
      decoration: BoxDecoration(
        color: color.withOpacity(0.12),
        borderRadius: BorderRadius.circular(3),
      ),
      child: Text(label, style: TextStyle(color: color, fontSize: 8, fontWeight: FontWeight.bold, fontFamily: 'monospace')),
    );
  }

  Widget _buildActionButtons(SandboxApp app, bool isRunning) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        if (!app.isInstalled && !_isAppInstalling(app))
          _primaryButton('INSTALL', () => _installApp(app)),
        if (_isAppInstalling(app))
          const Padding(
            padding: EdgeInsets.symmetric(horizontal: 8),
            child: SizedBox(width: 14, height: 14,
              child: CircularProgressIndicator(strokeWidth: 2, color: AppColors.corePending)),
          ),
        if (app.isInstalled && !isRunning) ...[
          _primaryButton('LAUNCH', () => _launchApp(app)),
          const SizedBox(width: 4),
          _iconButton(Icons.delete_outline, AppColors.error.withOpacity(0.7), () => _uninstallApp(app), 'Uninstall'),
        ],
        if (isRunning) ...[
          _primaryButton('VIEW', () => _viewRunningApp(app)),
          const SizedBox(width: 4),
          _primaryButton('STOP', () => _stopApp(app), danger: true),
        ],
      ],
    );
  }

  Widget _primaryButton(String label, VoidCallback onPressed, {bool danger = false}) {
    return TextButton(
      onPressed: onPressed,
      style: TextButton.styleFrom(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
        minimumSize: Size.zero,
        tapTargetSize: MaterialTapTargetSize.shrinkWrap,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(4),
          side: BorderSide(color: danger ? AppColors.error.withOpacity(0.6) : AppColors.accent.withOpacity(0.6)),
        ),
      ),
      child: Text(
        label,
        style: TextStyle(
          color: danger ? AppColors.error : AppColors.accent,
          fontSize: 10,
          fontWeight: FontWeight.bold,
          fontFamily: 'monospace',
        ),
      ),
    );
  }

  Widget _iconButton(IconData icon, Color color, VoidCallback onPressed, String tooltip) {
    return Tooltip(
      message: tooltip,
      child: InkWell(
        onTap: onPressed,
        borderRadius: BorderRadius.circular(4),
        child: Padding(
          padding: const EdgeInsets.all(5),
          child: Icon(icon, size: 16, color: color),
        ),
      ),
    );
  }

  Widget _buildError() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Icon(Icons.error_outline, color: AppColors.error, size: 40),
          const SizedBox(height: 12),
          Text(_error ?? 'Unknown error',
            style: const TextStyle(color: AppColors.textSecondary, fontFamily: 'monospace', fontSize: 12),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 12),
          ElevatedButton(
            onPressed: _loadData,
            style: ElevatedButton.styleFrom(backgroundColor: AppColors.accent),
            child: const Text('Retry', style: TextStyle(color: AppColors.primary, fontFamily: 'monospace')),
          ),
        ],
      ),
    );
  }

  String _podmanDownloadUrl() {
    final engine = _healthInfo?['container_engine'] as Map<String, dynamic>?;
    final platform = engine?['platform'] as String? ?? '';
    if (platform == 'windows') {
      return 'https://podman-desktop.io/downloads/windows';
    } else if (platform == 'darwin') {
      return 'https://podman-desktop.io/downloads/macos';
    }
    return 'https://podman-desktop.io/docs/installation/linux-install';
  }

  Widget _buildPodmanSetup() {
    final engine = _healthInfo?['container_engine'] as Map<String, dynamic>?;
    final installed = engine?['installed'] == true;
    return Expanded(
      child: Center(
        child: SingleChildScrollView(
          child: Padding(
            padding: const EdgeInsets.all(32),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Icon(
                  installed ? Icons.play_circle_outline : Icons.download_rounded,
                  size: 56,
                  color: AppColors.accent.withOpacity(0.5),
                ),
                const SizedBox(height: 20),
                Text(
                  installed ? 'Podman is installed but not running' : 'Podman needed for sandboxed apps',
                  style: const TextStyle(color: AppColors.textPrimary, fontSize: 15, fontWeight: FontWeight.bold, fontFamily: 'monospace'),
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 10),
                Text(
                  installed
                      ? 'Run "podman machine start" in a terminal, then tap Check Again.'
                      : 'Apps run in isolated containers for security.\nPodman is free and open source.',
                  style: const TextStyle(color: AppColors.textSecondary, fontSize: 12, fontFamily: 'monospace', height: 1.5),
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 20),
                if (!installed)
                  _podmanActionButton(Icons.download_rounded, 'GET PODMAN DESKTOP', () async {
                    try { await launchUrl(Uri.parse(_podmanDownloadUrl()), mode: LaunchMode.externalApplication); } catch (_) {}
                  }),
                const SizedBox(height: 10),
                _podmanActionButton(Icons.refresh, 'CHECK AGAIN', _loadData, secondary: !installed),
                const SizedBox(height: 24),
                Container(
                  padding: const EdgeInsets.all(14),
                  decoration: BoxDecoration(color: AppColors.surface, borderRadius: BorderRadius.circular(8), border: Border.all(color: AppColors.border)),
                  child: const Text(
                    'Apps run in sandboxed containers — they can\'t access your files or network without explicit permission. Your identity (KERI, contacts, OOBIs) always works without Podman.',
                    style: TextStyle(color: AppColors.textMuted, fontSize: 11, fontFamily: 'monospace', height: 1.5),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _podmanActionButton(IconData icon, String label, VoidCallback onPressed, {bool secondary = false}) {
    return SizedBox(
      width: 280,
      height: 42,
      child: ElevatedButton.icon(
        onPressed: onPressed,
        icon: Icon(icon, size: 16),
        label: Text(label, style: const TextStyle(fontFamily: 'monospace', fontWeight: FontWeight.w600, fontSize: 12, letterSpacing: 0.8)),
        style: ElevatedButton.styleFrom(
          backgroundColor: secondary ? AppColors.surface : AppColors.accent,
          foregroundColor: secondary ? AppColors.textSecondary : AppColors.primary,
          side: secondary ? const BorderSide(color: AppColors.border) : null,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
        ),
      ),
    );
  }

}

class _InstallProgress {
  final String status;
  final double progress;
  final String? layer;
  final bool done;
  final String? error;

  _InstallProgress({
    required this.status,
    required this.progress,
    required this.done,
    this.layer,
    this.error,
  });

  factory _InstallProgress.fromJson(Map<String, dynamic> json) {
    return _InstallProgress(
      status: json['status'] as String? ?? '',
      progress: (json['progress'] as num?)?.toDouble() ?? 0,
      layer: json['layer'] as String?,
      done: json['done'] as bool? ?? false,
      error: json['error'] as String?,
    );
  }

  String get statusText {
    if (error != null && error!.isNotEmpty) return 'Error: $error';
    if (done && status == 'complete') return 'Install complete';
    if (layer != null && layer!.isNotEmpty) return 'Pulling $layer…';
    switch (status) {
      case 'starting': return 'Contacting registry…';
      case 'Pulling from': return 'Pulling image…';
      case 'Pull complete': return 'Layers complete…';
      case 'Digest': return 'Verifying…';
      case 'Status': return 'Finalizing…';
      default: return status.isNotEmpty ? status : 'Installing…';
    }
  }
}
