import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart' show kIsWeb;
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
  bool _loading = true;
  String? _error;
  Map<String, dynamic>? _healthInfo;
  Timer? _pollTimer;

  String get _baseUrl => widget.serverUrl ?? AgentConfig.coreBaseUrl;

  @override
  void initState() {
    super.initState();
    _loadData();
    _pollTimer = Timer.periodic(const Duration(seconds: 5), (_) => _refreshStatuses());
  }

  @override
  void dispose() {
    _pollTimer?.cancel();
    super.dispose();
  }

  Future<void> _loadData() async {
    setState(() {
      _loading = true;
      _error = null;
    });

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
          setState(() {
            _statuses[app.id] = AppStatus.fromJson(jsonDecode(res.body));
          });
        }
      } catch (_) {}
    }
  }

  Future<void> _installApp(SandboxApp app) async {
    try {
      await http.post(Uri.parse('$_baseUrl/api/apps/${app.id}/install'));
      _loadData();
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
      _loadData();
    } catch (e) {
      _showError('Stop failed: $e');
    }
  }

  void _openViewer(SandboxApp app, SandboxInstance instance) {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => SandboxViewer(
          app: app,
          instance: instance,
          serverUrl: _baseUrl,
        ),
      ),
    );
  }

  void _showError(String msg) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(msg), backgroundColor: AppColors.error),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (kIsWeb) {
      return Scaffold(
        backgroundColor: AppColors.primary,
        body: SafeArea(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              _buildHeader(),
              Expanded(
                child: Stack(
                  children: [
                    SingleChildScrollView(
                      child: Column(
                        children: [
                          if (_loading)
                            const Padding(
                              padding: EdgeInsets.all(40),
                              child: CircularProgressIndicator(color: AppColors.accent),
                            )
                          else if (_error != null)
                            _buildError()
                          else
                            _buildAppGrid(),
                        ],
                      ),
                    ),
                    Container(
                      color: Colors.black.withOpacity(0.7),
                      child: Center(
                        child: Container(
                          padding: const EdgeInsets.all(32),
                          decoration: BoxDecoration(
                            color: AppColors.surface,
                            borderRadius: BorderRadius.circular(12),
                            border: Border.all(color: AppColors.accent.withOpacity(0.5)),
                          ),
                          child: Column(
                            mainAxisSize: MainAxisSize.min,
                            mainAxisAlignment: MainAxisAlignment.center,
                            children: [
                              Icon(
                                Icons.desktop_mac,
                                size: 48,
                                color: AppColors.accent.withOpacity(0.6),
                              ),
                              const SizedBox(height: 20),
                              Text(
                                'SANDBOXED APPS UNAVAILABLE ON WEB',
                                style: TextStyle(
                                  color: AppColors.accent.withOpacity(0.8),
                                  fontSize: 16,
                                  fontWeight: FontWeight.bold,
                                  fontFamily: 'monospace',
                                  letterSpacing: 1.2,
                                ),
                                textAlign: TextAlign.center,
                              ),
                              const SizedBox(height: 16),
                              Text(
                                'Sandboxed app execution requires a native desktop environment.\n\n'
                                'Install the Identity Agent desktop application for Windows, macOS, or Linux to access and launch apps.',
                                style: TextStyle(
                                  color: AppColors.textSecondary,
                                  fontSize: 13,
                                  fontFamily: 'monospace',
                                  height: 1.5,
                                ),
                                textAlign: TextAlign.center,
                              ),
                            ],
                          ),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      );
    }

    return Scaffold(
      backgroundColor: AppColors.primary,
      body: SafeArea(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildHeader(),
            if (_loading)
              const Expanded(
                child: Center(child: CircularProgressIndicator(color: AppColors.accent)),
              )
            else if (_error != null)
              Expanded(child: _buildError())
            else if (_dockerNotAvailable)
              _buildDockerSetup()
            else
              Expanded(child: _buildAppGrid()),
          ],
        ),
      ),
    );
  }

  bool get _dockerNotAvailable {
    if (_healthInfo == null) return false;
    final docker = _healthInfo!['docker'] as Map<String, dynamic>?;
    return docker != null && docker['available'] != true;
  }

  Widget _buildHeader() {
    return Padding(
      padding: const EdgeInsets.all(20),
      child: Row(
        children: [
          const Icon(Icons.apps, color: AppColors.accent, size: 28),
          const SizedBox(width: 12),
          const Text(
            'MARKETPLACE',
            style: TextStyle(
              color: AppColors.textPrimary,
              fontSize: 20,
              fontWeight: FontWeight.bold,
              fontFamily: 'monospace',
              letterSpacing: 2,
            ),
          ),
          const Spacer(),
          IconButton(
            icon: const Icon(Icons.refresh, color: AppColors.textSecondary),
            onPressed: _loadData,
            tooltip: 'Refresh',
          ),
        ],
      ),
    );
  }

  String _dockerDownloadUrl() {
    final docker = _healthInfo?['docker'] as Map<String, dynamic>?;
    final platform = docker?['platform'] as String? ?? '';
    final arch = docker?['architecture'] as String? ?? 'amd64';

    if (platform == 'windows') {
      if (arch == 'arm64') {
        return 'https://desktop.docker.com/win/main/arm64/Docker%20Desktop%20Installer.exe';
      }
      return 'https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe';
    } else if (platform == 'darwin') {
      if (arch == 'arm64') {
        return 'https://desktop.docker.com/mac/main/arm64/Docker.dmg';
      }
      return 'https://desktop.docker.com/mac/main/amd64/Docker.dmg';
    }
    return 'https://docs.docker.com/engine/install/';
  }

  Widget _buildDockerSetup() {
    final docker = _healthInfo?['docker'] as Map<String, dynamic>?;
    final installed = docker?['installed'] == true;

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
                  size: 64,
                  color: AppColors.accent.withOpacity(0.5),
                ),
                const SizedBox(height: 24),
                Text(
                  installed ? 'Docker is installed but not running' : 'Docker Desktop needed for sandboxed apps',
                  style: const TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                    fontFamily: 'monospace',
                  ),
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 12),
                Text(
                  installed
                      ? 'Open Docker Desktop on your computer and wait for it to fully start (the whale icon in your taskbar should stop animating), then tap Check Again.'
                      : 'Sandboxed apps run in isolated Docker containers for security.\nDocker Desktop is free to download and install.',
                  style: const TextStyle(
                    color: AppColors.textSecondary,
                    fontSize: 13,
                    fontFamily: 'monospace',
                    height: 1.5,
                  ),
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 24),
                if (!installed)
                  _buildDockerActionButton(
                    icon: Icons.download_rounded,
                    label: 'DOWNLOAD DOCKER DESKTOP',
                    onPressed: () async {
                      try {
                        await launchUrl(
                          Uri.parse(_dockerDownloadUrl()),
                          mode: LaunchMode.externalApplication,
                        );
                      } catch (_) {}
                    },
                  ),
                const SizedBox(height: 12),
                _buildDockerActionButton(
                  icon: Icons.refresh,
                  label: 'CHECK AGAIN',
                  onPressed: _loadData,
                  secondary: !installed,
                ),
                const SizedBox(height: 32),
                Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: AppColors.surface,
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: AppColors.border),
                  ),
                  child: const Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Why Docker?',
                        style: TextStyle(
                          color: AppColors.accent,
                          fontSize: 13,
                          fontWeight: FontWeight.bold,
                          fontFamily: 'monospace',
                        ),
                      ),
                      SizedBox(height: 8),
                      Text(
                        'The Identity Agent marketplace lets you run third-party apps '
                        'in sandboxed containers. Docker provides the isolation layer '
                        'that keeps these apps from accessing your files or network '
                        'without permission. Your core identity features (KERI, contacts, '
                        'OOBI sharing) work without Docker.',
                        style: TextStyle(
                          color: AppColors.textMuted,
                          fontSize: 11,
                          fontFamily: 'monospace',
                          height: 1.5,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildDockerActionButton({
    required IconData icon,
    required String label,
    required VoidCallback onPressed,
    bool secondary = false,
  }) {
    return SizedBox(
      width: 280,
      height: 44,
      child: ElevatedButton.icon(
        onPressed: onPressed,
        icon: Icon(icon, size: 18),
        label: Text(
          label,
          style: const TextStyle(
            fontFamily: 'monospace',
            fontWeight: FontWeight.w600,
            letterSpacing: 1,
          ),
        ),
        style: ElevatedButton.styleFrom(
          backgroundColor: secondary ? AppColors.surface : AppColors.accent,
          foregroundColor: secondary ? AppColors.textSecondary : AppColors.primary,
          side: secondary ? const BorderSide(color: AppColors.border) : null,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
        ),
      ),
    );
  }

  Widget _buildError() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const Icon(Icons.error_outline, color: AppColors.error, size: 48),
          const SizedBox(height: 16),
          Text(
            _error ?? 'Unknown error',
            style: const TextStyle(color: AppColors.textSecondary, fontFamily: 'monospace'),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 16),
          ElevatedButton(
            onPressed: _loadData,
            style: ElevatedButton.styleFrom(backgroundColor: AppColors.accent),
            child: const Text('Retry', style: TextStyle(color: AppColors.primary)),
          ),
        ],
      ),
    );
  }

  Widget _buildAppGrid() {
    if (_apps.isEmpty) {
      return const Center(
        child: Text(
          'No apps available',
          style: TextStyle(color: AppColors.textMuted, fontFamily: 'monospace'),
        ),
      );
    }

    return GridView.builder(
      padding: const EdgeInsets.all(20),
      gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
        crossAxisCount: 2,
        mainAxisSpacing: 16,
        crossAxisSpacing: 16,
        childAspectRatio: 1.3,
      ),
      itemCount: _apps.length,
      itemBuilder: (context, index) => _buildAppCard(_apps[index]),
    );
  }

  Widget _buildAppCard(SandboxApp app) {
    final status = _statuses[app.id];
    final isRunning = status?.isRunning ?? false;

    return Container(
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
          color: isRunning ? AppColors.accent.withOpacity(0.5) : AppColors.border,
        ),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                _buildAppIcon(app),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        app.name,
                        style: const TextStyle(
                          color: AppColors.textPrimary,
                          fontWeight: FontWeight.bold,
                          fontFamily: 'monospace',
                          fontSize: 14,
                        ),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                      Text(
                        app.isDocker ? 'Docker' : 'Binary',
                        style: const TextStyle(
                          color: AppColors.textMuted,
                          fontFamily: 'monospace',
                          fontSize: 11,
                        ),
                      ),
                    ],
                  ),
                ),
                _buildStatusBadge(app, isRunning),
              ],
            ),
            const SizedBox(height: 8),
            Text(
              app.description ?? 'No description',
              style: const TextStyle(
                color: AppColors.textSecondary,
                fontFamily: 'monospace',
                fontSize: 11,
              ),
              maxLines: 2,
              overflow: TextOverflow.ellipsis,
            ),
            if (app.isDocker) ...[
              const SizedBox(height: 4),
              Text(
                app.imageSizeDisplay,
                style: TextStyle(
                  color: AppColors.warning.withOpacity(0.8),
                  fontFamily: 'monospace',
                  fontSize: 10,
                ),
              ),
            ],
            const Spacer(),
            _buildActionButtons(app, isRunning),
          ],
        ),
      ),
    );
  }

  Widget _buildAppIcon(SandboxApp app) {
    IconData icon;
    switch (app.iconType) {
      case IconType.browser:
        icon = Icons.public;
        break;
      case IconType.ai:
        icon = Icons.smart_toy;
        break;
      case IconType.code:
        icon = Icons.code;
        break;
      case IconType.terminal:
        icon = Icons.terminal;
        break;
      case IconType.app:
        icon = Icons.apps;
        break;
    }

    return Container(
      width: 40,
      height: 40,
      decoration: BoxDecoration(
        color: AppColors.accent.withOpacity(0.15),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Icon(icon, color: AppColors.accent, size: 22),
    );
  }

  Widget _buildStatusBadge(SandboxApp app, bool isRunning) {
    String label;
    Color color;

    if (isRunning) {
      label = 'RUNNING';
      color = AppColors.coreActive;
    } else if (app.isInstalling) {
      label = 'INSTALLING';
      color = AppColors.corePending;
    } else if (app.isInstalled) {
      label = 'INSTALLED';
      color = AppColors.textSecondary;
    } else {
      label = 'AVAILABLE';
      color = AppColors.textMuted;
    }

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: color.withOpacity(0.15),
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(
        label,
        style: TextStyle(
          color: color,
          fontSize: 9,
          fontWeight: FontWeight.bold,
          fontFamily: 'monospace',
        ),
      ),
    );
  }

  Widget _buildActionButtons(SandboxApp app, bool isRunning) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.end,
      children: [
        if (!app.isInstalled && !app.isInstalling)
          _actionButton('INSTALL', AppColors.accent, () => _installApp(app)),
        if (app.isInstalling)
          const SizedBox(
            width: 16,
            height: 16,
            child: CircularProgressIndicator(strokeWidth: 2, color: AppColors.accent),
          ),
        if (app.isInstalled && !isRunning)
          _actionButton('LAUNCH', AppColors.accent, () => _launchApp(app)),
        if (isRunning) ...[
          _actionButton('VIEW', AppColors.accent, () async {
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
          }),
          const SizedBox(width: 8),
          _actionButton('STOP', AppColors.error, () => _stopApp(app)),
        ],
      ],
    );
  }

  Widget _actionButton(String label, Color color, VoidCallback onPressed) {
    return TextButton(
      onPressed: onPressed,
      style: TextButton.styleFrom(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        minimumSize: Size.zero,
        tapTargetSize: MaterialTapTargetSize.shrinkWrap,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(4),
          side: BorderSide(color: color.withOpacity(0.5)),
        ),
      ),
      child: Text(
        label,
        style: TextStyle(
          color: color,
          fontSize: 11,
          fontWeight: FontWeight.bold,
          fontFamily: 'monospace',
        ),
      ),
    );
  }
}
