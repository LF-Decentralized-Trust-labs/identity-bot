import 'package:flutter/material.dart';
import '../../theme/app_theme.dart';
import 'package:agent_client/services/core_service.dart';
import 'package:agent_client/config/agent_config.dart';

class ServiceProvidersScreen extends StatefulWidget {
  final String? serverUrl;

  const ServiceProvidersScreen({super.key, this.serverUrl});

  @override
  State<ServiceProvidersScreen> createState() => _ServiceProvidersScreenState();
}

class _ServiceProvidersScreenState extends State<ServiceProvidersScreen> with SingleTickerProviderStateMixin {
  late final CoreService _coreService;
  late final TabController _tabController;
  List<ServiceProviderResponse> _providers = [];
  bool _loading = true;
  String? _error;
  String _categoryFilter = 'all';

  static const _categories = ['all', 'infrastructure', 'witness', 'cloud_hsm', 'tunneling'];
  static const _categoryLabels = {
    'all': 'All',
    'infrastructure': 'Infrastructure',
    'witness': 'Witness',
    'cloud_hsm': 'Cloud HSM',
    'tunneling': 'Tunneling',
  };

  @override
  void initState() {
    super.initState();
    _coreService = CoreService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);
    _tabController = TabController(length: 3, vsync: this);
    _loadProviders();
  }

  @override
  void dispose() {
    _coreService.dispose();
    _tabController.dispose();
    super.dispose();
  }

  Future<void> _loadProviders() async {
    setState(() { _loading = true; _error = null; });
    try {
      final resp = await _coreService.getServiceProviders();
      if (mounted) setState(() { _providers = resp.providers; _loading = false; });
    } catch (e) {
      if (mounted) setState(() { _error = e.toString(); _loading = false; });
    }
  }

  List<ServiceProviderResponse> get _connected =>
      _filtered.where((p) => p.isConnected).toList();

  List<ServiceProviderResponse> get _available =>
      _filtered.where((p) => !p.isConnected).toList();

  List<ServiceProviderResponse> get _filtered =>
      _categoryFilter == 'all'
          ? _providers
          : _providers.where((p) => p.category == _categoryFilter).toList();

  Future<void> _connect(ServiceProviderResponse p) async {
    try {
      await _coreService.connectServiceProvider(p.id);
      _loadProviders();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Failed: $e')));
      }
    }
  }

  Future<void> _disconnect(ServiceProviderResponse p) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Disconnect Provider'),
        content: Text('Disconnect ${p.displayName}? You can reconnect later.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          TextButton(onPressed: () => Navigator.pop(ctx, true), child: const Text('Disconnect')),
        ],
      ),
    );
    if (confirm == true) {
      try {
        await _coreService.disconnectServiceProvider(p.id);
        _loadProviders();
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Failed: $e')));
        }
      }
    }
  }

  Future<void> _checkHealth(ServiceProviderResponse p) async {
    try {
      await _coreService.checkServiceProviderHealth(p.id);
      _loadProviders();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Health check failed: $e')));
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Scaffold(
      backgroundColor: cs.surface,
      body: Column(
        children: [
          Container(
              padding: EdgeInsets.fromLTRB(
                AppLayout.isMobile(context) ? 16 : 32,
                AppLayout.isMobile(context) ? 12 : 24,
                AppLayout.isMobile(context) ? 16 : 32,
                0,
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  if (!AppLayout.isMobile(context)) ...[
                    Text('Service Providers', style: Theme.of(context).textTheme.headlineSmall),
                    const SizedBox(height: 4),
                    Text(
                      'Manage external services your Identity Agent depends on for infrastructure, witnessing, key storage, and tunneling.',
                      style: Theme.of(context).textTheme.bodyMedium?.copyWith(color: AppColors.textSecondary),
                    ),
                    const SizedBox(height: 16),
                  ],
                // Category filter chips
                SingleChildScrollView(
                  scrollDirection: Axis.horizontal,
                  child: Row(
                    children: _categories.map((cat) {
                      final isSelected = _categoryFilter == cat;
                      return Padding(
                        padding: const EdgeInsets.only(right: 8),
                        child: FilterChip(
                          label: Text(_categoryLabels[cat] ?? cat),
                          selected: isSelected,
                          onSelected: (_) => setState(() => _categoryFilter = cat),
                          selectedColor: AppColors.primary.withOpacity(0.15),
                          checkmarkColor: AppColors.primary,
                        ),
                      );
                    }).toList(),
                  ),
                ),
                const SizedBox(height: 12),
                // Tabs
                TabBar(
                  controller: _tabController,
                  tabs: [
                    Tab(text: 'All (${_filtered.length})'),
                    Tab(text: 'Connected (${_connected.length})'),
                    Tab(text: 'Available (${_available.length})'),
                  ],
                  labelColor: AppColors.primary,
                  unselectedLabelColor: AppColors.textMuted,
                  indicatorColor: AppColors.primary,
                ),
              ],
            ),
          ),
          const Divider(height: 1),
          // Content
          Expanded(
            child: _loading
                ? const Center(child: CircularProgressIndicator())
                : _error != null
                    ? Center(child: Text(_error!, style: TextStyle(color: AppColors.error)))
                    : TabBarView(
                        controller: _tabController,
                        children: [
                          _buildProviderList(_filtered, isConnectedView: false),
                          _buildProviderList(_connected, isConnectedView: true),
                          _buildProviderList(_available, isConnectedView: false),
                        ],
                      ),
          ),
        ],
      ),
    );
  }

  Widget _buildProviderList(List<ServiceProviderResponse> providers, {required bool isConnectedView}) {
    if (providers.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              isConnectedView ? Icons.cloud_off_outlined : Icons.cloud_queue,
              size: 48,
              color: AppColors.textMuted,
            ),
            const SizedBox(height: 16),
            Text(
              isConnectedView ? 'No connected providers' : 'No available providers',
              style: Theme.of(context).textTheme.titleMedium?.copyWith(color: AppColors.textMuted),
            ),
            if (!isConnectedView) ...[
              const SizedBox(height: 8),
              Text(
                'Connect a provider from the Available tab or add one manually.',
                style: TextStyle(color: AppColors.textMuted, fontSize: 13),
              ),
            ],
          ],
        ),
      );
    }

    return ListView.builder(
      padding: const EdgeInsets.all(24),
      itemCount: providers.length,
      itemBuilder: (_, i) => ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 720),
        child: _buildProviderCard(providers[i], isConnectedView: isConnectedView),
      ),
    );
  }

  Widget _buildProviderCard(ServiceProviderResponse p, {required bool isConnectedView}) {
    final healthColor = p.health == 'healthy' ? AppColors.success
        : p.health == 'degraded' ? AppColors.warning
        : p.health == 'unreachable' ? AppColors.error
        : AppColors.textMuted;
    final healthLabel = p.health == 'unknown' ? 'Not checked' : p.health.toUpperCase();

    final statusColor = p.isConnected ? AppColors.success
        : p.status == 'disconnected' ? AppColors.warning
        : AppColors.textMuted;

    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: AppColors.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header row
          Row(
            children: [
              Expanded(
                child: Text(p.displayName, style: Theme.of(context).textTheme.titleMedium),
              ),
              // Category badge
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  color: AppColors.accent.withOpacity(0.08),
                  borderRadius: BorderRadius.circular(4),
                ),
                child: Text(
                  p.categoryLabel,
                  style: TextStyle(fontSize: 11, color: AppColors.accent, fontWeight: FontWeight.w600),
                ),
              ),
              const SizedBox(width: 8),
              // Status badge
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  color: statusColor.withOpacity(0.12),
                  borderRadius: BorderRadius.circular(4),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(Icons.circle, size: 6, color: statusColor),
                    const SizedBox(width: 4),
                    Text(
                      p.status.toUpperCase(),
                      style: TextStyle(fontSize: 10, color: statusColor, fontWeight: FontWeight.w600),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          // Detail rows
          _infoRow(Icons.link, 'Endpoint', p.endpointUrl),
          if (p.companyHq.isNotEmpty) _infoRow(Icons.business, 'Company HQ', p.companyHq),
          if (p.serverRegion.isNotEmpty) _infoRow(Icons.dns_outlined, 'Server Region', p.serverRegion),
          if (p.identityLevel > 0 || p.grapeScore > 0)
            _infoRow(Icons.verified_outlined, 'Trust', 'Identity Level ${p.identityLevel} \u00b7 Grape Score ${p.grapeScore}'),
          if (isConnectedView) ...[
            _infoRow(
              p.health == 'healthy' ? Icons.check_circle_outline : Icons.error_outline,
              'Health',
              '$healthLabel${p.healthCheckedAt.isNotEmpty ? " (${_formatTime(p.healthCheckedAt)})" : ""}',
              valueColor: healthColor,
            ),
            if (p.connectedAt.isNotEmpty)
              _infoRow(Icons.access_time, 'Connected', _formatTime(p.connectedAt)),
          ],
          if (p.capabilities.isNotEmpty) ...[
            const SizedBox(height: 8),
            Wrap(
              spacing: 6,
              runSpacing: 4,
              children: p.capabilities.map((cap) => Container(
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                  color: AppColors.primary.withOpacity(0.06),
                  borderRadius: BorderRadius.circular(3),
                ),
                child: Text(
                  cap.replaceAll('_', ' '),
                  style: TextStyle(fontSize: 10, color: AppColors.primary),
                ),
              )).toList(),
            ),
          ],
          const SizedBox(height: 16),
          // Actions
          Row(
            mainAxisAlignment: MainAxisAlignment.end,
            children: [
              if (isConnectedView) ...[
                OutlinedButton.icon(
                  onPressed: () => _checkHealth(p),
                  icon: const Icon(Icons.refresh, size: 14),
                  label: const Text('Check Health'),
                  style: OutlinedButton.styleFrom(textStyle: const TextStyle(fontSize: 12)),
                ),
                const SizedBox(width: 8),
                OutlinedButton.icon(
                  onPressed: () => _disconnect(p),
                  icon: Icon(Icons.link_off, size: 14, color: AppColors.error),
                  label: Text('Disconnect', style: TextStyle(color: AppColors.error)),
                  style: OutlinedButton.styleFrom(
                    side: BorderSide(color: AppColors.error.withOpacity(0.3)),
                    textStyle: const TextStyle(fontSize: 12),
                  ),
                ),
              ] else ...[
                FilledButton.icon(
                  onPressed: () => _connect(p),
                  icon: const Icon(Icons.link, size: 14),
                  label: const Text('Connect'),
                  style: FilledButton.styleFrom(textStyle: const TextStyle(fontSize: 12)),
                ),
              ],
            ],
          ),
        ],
      ),
    );
  }

  Widget _infoRow(IconData icon, String label, String value, {Color? valueColor}) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Row(
        children: [
          Icon(icon, size: 14, color: AppColors.textMuted),
          const SizedBox(width: 8),
          SizedBox(
            width: 100,
            child: Text(label, style: TextStyle(fontSize: 12, color: AppColors.textMuted)),
          ),
          Expanded(
            child: Text(
              value,
              style: TextStyle(fontSize: 12, fontFamily: 'monospace', color: valueColor),
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
  }

  String _formatTime(String iso) {
    try {
      final dt = DateTime.parse(iso);
      final diff = DateTime.now().difference(dt);
      if (diff.inMinutes < 1) return 'just now';
      if (diff.inMinutes < 60) return '${diff.inMinutes}m ago';
      if (diff.inHours < 24) return '${diff.inHours}h ago';
      return '${dt.month}/${dt.day}/${dt.year}';
    } catch (_) {
      return iso;
    }
  }
}
