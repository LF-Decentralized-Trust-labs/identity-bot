import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../../theme/app_theme.dart';
import '../../services/core_service.dart';
import '../../config/agent_config.dart';

/// Endpoints screen — shows all live public endpoints and available actions.
///
/// The agent URL and OOBI are fetched from the backend. The actions list is
/// always pulled dynamically from GET /api/actions so the backend is the
/// single source of truth for what the agent can do.
class EndpointsScreen extends StatefulWidget {
  final String? serverUrl;

  const EndpointsScreen({super.key, this.serverUrl});

  @override
  State<EndpointsScreen> createState() => _EndpointsScreenState();
}

class _EndpointsScreenState extends State<EndpointsScreen> {
  late final CoreService _coreService =
      CoreService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);

  bool _loading = true;
  String? _error;

  String _agentUrl = '';
  String _oobiUrl = '';
  String _aid = '';
  List<Map<String, dynamic>> _actions = [];

  String _searchQuery = '';
  String? _expandedAction;

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
        _coreService.getEndpoint(),
        _coreService.getOobi(),
        _coreService.getActions(),
      ]);
      final endpoint = results[0] as Map<String, dynamic>;
      final oobi = results[1] as OobiResponse;
      final actions = results[2] as List<Map<String, dynamic>>;

      if (mounted) {
        setState(() {
          _agentUrl = endpoint['url']?.toString() ?? '';
          _oobiUrl = oobi.oobiUrl;
          _aid = oobi.aid;
          _actions = actions;
          _loading = false;
        });
      }
    } catch (e) {
      if (mounted) setState(() { _error = e.toString(); _loading = false; });
    }
  }

  void _copy(String text, String label) {
    Clipboard.setData(ClipboardData(text: text));
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text('$label copied'), behavior: SnackBarBehavior.floating),
    );
  }

  List<Map<String, dynamic>> get _filteredActions {
    if (_searchQuery.isEmpty) return _actions;
    final q = _searchQuery.toLowerCase();
    return _actions.where((a) {
      final name = (a['name'] ?? '').toString().toLowerCase();
      final desc = (a['description'] ?? '').toString().toLowerCase();
      final endpoint = (a['endpoint'] ?? '').toString().toLowerCase();
      final tags = List<String>.from(a['tags'] ?? []).join(' ').toLowerCase();
      return name.contains(q) || desc.contains(q) || endpoint.contains(q) || tags.contains(q);
    }).toList();
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
                      Text('Endpoints', style: Theme.of(context).textTheme.headlineMedium),
                      const SizedBox(height: 4),
                      Text('All live public endpoints for this Identity Agent.',
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
              _buildPrimaryEndpoints(),
              const SizedBox(height: 24),
              _buildActionsSection(),
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

  Widget _buildPrimaryEndpoints() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text('Primary Endpoints',
            style: TextStyle(fontSize: 13, fontWeight: FontWeight.w600, color: AppColors.textSecondary)),
        const SizedBox(height: 12),
        _endpointRow(
          icon: Icons.dns_outlined,
          label: 'Identity Agent URL',
          description: 'Base URL for this agent. All API calls use this as the root.',
          value: _agentUrl.isNotEmpty ? _agentUrl : '(not available)',
          badge: _agentUrl.isNotEmpty ? 'LIVE' : 'OFFLINE',
          badgeColor: _agentUrl.isNotEmpty ? AppColors.success : AppColors.error,
        ),
        const SizedBox(height: 10),
        _endpointRow(
          icon: Icons.link,
          label: 'OOBI Endpoint',
          description: 'Share this URL so other agents can add you as a contact.',
          value: _oobiUrl.isNotEmpty ? _oobiUrl : '(no identity)',
          badge: _oobiUrl.isNotEmpty ? 'PUBLIC' : null,
          badgeColor: AppColors.primary,
        ),
        const SizedBox(height: 10),
        _endpointRow(
          icon: Icons.fingerprint,
          label: 'AID',
          description: 'Your Autonomous Identifier (cryptographic identity anchor).',
          value: _aid.isNotEmpty ? _aid : '(no identity)',
          badge: null,
          badgeColor: AppColors.textMuted,
          valueColor: AppColors.primary,
        ),
        const SizedBox(height: 10),
        _endpointRow(
          icon: Icons.smart_toy_outlined,
          label: 'MCP Server',
          description: 'AI agents connect here to access identity actions via Model Context Protocol.',
          value: _agentUrl.isNotEmpty ? '$_agentUrl/api/mcp' : '(agent URL not set)',
          badge: 'MCP',
          badgeColor: AppColors.accent,
        ),
      ],
    );
  }

  Widget _endpointRow({
    required IconData icon,
    required String label,
    required String description,
    required String value,
    required String? badge,
    required Color badgeColor,
    Color? valueColor,
  }) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        border: Border.all(color: AppColors.border),
        borderRadius: BorderRadius.circular(10),
        color: Theme.of(context).colorScheme.surface,
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(icon, size: 16, color: AppColors.textSecondary),
              const SizedBox(width: 8),
              Text(label,
                  style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600,
                      color: AppColors.textPrimary)),
              const Spacer(),
              if (badge != null)
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                  decoration: BoxDecoration(
                    color: badgeColor.withOpacity(0.12),
                    borderRadius: BorderRadius.circular(4),
                    border: Border.all(color: badgeColor.withOpacity(0.3)),
                  ),
                  child: Text(badge,
                      style: TextStyle(color: badgeColor, fontSize: 9,
                          fontWeight: FontWeight.w700, letterSpacing: 0.8, fontFamily: 'monospace')),
                ),
            ],
          ),
          const SizedBox(height: 4),
          Text(description,
              style: const TextStyle(color: AppColors.textMuted, fontSize: 11)),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(
                child: SelectableText(
                  value,
                  style: TextStyle(
                    color: valueColor ?? AppColors.accent,
                    fontSize: 11,
                    fontFamily: 'monospace',
                    height: 1.4,
                  ),
                ),
              ),
              if (value != '(not available)' && value != '(no identity)' && value != '(agent URL not set)')
                InkWell(
                  onTap: () => _copy(value, label),
                  borderRadius: BorderRadius.circular(6),
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                    decoration: BoxDecoration(
                      color: AppColors.surfaceLight,
                      borderRadius: BorderRadius.circular(6),
                      border: Border.all(color: AppColors.border),
                    ),
                    child: const Icon(Icons.copy, size: 13, color: AppColors.textMuted),
                  ),
                ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildActionsSection() {
    final filtered = _filteredActions;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            const Text('Available Actions',
                style: TextStyle(fontSize: 13, fontWeight: FontWeight.w600,
                    color: AppColors.textSecondary)),
            const Spacer(),
            Text('${filtered.length} action${filtered.length == 1 ? '' : 's'}',
                style: const TextStyle(fontSize: 11, color: AppColors.textMuted)),
          ],
        ),
        const SizedBox(height: 10),
        TextField(
          onChanged: (v) => setState(() => _searchQuery = v),
          style: const TextStyle(color: AppColors.textPrimary, fontSize: 13),
          decoration: InputDecoration(
            hintText: 'Search actions…',
            hintStyle: const TextStyle(color: AppColors.textMuted, fontSize: 13),
            prefixIcon: const Icon(Icons.search, color: AppColors.textMuted, size: 18),
            filled: true,
            fillColor: AppColors.surfaceLight,
            border: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
              borderSide: const BorderSide(color: AppColors.border),
            ),
            enabledBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
              borderSide: const BorderSide(color: AppColors.border),
            ),
            focusedBorder: OutlineInputBorder(
              borderRadius: BorderRadius.circular(8),
              borderSide: const BorderSide(color: AppColors.primary),
            ),
            contentPadding: const EdgeInsets.symmetric(vertical: 10, horizontal: 12),
          ),
        ),
        const SizedBox(height: 12),
        if (filtered.isEmpty)
          Container(
            padding: const EdgeInsets.all(20),
            decoration: BoxDecoration(
              border: Border.all(color: AppColors.border),
              borderRadius: BorderRadius.circular(10),
            ),
            child: const Center(
              child: Text('No matching actions.',
                  style: TextStyle(color: AppColors.textMuted, fontSize: 13)),
            ),
          )
        else
          ...filtered.map((action) => _actionCard(action)),
      ],
    );
  }

  Widget _actionCard(Map<String, dynamic> action) {
    final name = action['name']?.toString() ?? '';
    final endpoint = action['endpoint']?.toString() ?? '';
    final method = action['method']?.toString() ?? 'GET';
    final description = action['description']?.toString() ?? '';
    final tags = List<String>.from(action['tags'] ?? []);
    final fullEndpoint = _agentUrl.isNotEmpty ? '$_agentUrl$endpoint' : endpoint;
    final isExpanded = _expandedAction == name;

    final methodColor = method == 'GET'
        ? AppColors.success
        : method == 'POST'
            ? AppColors.primary
            : method == 'DELETE'
                ? AppColors.error
                : AppColors.warning;

    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      decoration: BoxDecoration(
        border: Border.all(color: isExpanded ? AppColors.primary.withOpacity(0.4) : AppColors.border),
        borderRadius: BorderRadius.circular(10),
        color: Theme.of(context).colorScheme.surface,
      ),
      child: InkWell(
        onTap: () => setState(() => _expandedAction = isExpanded ? null : name),
        borderRadius: BorderRadius.circular(10),
        child: Column(
          children: [
            Padding(
              padding: const EdgeInsets.all(14),
              child: Row(
                children: [
                  Container(
                    width: 44,
                    padding: const EdgeInsets.symmetric(vertical: 3),
                    decoration: BoxDecoration(
                      color: methodColor.withOpacity(0.1),
                      borderRadius: BorderRadius.circular(4),
                    ),
                    alignment: Alignment.center,
                    child: Text(method,
                        style: TextStyle(color: methodColor, fontSize: 10,
                            fontWeight: FontWeight.w700, fontFamily: 'monospace')),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(name,
                            style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600,
                                color: AppColors.textPrimary)),
                        const SizedBox(height: 2),
                        Text(endpoint,
                            style: const TextStyle(fontSize: 11, color: AppColors.textMuted,
                                fontFamily: 'monospace')),
                      ],
                    ),
                  ),
                  Icon(
                    isExpanded ? Icons.keyboard_arrow_up : Icons.keyboard_arrow_down,
                    color: AppColors.textMuted,
                    size: 18,
                  ),
                ],
              ),
            ),
            if (isExpanded)
              Container(
                width: double.infinity,
                padding: const EdgeInsets.fromLTRB(14, 0, 14, 14),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Divider(height: 1),
                    const SizedBox(height: 12),
                    Text(description,
                        style: const TextStyle(color: AppColors.textSecondary, fontSize: 12,
                            height: 1.5)),
                    const SizedBox(height: 10),
                    Row(
                      children: [
                        Expanded(
                          child: SelectableText(
                            fullEndpoint,
                            style: const TextStyle(color: AppColors.accent, fontSize: 11,
                                fontFamily: 'monospace'),
                          ),
                        ),
                        const SizedBox(width: 8),
                        InkWell(
                          onTap: () => _copy(fullEndpoint, '$name endpoint'),
                          borderRadius: BorderRadius.circular(6),
                          child: Container(
                            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                            decoration: BoxDecoration(
                              color: AppColors.surfaceLight,
                              borderRadius: BorderRadius.circular(6),
                              border: Border.all(color: AppColors.border),
                            ),
                            child: const Icon(Icons.copy, size: 13, color: AppColors.textMuted),
                          ),
                        ),
                      ],
                    ),
                    if (tags.isNotEmpty) ...[
                      const SizedBox(height: 10),
                      Wrap(
                        spacing: 6,
                        children: tags.map((tag) => Container(
                          padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                          decoration: BoxDecoration(
                            color: AppColors.surfaceVariant,
                            borderRadius: BorderRadius.circular(4),
                          ),
                          child: Text(tag,
                              style: const TextStyle(color: AppColors.textMuted, fontSize: 10,
                                  fontWeight: FontWeight.w500)),
                        )).toList(),
                      ),
                    ],
                  ],
                ),
              ),
          ],
        ),
      ),
    );
  }
}
