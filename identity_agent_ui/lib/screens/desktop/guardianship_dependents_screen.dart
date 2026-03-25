import 'package:flutter/material.dart';
import '../../theme/app_theme.dart';
import '../../services/core_service.dart';
import '../../config/agent_config.dart';
import 'add_dependent_dialog.dart';

class GuardianshipDependentsScreen extends StatefulWidget {
  final String? serverUrl;

  const GuardianshipDependentsScreen({super.key, this.serverUrl});

  @override
  State<GuardianshipDependentsScreen> createState() => _GuardianshipDependentsScreenState();
}

class _GuardianshipDependentsScreenState extends State<GuardianshipDependentsScreen> {
  late final CoreService _coreService;
  List<GuardianshipResponse> _dependents = [];
  bool _loading = true;
  String? _error;
  GuardianshipResponse? _selected;

  @override
  void initState() {
    super.initState();
    _coreService = CoreService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);
    _loadDependents();
  }

  @override
  void dispose() {
    _coreService.dispose();
    super.dispose();
  }

  Future<void> _loadDependents() async {
    setState(() { _loading = true; _error = null; });
    try {
      final resp = await _coreService.getGuardianships();
      if (mounted) {
        setState(() {
          _dependents = resp.guardianships;
          _loading = false;
        });
      }
    } catch (e) {
      if (mounted) setState(() { _error = e.toString(); _loading = false; });
    }
  }

  Future<void> _addDependent() async {
    final created = await showDialog<bool>(
      context: context,
      builder: (_) => AddDependentDialog(serverUrl: widget.serverUrl),
    );
    if (created == true) {
      _loadDependents();
    }
  }

  Future<void> _revokeGuardianship(GuardianshipResponse g) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Revoke Guardianship'),
        content: Text('Are you sure you want to revoke guardianship of ${g.dependentName}?'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: Text('Revoke', style: TextStyle(color: AppColors.error)),
          ),
        ],
      ),
    );
    if (confirm == true) {
      try {
        await _coreService.revokeGuardianship(g.id);
        _loadDependents();
        setState(() => _selected = null);
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('Failed to revoke: $e')),
          );
        }
      }
    }
  }

  Future<void> _emancipate(GuardianshipResponse g) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Emancipate Dependent'),
        content: Text('This will transfer full identity authority to ${g.dependentName}. This action cannot be undone.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: Text('Emancipate', style: TextStyle(color: AppColors.warning)),
          ),
        ],
      ),
    );
    if (confirm == true) {
      try {
        await _coreService.emancipateGuardianship(g.id);
        _loadDependents();
        setState(() => _selected = null);
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text('Failed to emancipate: $e')),
          );
        }
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
          // Header
          Container(
            padding: const EdgeInsets.fromLTRB(32, 24, 32, 16),
            child: Row(
              children: [
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text('My Dependents', style: Theme.of(context).textTheme.headlineSmall),
                      const SizedBox(height: 4),
                      Text(
                        'People you are guardian of. Their identities are managed through your Identity Agent.',
                        style: Theme.of(context).textTheme.bodyMedium?.copyWith(color: AppColors.textSecondary),
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: 16),
                FilledButton.icon(
                  onPressed: _addDependent,
                  icon: const Icon(Icons.add, size: 16),
                  label: const Text('Add Dependent',
                      style: TextStyle(fontSize: 13, fontWeight: FontWeight.w500, letterSpacing: 0.2)),
                  style: FilledButton.styleFrom(
                    backgroundColor: AppColors.accent,
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                    minimumSize: const Size(0, 36),
                    tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                    elevation: 0,
                  ),
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
                    : _dependents.isEmpty
                        ? _buildEmptyState()
                        : Row(
                            children: [
                              // List
                              SizedBox(
                                width: 380,
                                child: ListView.builder(
                                  padding: const EdgeInsets.all(16),
                                  itemCount: _dependents.length,
                                  itemBuilder: (_, i) => _buildDependentCard(_dependents[i]),
                                ),
                              ),
                              const VerticalDivider(width: 1),
                              // Detail
                              Expanded(
                                child: _selected != null
                                    ? _buildDetailPane(_selected!)
                                    : Center(
                                        child: Text(
                                          'Select a dependent to view details',
                                          style: TextStyle(color: AppColors.textMuted),
                                        ),
                                      ),
                              ),
                            ],
                          ),
          ),
        ],
      ),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 72,
            height: 72,
            decoration: BoxDecoration(
              color: AppColors.primary.withOpacity(0.08),
              borderRadius: BorderRadius.circular(20),
            ),
            child: Icon(Icons.family_restroom_outlined, size: 36, color: AppColors.primary),
          ),
          const SizedBox(height: 24),
          Text('No Dependents', style: Theme.of(context).textTheme.titleLarge),
          const SizedBox(height: 8),
          Text(
            'Add a dependent to manage their identity through your Identity Agent.',
            style: Theme.of(context).textTheme.bodyMedium,
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 20),
          FilledButton.icon(
            onPressed: _addDependent,
            icon: const Icon(Icons.add, size: 18),
            label: const Text('Add Dependent'),
          ),
        ],
      ),
    );
  }

  Widget _buildDependentCard(GuardianshipResponse g) {
    final isSelected = _selected?.id == g.id;
    final statusColor = g.isActive ? AppColors.success
        : g.status == 'emancipated' ? AppColors.warning
        : AppColors.error;

    return InkWell(
      onTap: () => setState(() => _selected = g),
      borderRadius: BorderRadius.circular(12),
      child: Container(
        margin: const EdgeInsets.only(bottom: 8),
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          color: isSelected ? AppColors.primary.withOpacity(0.06) : Colors.transparent,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(
            color: isSelected ? AppColors.primary.withOpacity(0.3) : AppColors.border,
          ),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                CircleAvatar(
                  radius: 18,
                  backgroundColor: AppColors.primary.withOpacity(0.1),
                  child: Text(
                    g.dependentName.isNotEmpty ? g.dependentName[0].toUpperCase() : '?',
                    style: TextStyle(color: AppColors.primary, fontWeight: FontWeight.w600),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    g.dependentName,
                    style: Theme.of(context).textTheme.titleSmall,
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                  decoration: BoxDecoration(
                    color: statusColor.withOpacity(0.12),
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: Text(
                    g.status.toUpperCase(),
                    style: TextStyle(fontSize: 10, color: statusColor, fontWeight: FontWeight.w600),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Row(
              children: [
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                  decoration: BoxDecoration(
                    color: AppColors.accent.withOpacity(0.08),
                    borderRadius: BorderRadius.circular(3),
                  ),
                  child: Text(
                    g.typeLabel,
                    style: TextStyle(fontSize: 11, color: AppColors.accent),
                  ),
                ),
                const Spacer(),
                Icon(
                  g.hostingType == 'cloud' ? Icons.cloud_outlined : Icons.phone_android_outlined,
                  size: 14,
                  color: AppColors.textMuted,
                ),
                const SizedBox(width: 4),
                Text(
                  g.hostingType == 'cloud' ? 'Cloud-hosted' : 'Device',
                  style: TextStyle(fontSize: 11, color: AppColors.textMuted),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildDetailPane(GuardianshipResponse g) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(32),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              CircleAvatar(
                radius: 28,
                backgroundColor: AppColors.primary.withOpacity(0.1),
                child: Text(
                  g.dependentName.isNotEmpty ? g.dependentName[0].toUpperCase() : '?',
                  style: TextStyle(fontSize: 24, color: AppColors.primary, fontWeight: FontWeight.w600),
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(g.dependentName, style: Theme.of(context).textTheme.headlineSmall),
                    const SizedBox(height: 4),
                    Text(g.typeLabel, style: TextStyle(color: AppColors.textSecondary)),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 32),
          _detailRow('Status', g.status.toUpperCase()),
          _detailRow('Hosting', g.hostingType == 'cloud' ? 'Cloud-hosted (Grape ID)' : 'Separate device'),
          if (g.hostingUrl.isNotEmpty) _detailRow('Hosting URL', g.hostingUrl),
          if (g.dependentAid.isNotEmpty) _detailRow('Dependent AID', g.dependentAid),
          if (g.delegatedAidPrefix.isNotEmpty) _detailRow('Delegated AID', g.delegatedAidPrefix),
          _detailRow('Created', g.createdAt),
          if (g.emancipationTrigger != null)
            _detailRow('Emancipation', '${g.emancipationTrigger!.type}: ${g.emancipationTrigger!.value}'),
          if (g.coGuardians.isNotEmpty)
            _detailRow('Co-guardians', g.coGuardians.join(', ')),
          if (g.multisigThreshold > 0)
            _detailRow('Multi-sig threshold', '${g.multisigThreshold}'),
          if (g.metadata.isNotEmpty) ...[
            const SizedBox(height: 16),
            Text('Additional Info', style: Theme.of(context).textTheme.titleSmall),
            const SizedBox(height: 8),
            ...g.metadata.entries.map((e) => _detailRow(e.key, e.value)),
          ],
          const SizedBox(height: 32),
          if (g.isActive) ...[
            Row(
              children: [
                OutlinedButton.icon(
                  onPressed: () => _emancipate(g),
                  icon: const Icon(Icons.launch, size: 16),
                  label: const Text('Emancipate'),
                ),
                const SizedBox(width: 12),
                OutlinedButton.icon(
                  onPressed: () => _revokeGuardianship(g),
                  icon: Icon(Icons.block, size: 16, color: AppColors.error),
                  label: Text('Revoke', style: TextStyle(color: AppColors.error)),
                  style: OutlinedButton.styleFrom(
                    side: BorderSide(color: AppColors.error.withOpacity(0.3)),
                  ),
                ),
              ],
            ),
          ],
        ],
      ),
    );
  }

  Widget _detailRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 160,
            child: Text(label, style: TextStyle(color: AppColors.textMuted, fontSize: 13)),
          ),
          Expanded(
            child: Text(
              value,
              style: const TextStyle(fontSize: 13, fontFamily: 'monospace'),
            ),
          ),
        ],
      ),
    );
  }
}
