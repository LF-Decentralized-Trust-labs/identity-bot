import 'package:flutter/material.dart';
import '../../theme/app_theme.dart';
import '../../services/core_service.dart';
import '../../config/agent_config.dart';

// ── Data model for a provider row ─────────────────────────────────────────────
class _ApiProvider {
  final String id;
  final String name;
  final String description;
  final String url;
  final String hintText;
  final IconData icon;

  const _ApiProvider({
    required this.id,
    required this.name,
    required this.description,
    required this.url,
    required this.hintText,
    required this.icon,
  });
}

// ── Provider catalogue (extend as backend adds support) ───────────────────────
const _providers = [
  _ApiProvider(
    id: 'openrouter',
    name: 'OpenRouter',
    description: 'Access 200+ AI models through a single API, including Claude, GPT-4, and Llama.',
    url: 'openrouter.ai',
    hintText: 'sk-or-v1-...',
    icon: Icons.auto_awesome,
  ),
];

// ── Screen ────────────────────────────────────────────────────────────────────
class ApiKeysScreen extends StatefulWidget {
  final String? serverUrl;

  const ApiKeysScreen({super.key, this.serverUrl});

  @override
  State<ApiKeysScreen> createState() => _ApiKeysScreenState();
}

class _ApiKeysScreenState extends State<ApiKeysScreen> {
  late final CoreService _coreService;

  // Per-provider state maps
  final Map<String, bool> _keySet       = {};
  final Map<String, bool> _showKey      = {};
  final Map<String, bool> _saving       = {};
  final Map<String, bool> _deleting     = {};
  final Map<String, bool> _editing      = {};
  final Map<String, TextEditingController> _controllers = {};

  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _coreService = CoreService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);
    for (final p in _providers) {
      _keySet[p.id]    = false;
      _showKey[p.id]   = false;
      _saving[p.id]    = false;
      _deleting[p.id]  = false;
      _editing[p.id]   = false;
      _controllers[p.id] = TextEditingController();
    }
    _loadKeys();
  }

  @override
  void dispose() {
    for (final c in _controllers.values) c.dispose();
    _coreService.dispose();
    super.dispose();
  }

  Future<void> _loadKeys() async {
    setState(() => _loading = true);
    try {
      final data = await _coreService.getLLMSettings();
      final serviceStatus = data['service_status'] as Map<String, dynamic>? ?? {};
      if (mounted) {
        setState(() {
          for (final p in _providers) {
            _keySet[p.id] = serviceStatus[p.id] == true;
          }
          _loading = false;
        });
      }
    } catch (_) {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _saveKey(String id) async {
    final key = _controllers[id]!.text.trim();
    if (key.isEmpty) return;
    setState(() => _saving[id] = true);
    try {
      await _coreService.saveLLMKey(id, key);
      _controllers[id]!.clear();
      if (mounted) {
        setState(() {
          _keySet[id]   = true;
          _saving[id]   = false;
          _editing[id]  = false;
        });
        _showSnack('Key saved');
      }
    } catch (e) {
      if (mounted) {
        setState(() => _saving[id] = false);
        _showSnack('Failed to save: $e', error: true);
      }
    }
  }

  Future<void> _deleteKey(String id, String name) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppColors.surface,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        title: Text('Remove $name key?',
            style: const TextStyle(color: AppColors.textPrimary, fontSize: 15, fontWeight: FontWeight.w600)),
        content: Text('The key will be deleted from your Identity Agent.',
            style: const TextStyle(color: AppColors.textSecondary, fontSize: 13)),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: const Text('Cancel', style: TextStyle(color: AppColors.textMuted)),
          ),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Remove', style: TextStyle(color: AppColors.error)),
          ),
        ],
      ),
    );
    if (confirm != true) return;
    setState(() => _deleting[id] = true);
    try {
      await _coreService.deleteLLMKey(id);
      if (mounted) {
        setState(() {
          _keySet[id]    = false;
          _deleting[id]  = false;
          _editing[id]   = false;
          _controllers[id]!.clear();
        });
        _showSnack('Key removed');
      }
    } catch (e) {
      if (mounted) {
        setState(() => _deleting[id] = false);
        _showSnack('Failed to remove: $e', error: true);
      }
    }
  }

  void _showSnack(String msg, {bool error = false}) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: Text(msg, style: const TextStyle(fontFamily: 'monospace')),
      backgroundColor: error ? AppColors.error : AppColors.accent,
      behavior: SnackBarBehavior.floating,
      duration: const Duration(seconds: 3),
    ));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Theme.of(context).colorScheme.surface,
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : SingleChildScrollView(
              padding: const EdgeInsets.all(32),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // ── Page header ──────────────────────────────────────────
                  const Text(
                    'API Keys',
                    style: TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 22,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                  const SizedBox(height: 6),
                  const Text(
                    'Connect AI and third-party services to your Identity Agent. '
                    'Keys are stored locally and never leave your device.',
                    style: TextStyle(
                      color: AppColors.textSecondary,
                      fontSize: 13,
                      height: 1.5,
                    ),
                  ),
                  const SizedBox(height: 32),

                  // ── Provider list ────────────────────────────────────────
                  Container(
                    decoration: BoxDecoration(
                      color: AppColors.surface,
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(color: AppColors.border),
                    ),
                    child: Column(
                      children: [
                        for (int i = 0; i < _providers.length; i++) ...[
                          if (i > 0) Divider(height: 1, color: AppColors.border),
                          _ProviderRow(
                            provider: _providers[i],
                            keySet:    _keySet[_providers[i].id]    ?? false,
                            showKey:   _showKey[_providers[i].id]   ?? false,
                            saving:    _saving[_providers[i].id]    ?? false,
                            deleting:  _deleting[_providers[i].id]  ?? false,
                            editing:   _editing[_providers[i].id]   ?? false,
                            controller: _controllers[_providers[i].id]!,
                            onToggleShow:   () => setState(() => _showKey[_providers[i].id] = !(_showKey[_providers[i].id] ?? false)),
                            onToggleEdit:   () => setState(() => _editing[_providers[i].id] = !(_editing[_providers[i].id] ?? false)),
                            onSave:         () => _saveKey(_providers[i].id),
                            onDelete:       () => _deleteKey(_providers[i].id, _providers[i].name),
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

// ── Provider row ──────────────────────────────────────────────────────────────
class _ProviderRow extends StatelessWidget {
  final _ApiProvider provider;
  final bool keySet;
  final bool showKey;
  final bool saving;
  final bool deleting;
  final bool editing;
  final TextEditingController controller;
  final VoidCallback onToggleShow;
  final VoidCallback onToggleEdit;
  final VoidCallback onSave;
  final VoidCallback onDelete;

  const _ProviderRow({
    required this.provider,
    required this.keySet,
    required this.showKey,
    required this.saving,
    required this.deleting,
    required this.editing,
    required this.controller,
    required this.onToggleShow,
    required this.onToggleEdit,
    required this.onSave,
    required this.onDelete,
  });

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // ── Top row: icon + name + url + status badge + actions ──────────
          Row(
            crossAxisAlignment: CrossAxisAlignment.center,
            children: [
              // Provider icon
              Container(
                width: 36,
                height: 36,
                decoration: BoxDecoration(
                  color: AppColors.surfaceVariant,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Icon(provider.icon, size: 18, color: AppColors.textSecondary),
              ),
              const SizedBox(width: 12),

              // Name + URL
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      provider.name,
                      style: const TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 14,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    Text(
                      provider.url,
                      style: const TextStyle(
                        color: AppColors.textMuted,
                        fontSize: 11,
                        fontFamily: 'monospace',
                      ),
                    ),
                  ],
                ),
              ),

              // Status badge
              _StatusBadge(keySet: keySet),
              const SizedBox(width: 12),

              // Action buttons
              if (keySet) ...[
                _IconBtn(
                  icon: showKey ? Icons.visibility_off_outlined : Icons.visibility_outlined,
                  tooltip: showKey ? 'Hide key' : 'Show key',
                  onTap: onToggleShow,
                ),
                const SizedBox(width: 4),
                _IconBtn(
                  icon: editing ? Icons.edit_off_outlined : Icons.edit_outlined,
                  tooltip: editing ? 'Cancel update' : 'Update key',
                  onTap: onToggleEdit,
                ),
                const SizedBox(width: 4),
                _IconBtn(
                  icon: Icons.delete_outline,
                  tooltip: 'Remove key',
                  onTap: deleting ? () {} : onDelete,
                  color: AppColors.error,
                ),
              ],
            ],
          ),

          // ── Description ──────────────────────────────────────────────────
          const SizedBox(height: 8),
          Text(
            provider.description,
            style: const TextStyle(
              color: AppColors.textSecondary,
              fontSize: 12,
              height: 1.5,
            ),
          ),

          // ── Key entry / masked display ────────────────────────────────────
          if (!keySet || editing) ...[
            const SizedBox(height: 14),
            Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: controller,
                    obscureText: true,
                    style: const TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 12,
                      fontFamily: 'monospace',
                    ),
                    decoration: InputDecoration(
                      hintText: keySet ? 'Enter new key to replace...' : provider.hintText,
                      hintStyle: TextStyle(
                        color: AppColors.textMuted.withOpacity(0.5),
                        fontSize: 11,
                        fontFamily: 'monospace',
                      ),
                      filled: true,
                      fillColor: AppColors.primary,
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
                        borderSide: const BorderSide(color: AppColors.accent, width: 1.5),
                      ),
                      contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                    ),
                  ),
                ),
                const SizedBox(width: 10),
                SizedBox(
                  height: 40,
                  child: ElevatedButton(
                    onPressed: saving ? null : onSave,
                    style: ElevatedButton.styleFrom(
                      backgroundColor: AppColors.accent,
                      foregroundColor: AppColors.primary,
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                      padding: const EdgeInsets.symmetric(horizontal: 18),
                    ),
                    child: saving
                        ? const SizedBox(
                            width: 14, height: 14,
                            child: CircularProgressIndicator(strokeWidth: 2, color: AppColors.primary),
                          )
                        : const Text(
                            'Save',
                            style: TextStyle(fontSize: 12, fontWeight: FontWeight.w600),
                          ),
                  ),
                ),
              ],
            ),
          ] else if (keySet && showKey) ...[
            // Masked key reveal (read-only display)
            const SizedBox(height: 10),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
              decoration: BoxDecoration(
                color: AppColors.surfaceVariant,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: AppColors.border),
              ),
              child: Row(
                children: [
                  const Icon(Icons.key, size: 13, color: AppColors.textMuted),
                  const SizedBox(width: 8),
                  Text(
                    '${provider.hintText.split('-').take(3).join('-')}-••••••••••••••••',
                    style: const TextStyle(
                      color: AppColors.textSecondary,
                      fontSize: 12,
                      fontFamily: 'monospace',
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
}

// ── Status badge ──────────────────────────────────────────────────────────────
class _StatusBadge extends StatelessWidget {
  final bool keySet;
  const _StatusBadge({required this.keySet});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: keySet
            ? AppColors.accent.withOpacity(0.12)
            : AppColors.textMuted.withOpacity(0.08),
        borderRadius: BorderRadius.circular(4),
        border: Border.all(
          color: keySet ? AppColors.accent.withOpacity(0.35) : AppColors.border,
        ),
      ),
      child: Text(
        keySet ? 'Key set' : 'No key',
        style: TextStyle(
          color: keySet ? AppColors.accent : AppColors.textMuted,
          fontSize: 10,
          fontWeight: FontWeight.w600,
          letterSpacing: 0.3,
        ),
      ),
    );
  }
}

// ── Icon button helper ────────────────────────────────────────────────────────
class _IconBtn extends StatelessWidget {
  final IconData icon;
  final String tooltip;
  final VoidCallback onTap;
  final Color? color;

  const _IconBtn({
    required this.icon,
    required this.tooltip,
    required this.onTap,
    this.color,
  });

  @override
  Widget build(BuildContext context) {
    return Tooltip(
      message: tooltip,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(6),
        child: Padding(
          padding: const EdgeInsets.all(6),
          child: Icon(icon, size: 16, color: color ?? AppColors.textMuted),
        ),
      ),
    );
  }
}
