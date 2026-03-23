import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:qr_flutter/qr_flutter.dart';
import '../../theme/mobile_theme.dart';
import '../../services/core_service.dart';
import '../../config/agent_config.dart';

// ignore_for_file: library_private_types_in_public_api

enum _CredFilter { all, received, issued, pending, expired }

class MobileCredentialsScreen extends StatefulWidget {
  final String? serverUrl;
  const MobileCredentialsScreen({super.key, this.serverUrl});

  @override
  State<MobileCredentialsScreen> createState() => _MobileCredentialsScreenState();
}

class _MobileCredentialsScreenState extends State<MobileCredentialsScreen> {
  late final CoreService _coreService;
  List<CredentialRecord> _all = [];
  bool _loading = true;
  String? _error;
  _CredFilter _filter = _CredFilter.all;

  @override
  void initState() {
    super.initState();
    _coreService = CoreService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);
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
      final creds = await _coreService.getCredentials();
      if (mounted) setState(() { _all = creds; _loading = false; });
    } catch (e) {
      if (mounted) setState(() { _error = e.toString(); _loading = false; });
    }
  }

  List<CredentialRecord> get _filtered {
    switch (_filter) {
      case _CredFilter.received:
        return _all.where((c) => c.status == 'received').toList();
      case _CredFilter.issued:
        return _all.where((c) => c.status == 'issued').toList();
      case _CredFilter.pending:
        return _all.where((c) => c.status == 'pending_inbound').toList();
      case _CredFilter.expired:
        return _all.where((c) => c.isExpired).toList();
      case _CredFilter.all:
        return _all;
    }
  }

  // ── Accept / Reject pending credentials ────────────────────────────────────

  Future<void> _accept(CredentialRecord cred) async {
    try {
      await _coreService.acceptCredential(cred.said);
      await _load();
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('Credential accepted')),
        );
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed: $e'), backgroundColor: MobileColors.error),
        );
      }
    }
  }

  Future<void> _reject(CredentialRecord cred) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Reject Credential'),
        content: const Text('Reject and delete this incoming credential?'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: TextButton.styleFrom(foregroundColor: MobileColors.error),
            child: const Text('Reject'),
          ),
        ],
      ),
    );
    if (confirm != true) return;
    try {
      await _coreService.rejectCredential(cred.said);
      await _load();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed: $e'), backgroundColor: MobileColors.error),
        );
      }
    }
  }

  Future<void> _delete(CredentialRecord cred) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Remove Credential'),
        content: const Text('Remove this credential from your wallet? The original is not revoked.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            style: TextButton.styleFrom(foregroundColor: MobileColors.error),
            child: const Text('Remove'),
          ),
        ],
      ),
    );
    if (confirm != true) return;
    try {
      await _coreService.deleteCredential(cred.said);
      await _load();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed: $e'), backgroundColor: MobileColors.error),
        );
      }
    }
  }

  // ── Issue ──────────────────────────────────────────────────────────────────

  Future<void> _showIssueDialog() async {
    List<BuiltinSchema> schemas = [];
    List<ContactResponse> contacts = [];
    try {
      final results = await Future.wait([
        _coreService.getBuiltinSchemas(),
        _coreService.getContacts().then((r) => r.contacts.where((c) => c.isAccepted).toList()),
      ]);
      schemas = results[0] as List<BuiltinSchema>;
      contacts = results[1] as List<ContactResponse>;
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to load: $e'), backgroundColor: MobileColors.error),
        );
      }
      return;
    }

    if (!mounted) return;
    await Navigator.of(context).push(
      MaterialPageRoute(
        builder: (_) => _MobileIssueScreen(
          schemas: schemas,
          contacts: contacts,
          coreService: _coreService,
          onIssued: _load,
        ),
        fullscreenDialog: true,
      ),
    );
  }

  // ── Receive ─────────────────────────────────────────────────────────────────

  Future<void> _showReceiveDialog() async {
    final ctrl = TextEditingController();
    await showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      backgroundColor: MobileColors.surface,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      builder: (ctx) {
        String? error;
        bool fetching = false;
        return StatefulBuilder(
          builder: (ctx, setSheet) => Padding(
            padding: EdgeInsets.fromLTRB(20, 20, 20, MediaQuery.of(ctx).viewInsets.bottom + 20),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text('Receive Credential',
                    style: TextStyle(fontSize: 16, fontWeight: FontWeight.w700,
                        color: MobileColors.textPrimary)),
                const SizedBox(height: 4),
                const Text('Paste a delivery link or ACDC/W3C VC JSON.',
                    style: TextStyle(fontSize: 13, color: MobileColors.textSecondary)),
                const SizedBox(height: 12),
                TextField(
                  controller: ctrl,
                  maxLines: 5,
                  style: const TextStyle(fontSize: 12, fontFamily: 'monospace',
                      color: MobileColors.textPrimary),
                  decoration: InputDecoration(
                    filled: true,
                    fillColor: MobileColors.surfaceSecondary,
                    border: OutlineInputBorder(borderRadius: BorderRadius.circular(8),
                        borderSide: const BorderSide(color: MobileColors.border)),
                    enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(8),
                        borderSide: const BorderSide(color: MobileColors.border)),
                    hintText: 'https://… or { "v": "ACDC10JSON…" }',
                    hintStyle: const TextStyle(color: MobileColors.textMuted, fontSize: 11),
                    contentPadding: const EdgeInsets.all(12),
                  ),
                ),
                if (error != null) ...[
                  const SizedBox(height: 8),
                  Text(error!, style: const TextStyle(color: MobileColors.error, fontSize: 12)),
                ],
                const SizedBox(height: 16),
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton(
                    style: ElevatedButton.styleFrom(
                      backgroundColor: MobileColors.primary,
                      foregroundColor: MobileColors.textOnPrimary,
                      padding: const EdgeInsets.symmetric(vertical: 14),
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                    ),
                    onPressed: fetching ? null : () async {
                      final input = ctrl.text.trim();
                      if (input.isEmpty) {
                        setSheet(() => error = 'Paste a link or JSON first');
                        return;
                      }
                      if (input.startsWith('http://') || input.startsWith('https://')) {
                        setSheet(() { fetching = true; error = null; });
                        try {
                          final data = await _coreService.fetchPublicCredential(input);
                          if (ctx.mounted) Navigator.pop(ctx);
                          if (mounted) await _showAcceptDialog(data);
                        } catch (e) {
                          setSheet(() { fetching = false; error = e.toString().replaceFirst('Exception: ', ''); });
                        }
                      } else {
                        try {
                          await _coreService.receiveCredential(acdcJson: input, format: _detectFormat(input));
                          if (ctx.mounted) Navigator.pop(ctx);
                          await _load();
                        } catch (e) {
                          setSheet(() => error = e.toString().replaceFirst('Exception: ', ''));
                        }
                      }
                    },
                    child: fetching
                        ? const SizedBox(width: 18, height: 18,
                            child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                        : const Text('Receive', style: TextStyle(fontWeight: FontWeight.w600)),
                  ),
                ),
              ],
            ),
          ),
        );
      },
    );
    ctrl.dispose();
  }

  String _detectFormat(String json) {
    try {
      final decoded = jsonDecode(json);
      if (decoded is Map) {
        if (decoded.containsKey('v') && (decoded['v'] as String? ?? '').startsWith('ACDC')) return 'acdc';
        if (decoded.containsKey('@context')) return 'w3c_vc';
      }
    } catch (_) {}
    return 'acdc';
  }

  Future<void> _showAcceptDialog(Map<String, dynamic> data) async {
    final acdcJson = data['acdc_json'] as String? ?? '';
    final format = data['format'] as String? ?? 'acdc';
    final credType = data['credential_type'] as String? ?? 'Credential';
    final issuerName = data['issuer_name'] as String? ?? '';
    final issuerAid = data['issuer_aid'] as String? ?? '';
    final said = data['said'] as String? ?? '';

    Map<String, dynamic>? claims;
    try {
      final parsed = jsonDecode(acdcJson) as Map<String, dynamic>;
      claims = parsed['a'] as Map<String, dynamic>?;
    } catch (_) {}

    await showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      backgroundColor: MobileColors.surface,
      shape: const RoundedRectangleBorder(borderRadius: BorderRadius.vertical(top: Radius.circular(16))),
      builder: (ctx) {
        bool accepting = false;
        String? acceptError;
        return StatefulBuilder(
          builder: (ctx, setSheet) => SingleChildScrollView(
            padding: EdgeInsets.fromLTRB(20, 20, 20, MediaQuery.of(ctx).viewInsets.bottom + 20),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(children: [
                  const Icon(Icons.verified_outlined, color: MobileColors.success, size: 18),
                  const SizedBox(width: 8),
                  const Text('Accept Credential',
                      style: TextStyle(fontSize: 16, fontWeight: FontWeight.w700,
                          color: MobileColors.textPrimary)),
                ]),
                const SizedBox(height: 12),
                Container(
                  padding: const EdgeInsets.all(14),
                  decoration: BoxDecoration(
                    color: MobileColors.surfaceSecondary,
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: MobileColors.border),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(credType,
                          style: const TextStyle(fontSize: 15, fontWeight: FontWeight.w700,
                              color: MobileColors.textPrimary)),
                      const SizedBox(height: 2),
                      Text('from ${issuerName.isNotEmpty ? issuerName
                          : (issuerAid.length > 20 ? '${issuerAid.substring(0, 16)}…' : issuerAid)}',
                          style: const TextStyle(fontSize: 12, color: MobileColors.textMuted)),
                      if (claims != null && claims.isNotEmpty) ...[
                        const SizedBox(height: 10),
                        const Divider(color: MobileColors.border, height: 1),
                        const SizedBox(height: 10),
                        ...claims.entries
                            .where((e) => e.key != 'd' && e.key != 'i')
                            .take(5)
                            .map((e) => Padding(
                              padding: const EdgeInsets.only(bottom: 4),
                              child: Row(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  SizedBox(
                                    width: 100,
                                    child: Text(e.key.replaceAll('_', ' '),
                                        style: const TextStyle(fontSize: 11,
                                            color: MobileColors.textMuted)),
                                  ),
                                  Expanded(child: Text(e.value?.toString() ?? '',
                                      style: const TextStyle(fontSize: 11,
                                          color: MobileColors.textPrimary))),
                                ],
                              ),
                            )),
                      ],
                      if (said.isNotEmpty) ...[
                        const SizedBox(height: 6),
                        Text('SAID: ${said.length > 20 ? '${said.substring(0, 16)}…' : said}',
                            style: const TextStyle(fontSize: 9, color: MobileColors.textMuted,
                                fontFamily: 'monospace')),
                      ],
                    ],
                  ),
                ),
                if (acceptError != null) ...[
                  const SizedBox(height: 8),
                  Text(acceptError!, style: const TextStyle(color: MobileColors.error, fontSize: 12)),
                ],
                const SizedBox(height: 16),
                Row(
                  children: [
                    Expanded(
                      child: OutlinedButton(
                        onPressed: () => Navigator.pop(ctx),
                        style: OutlinedButton.styleFrom(
                          foregroundColor: MobileColors.textSecondary,
                          side: const BorderSide(color: MobileColors.border),
                          padding: const EdgeInsets.symmetric(vertical: 13),
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                        ),
                        child: const Text('Decline'),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: ElevatedButton(
                        style: ElevatedButton.styleFrom(
                          backgroundColor: MobileColors.success,
                          foregroundColor: MobileColors.textOnPrimary,
                          padding: const EdgeInsets.symmetric(vertical: 13),
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                        ),
                        onPressed: accepting ? null : () async {
                          setSheet(() { accepting = true; acceptError = null; });
                          try {
                            await _coreService.receiveCredential(acdcJson: acdcJson, format: format);
                            if (ctx.mounted) Navigator.pop(ctx);
                            await _load();
                          } catch (e) {
                            setSheet(() {
                              accepting = false;
                              acceptError = e.toString().replaceFirst('Exception: ', '');
                            });
                          }
                        },
                        child: accepting
                            ? const SizedBox(width: 16, height: 16,
                                child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                            : const Text('Accept', style: TextStyle(fontWeight: FontWeight.w600)),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        );
      },
    );
  }

  // ── Build ──────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: MobileColors.background,
      appBar: AppBar(
        backgroundColor: MobileColors.surface,
        elevation: 0,
        leading: IconButton(
          icon: const Icon(Icons.arrow_back, color: MobileColors.textPrimary),
          onPressed: () => Navigator.of(context).pop(),
        ),
        title: const Text('Credentials',
            style: TextStyle(fontSize: 18, fontWeight: FontWeight.w700,
                color: MobileColors.textPrimary)),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh, color: MobileColors.textSecondary),
            onPressed: _load,
          ),
        ],
      ),
      body: Column(
        children: [
          _buildFilterBar(),
          Expanded(child: _buildBody()),
        ],
      ),
      floatingActionButton: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.end,
        children: [
          FloatingActionButton.extended(
            heroTag: 'mobile_fab_issue',
            onPressed: _showIssueDialog,
            backgroundColor: MobileColors.success,
            foregroundColor: MobileColors.textOnPrimary,
            icon: const Icon(Icons.send_outlined, size: 18),
            label: const Text('Issue', style: TextStyle(fontSize: 13)),
          ),
          const SizedBox(height: 10),
          FloatingActionButton.extended(
            heroTag: 'mobile_fab_receive',
            onPressed: _showReceiveDialog,
            backgroundColor: MobileColors.primary,
            foregroundColor: MobileColors.textOnPrimary,
            icon: const Icon(Icons.download_outlined, size: 18),
            label: const Text('Receive', style: TextStyle(fontSize: 13)),
          ),
        ],
      ),
    );
  }

  Widget _buildFilterBar() {
    return SingleChildScrollView(
      scrollDirection: Axis.horizontal,
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
      child: Row(
        children: _CredFilter.values.map((f) {
          final label = switch (f) {
            _CredFilter.all      => 'All',
            _CredFilter.received => 'Received',
            _CredFilter.issued   => 'Issued',
            _CredFilter.pending  => 'Pending',
            _CredFilter.expired  => 'Expired',
          };
          final isActive = _filter == f;
          return Padding(
            padding: const EdgeInsets.only(right: 8),
            child: GestureDetector(
              onTap: () => setState(() => _filter = f),
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
                decoration: BoxDecoration(
                  color: isActive ? MobileColors.primary : MobileColors.surface,
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(color: isActive ? MobileColors.primary : MobileColors.border),
                ),
                child: Text(label,
                    style: TextStyle(
                      fontSize: 12,
                      fontWeight: isActive ? FontWeight.w600 : FontWeight.w400,
                      color: isActive ? MobileColors.textOnPrimary : MobileColors.textSecondary,
                    )),
              ),
            ),
          );
        }).toList(),
      ),
    );
  }

  Widget _buildBody() {
    if (_loading) {
      return const Center(child: CircularProgressIndicator(color: MobileColors.primary));
    }
    if (_error != null) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.error_outline, size: 40, color: MobileColors.error),
            const SizedBox(height: 12),
            const Text('Failed to load credentials',
                style: TextStyle(color: MobileColors.textPrimary, fontSize: 15)),
            const SizedBox(height: 4),
            Text(_error!, style: const TextStyle(color: MobileColors.textMuted, fontSize: 12),
                textAlign: TextAlign.center),
            const SizedBox(height: 16),
            ElevatedButton(onPressed: _load,
                style: ElevatedButton.styleFrom(backgroundColor: MobileColors.primary,
                    foregroundColor: MobileColors.textOnPrimary),
                child: const Text('Retry')),
          ],
        ),
      );
    }

    final list = _filtered;
    if (list.isEmpty) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.verified_user_outlined, size: 56, color: MobileColors.border),
            const SizedBox(height: 16),
            Text(
              _filter == _CredFilter.all ? 'No credentials yet' : 'No ${_filter.name} credentials',
              style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w500,
                  color: MobileColors.textSecondary),
            ),
            const SizedBox(height: 8),
            Text(
              _filter == _CredFilter.all
                  ? 'Tap "Receive" to import a credential, or issue one to a contact.'
                  : 'Change the filter above to see all credentials.',
              style: const TextStyle(fontSize: 13, color: MobileColors.textMuted),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 100),
          ],
        ),
      );
    }

    return ListView.separated(
      padding: const EdgeInsets.fromLTRB(16, 8, 16, 100),
      itemCount: list.length,
      separatorBuilder: (_, __) => const SizedBox(height: 8),
      itemBuilder: (_, i) => _MobileCredentialCard(
        cred: list[i],
        onAccept: list[i].status == 'pending_inbound' ? () => _accept(list[i]) : null,
        onReject: list[i].status == 'pending_inbound' ? () => _reject(list[i]) : null,
        onDelete: list[i].status != 'pending_inbound' ? () => _delete(list[i]) : null,
      ),
    );
  }
}

// ── Mobile credential card ────────────────────────────────────────────────────

class _MobileCredentialCard extends StatelessWidget {
  final CredentialRecord cred;
  final VoidCallback? onAccept;
  final VoidCallback? onReject;
  final VoidCallback? onDelete;

  const _MobileCredentialCard({
    required this.cred,
    this.onAccept,
    this.onReject,
    this.onDelete,
  });

  @override
  Widget build(BuildContext context) {
    final isPending = cred.status == 'pending_inbound';
    final issuerDisplay = cred.issuerName.isNotEmpty ? cred.issuerName
        : (cred.issuerAid.length > 16 ? '${cred.issuerAid.substring(0, 12)}…' : cred.issuerAid);
    final typeDisplay = cred.credentialType.isNotEmpty ? cred.credentialType : 'Credential';

    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: MobileColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
          color: isPending ? MobileColors.success.withOpacity(0.4) : MobileColors.border,
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              _CredAvatar(name: issuerDisplay),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(typeDisplay,
                        style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w600,
                            color: MobileColors.textPrimary),
                        maxLines: 1, overflow: TextOverflow.ellipsis),
                    Text(issuerDisplay,
                        style: const TextStyle(fontSize: 12, color: MobileColors.textMuted),
                        maxLines: 1, overflow: TextOverflow.ellipsis),
                  ],
                ),
              ),
              _statusChip(cred.status),
            ],
          ),
          if (cred.primaryClaim.isNotEmpty) ...[
            const SizedBox(height: 8),
            Text(cred.primaryClaim,
                style: const TextStyle(fontSize: 13, color: MobileColors.textSecondary),
                maxLines: 2, overflow: TextOverflow.ellipsis),
          ],
          if (cred.expiryDate.isNotEmpty) ...[
            const SizedBox(height: 6),
            Row(children: [
              Icon(Icons.schedule, size: 12,
                  color: cred.isExpired ? MobileColors.error : MobileColors.textMuted),
              const SizedBox(width: 4),
              Text(cred.isExpired ? 'Expired' : 'Expires ${cred.expiryDate}',
                  style: TextStyle(fontSize: 11,
                      color: cred.isExpired ? MobileColors.error : MobileColors.textMuted)),
            ]),
          ],
          if (isPending) ...[
            const SizedBox(height: 10),
            const Divider(color: MobileColors.border, height: 1),
            const SizedBox(height: 10),
            Row(
              children: [
                Expanded(
                  child: OutlinedButton(
                    onPressed: onReject,
                    style: OutlinedButton.styleFrom(
                      foregroundColor: MobileColors.error,
                      side: const BorderSide(color: MobileColors.error),
                      padding: const EdgeInsets.symmetric(vertical: 8),
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                    ),
                    child: const Text('Reject', style: TextStyle(fontSize: 13)),
                  ),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: ElevatedButton(
                    onPressed: onAccept,
                    style: ElevatedButton.styleFrom(
                      backgroundColor: MobileColors.success,
                      foregroundColor: MobileColors.textOnPrimary,
                      padding: const EdgeInsets.symmetric(vertical: 8),
                      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                    ),
                    child: const Text('Accept', style: TextStyle(fontSize: 13)),
                  ),
                ),
              ],
            ),
          ] else if (onDelete != null) ...[
            const SizedBox(height: 8),
            Align(
              alignment: Alignment.centerRight,
              child: GestureDetector(
                onTap: onDelete,
                child: const Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(Icons.delete_outline, size: 14, color: MobileColors.textMuted),
                    SizedBox(width: 4),
                    Text('Remove', style: TextStyle(fontSize: 11, color: MobileColors.textMuted)),
                  ],
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _statusChip(String status) {
    final Color color = switch (status) {
      'issued'          => MobileColors.primary,
      'received'        => MobileColors.success,
      'pending_inbound' => MobileColors.warning,
      'revoked'         => MobileColors.error,
      _                 => MobileColors.textMuted,
    };
    final String label = switch (status) {
      'pending_inbound' => 'Pending',
      _                 => status,
    };
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: color.withOpacity(0.1),
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(label,
          style: TextStyle(fontSize: 10, fontWeight: FontWeight.w600, color: color)),
    );
  }
}

class _CredAvatar extends StatelessWidget {
  final String name;
  const _CredAvatar({required this.name});

  @override
  Widget build(BuildContext context) {
    const colors = [
      Color(0xFF4589FF), Color(0xFF24A148), Color(0xFFFF832B),
      Color(0xFF8A3FFC), Color(0xFF007D79), Color(0xFFDA1E28),
    ];
    final letter = name.isNotEmpty ? name[0].toUpperCase() : '?';
    final color = colors[name.codeUnitAt(0) % colors.length];
    return Container(
      width: 40, height: 40,
      decoration: BoxDecoration(
        color: color.withOpacity(0.12),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: color.withOpacity(0.3)),
      ),
      child: Center(
        child: Text(letter,
            style: TextStyle(fontSize: 16, fontWeight: FontWeight.w700, color: color)),
      ),
    );
  }
}

// ── Mobile issue screen (full-screen wizard) ──────────────────────────────────

class _MobileIssueScreen extends StatefulWidget {
  final List<BuiltinSchema> schemas;
  final List<ContactResponse> contacts;
  final CoreService coreService;
  final VoidCallback onIssued;

  const _MobileIssueScreen({
    required this.schemas,
    required this.contacts,
    required this.coreService,
    required this.onIssued,
  });

  @override
  State<_MobileIssueScreen> createState() => _MobileIssueScreenState();
}

class _MobileIssueScreenState extends State<_MobileIssueScreen> {
  int _step = 0;
  BuiltinSchema? _schema;
  ContactResponse? _contact;
  final Map<String, TextEditingController> _controllers = {};
  final Map<String, bool> _boolValues = {};
  bool _issuing = false;
  String? _error;
  String? _deliveryUrl;
  bool _deliveryUrlCopied = false;

  @override
  void dispose() {
    for (final c in _controllers.values) c.dispose();
    super.dispose();
  }

  void _selectSchema(BuiltinSchema schema) {
    _controllers.clear();
    _boolValues.clear();
    for (final f in schema.fields) {
      if (f.key == 'd' || f.key == 'i') continue;
      if (f.type == 'boolean') {
        _boolValues[f.key] = false;
      } else {
        _controllers[f.key] = TextEditingController();
      }
    }
    setState(() { _schema = schema; _step = 1; });
  }

  Future<void> _issue() async {
    if (_contact == null || _schema == null) return;
    setState(() { _issuing = true; _error = null; });

    final claims = <String, String>{};
    for (final f in _schema!.fields) {
      if (f.key == 'd' || f.key == 'i') continue;
      if (f.type == 'boolean') {
        claims[f.key] = (_boolValues[f.key] ?? false).toString();
      } else {
        final val = _controllers[f.key]?.text.trim() ?? '';
        if (val.isNotEmpty) claims[f.key] = val;
      }
    }

    try {
      final results = await Future.wait([
        widget.coreService.issueCredential(
          schemaSaid: _schema!.said,
          holderAid: _contact!.aid,
          claims: claims,
        ),
        widget.coreService.getOobi(),
      ]);
      final result = results[0] as Map<String, dynamic>;
      final oobi = results[1] as OobiResponse;
      final said = result['acdc_said'] as String? ?? '';
      final base = oobi.endpointUrl.isNotEmpty ? oobi.endpointUrl : oobi.baseUrl;
      final baseClean = base.endsWith('/') ? base.substring(0, base.length - 1) : base;
      setState(() {
        _issuing = false;
        _deliveryUrl = said.isNotEmpty ? '$baseClean/public/credential/$said' : null;
        _step = 3;
      });
    } catch (e) {
      setState(() { _issuing = false; _error = e.toString().replaceFirst('Exception: ', ''); });
    }
  }

  @override
  Widget build(BuildContext context) {
    final titles = ['Choose Type', 'Fill Details', 'Choose Recipient', 'Issued!'];
    return Scaffold(
      backgroundColor: MobileColors.background,
      appBar: AppBar(
        backgroundColor: MobileColors.surface,
        elevation: 0,
        leading: _step == 0 || _step == 3
            ? IconButton(
                icon: const Icon(Icons.close, color: MobileColors.textPrimary),
                onPressed: () {
                  if (_step == 3) widget.onIssued();
                  Navigator.of(context).pop();
                },
              )
            : IconButton(
                icon: const Icon(Icons.arrow_back, color: MobileColors.textPrimary),
                onPressed: () => setState(() { _step -= 1; _error = null; }),
              ),
        title: Text(titles[_step.clamp(0, 3)],
            style: const TextStyle(fontSize: 17, fontWeight: FontWeight.w700,
                color: MobileColors.textPrimary)),
      ),
      body: _buildStep(),
      bottomNavigationBar: _step < 3 && _step > 0
          ? SafeArea(
              child: Padding(
                padding: const EdgeInsets.fromLTRB(16, 8, 16, 8),
                child: ElevatedButton(
                  style: ElevatedButton.styleFrom(
                    backgroundColor: _step == 2 ? MobileColors.success : MobileColors.primary,
                    foregroundColor: MobileColors.textOnPrimary,
                    minimumSize: const Size(double.infinity, 50),
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                  ),
                  onPressed: (_issuing || (_step == 2 && _contact == null)) ? null : () {
                    if (_step == 1) setState(() { _step = 2; _error = null; });
                    else if (_step == 2) _issue();
                  },
                  child: _issuing
                      ? const SizedBox(width: 20, height: 20,
                          child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                      : Text(_step == 2 ? 'Issue Credential' : 'Next',
                          style: const TextStyle(fontSize: 15, fontWeight: FontWeight.w600)),
                ),
              ),
            )
          : null,
    );
  }

  Widget _buildStep() {
    switch (_step) {
      case 0:
        return _buildSchemaPicker();
      case 1:
        return _buildClaimsForm();
      case 2:
        return _buildContactPicker();
      case 3:
        return _buildSuccess();
      default:
        return const SizedBox.shrink();
    }
  }

  Widget _buildSchemaPicker() {
    if (widget.schemas.isEmpty) {
      return const Center(child: Text('No schemas available', style: TextStyle(color: MobileColors.textMuted)));
    }
    return ListView.separated(
      padding: const EdgeInsets.all(16),
      itemCount: widget.schemas.length,
      separatorBuilder: (_, __) => const SizedBox(height: 8),
      itemBuilder: (_, i) {
        final s = widget.schemas[i];
        return GestureDetector(
          onTap: () => _selectSchema(s),
          child: Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: MobileColors.surface,
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: MobileColors.border),
            ),
            child: Row(
              children: [
                Expanded(child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(s.name, style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w600,
                        color: MobileColors.textPrimary)),
                    const SizedBox(height: 2),
                    Text(s.description, style: const TextStyle(fontSize: 12, color: MobileColors.textMuted),
                        maxLines: 2, overflow: TextOverflow.ellipsis),
                  ],
                )),
                const Icon(Icons.chevron_right, color: MobileColors.textMuted),
              ],
            ),
          ),
        );
      },
    );
  }

  Widget _buildClaimsForm() {
    if (_schema == null) return const SizedBox.shrink();
    final fields = _schema!.fields.where((f) => f.key != 'd' && f.key != 'i').toList();
    return SingleChildScrollView(
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 80),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: MobileColors.primary.withOpacity(0.06),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Row(
              children: [
                const Icon(Icons.info_outline, size: 14, color: MobileColors.primary),
                const SizedBox(width: 8),
                Expanded(child: Text(_schema!.description,
                    style: const TextStyle(fontSize: 12, color: MobileColors.textSecondary))),
              ],
            ),
          ),
          const SizedBox(height: 14),
          if (_error != null) ...[
            Text(_error!, style: const TextStyle(color: MobileColors.error, fontSize: 12)),
            const SizedBox(height: 8),
          ],
          ...fields.map((f) => Padding(
            padding: const EdgeInsets.only(bottom: 12),
            child: f.type == 'boolean'
                ? Row(children: [
                    Checkbox(
                      value: _boolValues[f.key] ?? false,
                      onChanged: (v) => setState(() => _boolValues[f.key] = v ?? false),
                      activeColor: MobileColors.primary,
                    ),
                    Text(f.label + (f.required ? ' *' : ''),
                        style: const TextStyle(fontSize: 14, color: MobileColors.textPrimary)),
                  ])
                : TextField(
                    controller: _controllers[f.key],
                    style: const TextStyle(fontSize: 14, color: MobileColors.textPrimary),
                    decoration: InputDecoration(
                      labelText: f.label + (f.required ? ' *' : ''),
                      labelStyle: const TextStyle(fontSize: 13, color: MobileColors.textSecondary),
                      hintText: f.placeholder.isNotEmpty ? f.placeholder : null,
                      hintStyle: const TextStyle(fontSize: 12, color: MobileColors.textMuted),
                      filled: true, fillColor: MobileColors.surface,
                      border: OutlineInputBorder(borderRadius: BorderRadius.circular(8),
                          borderSide: const BorderSide(color: MobileColors.border)),
                      enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(8),
                          borderSide: const BorderSide(color: MobileColors.border)),
                      contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
                    ),
                  ),
          )),
        ],
      ),
    );
  }

  Widget _buildContactPicker() {
    if (widget.contacts.isEmpty) {
      return const Center(
        child: Padding(
          padding: EdgeInsets.all(24),
          child: Text('No accepted contacts. Add contacts first to issue credentials.',
              style: TextStyle(color: MobileColors.textMuted, fontSize: 14),
              textAlign: TextAlign.center),
        ),
      );
    }
    return ListView.separated(
      padding: const EdgeInsets.fromLTRB(16, 16, 16, 80),
      itemCount: widget.contacts.length,
      separatorBuilder: (_, __) => const SizedBox(height: 8),
      itemBuilder: (_, i) {
        final c = widget.contacts[i];
        final isSelected = _contact?.aid == c.aid;
        return GestureDetector(
          onTap: () => setState(() => _contact = c),
          child: Container(
            padding: const EdgeInsets.all(14),
            decoration: BoxDecoration(
              color: isSelected ? MobileColors.primary.withOpacity(0.06) : MobileColors.surface,
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: isSelected ? MobileColors.primary : MobileColors.border),
            ),
            child: Row(
              children: [
                _CredAvatar(name: c.alias.isNotEmpty ? c.alias : c.aid),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(c.alias.isNotEmpty ? c.alias : 'Unknown',
                          style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w500,
                              color: MobileColors.textPrimary)),
                      Text(c.aid.length > 28 ? '${c.aid.substring(0, 24)}…' : c.aid,
                          style: const TextStyle(fontSize: 11, color: MobileColors.textMuted,
                              fontFamily: 'monospace')),
                    ],
                  ),
                ),
                if (isSelected) const Icon(Icons.check_circle, size: 20, color: MobileColors.primary),
              ],
            ),
          ),
        );
      },
    );
  }

  Widget _buildSuccess() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const SizedBox(height: 20),
          const Icon(Icons.check_circle_outline, size: 64, color: MobileColors.success),
          const SizedBox(height: 16),
          Text('Credential issued to ${_contact?.alias ?? _contact?.aid ?? "holder"}',
              style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w600,
                  color: MobileColors.textPrimary),
              textAlign: TextAlign.center),
          const SizedBox(height: 8),
          const Text('Signed and anchored to your Key Event Log.',
              style: TextStyle(fontSize: 13, color: MobileColors.textMuted),
              textAlign: TextAlign.center),
          if (_deliveryUrl != null) ...[
            const SizedBox(height: 24),
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: MobileColors.surface,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: MobileColors.border),
              ),
              child: Column(
                children: [
                  const Row(
                    children: [
                      Icon(Icons.link, size: 14, color: MobileColors.primary),
                      SizedBox(width: 6),
                      Text('DELIVERY LINK',
                          style: TextStyle(fontSize: 10, fontWeight: FontWeight.w700,
                              color: MobileColors.primary, letterSpacing: 0.8)),
                    ],
                  ),
                  const SizedBox(height: 8),
                  Text(_deliveryUrl!,
                      style: const TextStyle(fontSize: 10, color: MobileColors.textSecondary,
                          fontFamily: 'monospace'),
                      maxLines: 3, overflow: TextOverflow.ellipsis),
                  const SizedBox(height: 10),
                  OutlinedButton.icon(
                    onPressed: () {
                      Clipboard.setData(ClipboardData(text: _deliveryUrl!));
                      setState(() => _deliveryUrlCopied = true);
                      Future.delayed(const Duration(seconds: 2), () {
                        if (mounted) setState(() => _deliveryUrlCopied = false);
                      });
                    },
                    icon: Icon(_deliveryUrlCopied ? Icons.check : Icons.copy, size: 14),
                    label: Text(_deliveryUrlCopied ? 'Copied!' : 'Copy Link',
                        style: const TextStyle(fontSize: 12)),
                    style: OutlinedButton.styleFrom(
                      foregroundColor: _deliveryUrlCopied ? MobileColors.success : MobileColors.textSecondary,
                      side: const BorderSide(color: MobileColors.border),
                    ),
                  ),
                  const SizedBox(height: 12),
                  QrImageView(
                    data: _deliveryUrl!,
                    version: QrVersions.auto,
                    size: 180,
                    backgroundColor: Colors.white,
                    padding: const EdgeInsets.all(6),
                  ),
                ],
              ),
            ),
          ],
          const SizedBox(height: 24),
          SizedBox(
            width: double.infinity,
            child: ElevatedButton(
              style: ElevatedButton.styleFrom(
                backgroundColor: MobileColors.primary,
                foregroundColor: MobileColors.textOnPrimary,
                minimumSize: const Size(double.infinity, 50),
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
              ),
              onPressed: () {
                widget.onIssued();
                Navigator.of(context).pop();
              },
              child: const Text('Done', style: TextStyle(fontSize: 15, fontWeight: FontWeight.w600)),
            ),
          ),
        ],
      ),
    );
  }
}
