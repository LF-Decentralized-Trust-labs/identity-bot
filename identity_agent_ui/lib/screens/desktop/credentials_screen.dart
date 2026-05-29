import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:qr_flutter/qr_flutter.dart';
import '../../theme/app_theme.dart';
import '../../services/core_service.dart';
import '../../config/agent_config.dart';

// ignore_for_file: library_private_types_in_public_api

/// Derive a human-readable credential type from schema SAID / ACDC JSON.
String _deriveTypeFromSchemaSaid(String schemaSaid, String decodedAcdc) {
  String schema = schemaSaid;
  if (schema.isEmpty && decodedAcdc.isNotEmpty) {
    try {
      schema = (Map<String, dynamic>.from(jsonDecode(decodedAcdc) as Map))['s']?.toString() ?? '';
    } catch (_) {}
  }
  if (schema.isEmpty) return 'Credential';
  // Schema SAIDs often look like "ESchoolPickupAuthorization__placeholder__v1"
  var name = schema;
  if (name.startsWith('E') && name.length > 1 && name[1] == name[1].toUpperCase()) {
    name = name.substring(1);
  }
  name = name.replaceAll(RegExp(r'__.*$'), '');
  name = name.replaceAll(RegExp(r'X+$'), '');
  name = name.replaceAllMapped(RegExp(r'([a-z])([A-Z])'), (m) => '${m.group(1)} ${m.group(2)}');
  name = name.replaceAll('_', ' ').trim();
  // Clean up common schema naming patterns
  name = name.replaceAll(RegExp(r'\s+'), ' ');
  return name.isEmpty ? 'Credential' : name;
}

// ── Filter tabs ───────────────────────────────────────────────────────────────

enum _CredFilter { all, received, issued, expired }

// ── Screen ────────────────────────────────────────────────────────────────────

class CredentialsScreen extends StatefulWidget {
  final String? serverUrl;
  const CredentialsScreen({super.key, this.serverUrl});

  @override
  State<CredentialsScreen> createState() => _CredentialsScreenState();
}

class _CredentialsScreenState extends State<CredentialsScreen> {
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
      case _CredFilter.expired:
        return _all.where((c) => c.isExpired).toList();
      case _CredFilter.all:
        return _all;
    }
  }

  // ── Issue dialog ───────────────────────────────────────────────────────────

  Future<void> _showIssueDialog() async {
    // Step 1: load schemas + contacts in parallel
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
          SnackBar(content: Text('Failed to load: $e'), backgroundColor: AppColors.error),
        );
      }
      return;
    }

    if (!mounted) return;

    await showDialog<void>(
      context: context,
      builder: (ctx) => _IssueCredentialDialog(
        schemas: schemas,
        contacts: contacts,
        coreService: _coreService,
        onIssued: () async {
          if (ctx.mounted) Navigator.pop(ctx);
          await _load();
        },
      ),
    );
  }

  // ── Receive dialog ─────────────────────────────────────────────────────────

  Future<void> _showReceiveDialog() async {
    final ctrl = TextEditingController();
    String? dialogError;
    bool fetching = false;

    await showDialog<void>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setDialogState) => AlertDialog(
          backgroundColor: AppColors.surface,
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
          title: const Text('Receive Credential',
              style: TextStyle(color: AppColors.textPrimary, fontSize: 16, fontWeight: FontWeight.w600)),
          content: SizedBox(
            width: 480,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Paste a credential delivery link or ACDC/W3C VC JSON.',
                    style: TextStyle(color: AppColors.textSecondary, fontSize: 13)),
                const SizedBox(height: 12),
                TextField(
                  controller: ctrl,
                  maxLines: 6,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 12, color: AppColors.textPrimary),
                  decoration: InputDecoration(
                    filled: true,
                    fillColor: AppColors.surfaceLight,
                    border: OutlineInputBorder(borderRadius: BorderRadius.circular(6),
                        borderSide: BorderSide(color: AppColors.border)),
                    enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(6),
                        borderSide: BorderSide(color: AppColors.border)),
                    hintText: 'https://… (delivery link)  or  { "v": "ACDC10JSON…", … }',
                    hintStyle: TextStyle(color: AppColors.textMuted, fontFamily: 'monospace', fontSize: 11),
                    contentPadding: const EdgeInsets.all(12),
                  ),
                ),
                if (dialogError != null) ...[
                  const SizedBox(height: 8),
                  Text(dialogError!, style: TextStyle(color: AppColors.error, fontSize: 12)),
                ],
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: Text('Cancel', style: TextStyle(color: AppColors.textSecondary)),
            ),
            ElevatedButton(
              style: ElevatedButton.styleFrom(
                backgroundColor: AppColors.primary,
                foregroundColor: Colors.white,
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
              ),
              onPressed: fetching ? null : () async {
                final input = ctrl.text.trim();
                if (input.isEmpty) {
                  setDialogState(() => dialogError = 'Paste a delivery link or credential JSON first');
                  return;
                }
                // Auto-detect: URL vs JSON
                if (input.startsWith('http://') || input.startsWith('https://')) {
                  setDialogState(() { fetching = true; dialogError = null; });
                  try {
                    final data = await _coreService.fetchPublicCredential(input);
                    if (ctx.mounted) Navigator.pop(ctx);
                    if (mounted) await _showCredentialAcceptDialog(data);
                  } catch (e) {
                    setDialogState(() {
                      fetching = false;
                      dialogError = e.toString().replaceFirst('Exception: ', '');
                    });
                  }
                } else {
                  final format = _detectFormat(input);
                  try {
                    await _coreService.receiveCredential(acdcJson: input, format: format);
                    if (ctx.mounted) Navigator.pop(ctx);
                    await _load();
                  } catch (e) {
                    setDialogState(() => dialogError = e.toString().replaceFirst('Exception: ', ''));
                  }
                }
              },
              child: fetching
                  ? const SizedBox(width: 16, height: 16,
                      child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                  : const Text('Receive'),
            ),
          ],
        ),
      ),
    );
    ctrl.dispose();
  }

  // ── Verify credential chain dialog ─────────────────────────────────────────

  Future<void> _showVerifyDialog({String? prefillSaid}) async {
    final ctrl = TextEditingController(text: prefillSaid ?? '');
    Map<String, dynamic>? result;
    bool verifying = false;
    String? dialogError;

    await showDialog<void>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setDialogState) {
          final chain = result == null ? null : (result!['chain'] as List<dynamic>? ?? []);
          final valid = result == null ? null : result!['valid'] as bool?;
          final warnings = result == null ? <dynamic>[] : (result!['warnings'] as List<dynamic>? ?? []);
          final errors = result == null ? <dynamic>[] : (result!['errors'] as List<dynamic>? ?? []);

          return AlertDialog(
            backgroundColor: AppColors.surface,
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
            title: const Text('Verify Credential',
                style: TextStyle(color: AppColors.textPrimary, fontSize: 16, fontWeight: FontWeight.w600)),
            content: SizedBox(
              width: 560,
              child: SingleChildScrollView(
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('Paste a credential SAID or ACDC JSON (base64) to verify its chain of trust.',
                        style: TextStyle(color: AppColors.textSecondary, fontSize: 13)),
                    const SizedBox(height: 12),
                    TextField(
                      controller: ctrl,
                      maxLines: 4,
                      style: const TextStyle(fontFamily: 'monospace', fontSize: 11, color: AppColors.textPrimary),
                      decoration: InputDecoration(
                        filled: true,
                        fillColor: AppColors.surfaceLight,
                        border: OutlineInputBorder(borderRadius: BorderRadius.circular(6),
                            borderSide: BorderSide(color: AppColors.border)),
                        enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(6),
                            borderSide: BorderSide(color: AppColors.border)),
                        hintText: 'SAID (E...) or base64 ACDC JSON',
                        hintStyle: TextStyle(color: AppColors.textMuted, fontFamily: 'monospace', fontSize: 11),
                        contentPadding: const EdgeInsets.all(12),
                      ),
                    ),
                    if (dialogError != null) ...[
                      const SizedBox(height: 8),
                      Text(dialogError!, style: TextStyle(color: AppColors.error, fontSize: 12)),
                    ],
                    if (result != null) ...[
                      const SizedBox(height: 16),
                      // Overall status banner
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                        decoration: BoxDecoration(
                          color: valid == true
                              ? AppColors.success.withOpacity(0.15)
                              : AppColors.error.withOpacity(0.15),
                          borderRadius: BorderRadius.circular(6),
                          border: Border.all(
                            color: valid == true ? AppColors.success : AppColors.error,
                          ),
                        ),
                        child: Row(
                          children: [
                            Icon(
                              valid == true ? Icons.verified : Icons.dangerous_outlined,
                              size: 16,
                              color: valid == true ? AppColors.success : AppColors.error,
                            ),
                            const SizedBox(width: 8),
                            Text(
                              valid == true ? 'Chain valid — all checks passed' : 'Verification failed',
                              style: TextStyle(
                                color: valid == true ? AppColors.success : AppColors.error,
                                fontWeight: FontWeight.w600, fontSize: 13,
                              ),
                            ),
                          ],
                        ),
                      ),
                      // Chain steps
                      if (chain != null && chain.isNotEmpty) ...[
                        const SizedBox(height: 12),
                        ...chain.asMap().entries.map((entry) {
                          final i = entry.key;
                          final step = entry.value as Map<String, dynamic>;
                          final stepValid = step['valid'] as bool? ?? false;
                          final stepSaid = step['said'] as String? ?? '';
                          final edgeLabel = step['edge_label'] as String? ?? '';
                          final stepErrors = (step['errors'] as List<dynamic>? ?? []).cast<String>();
                          final stepChecks = step['checks'] as Map<String, dynamic>?;

                          return Container(
                            margin: EdgeInsets.only(top: i == 0 ? 0 : 6),
                            padding: const EdgeInsets.all(10),
                            decoration: BoxDecoration(
                              color: AppColors.surfaceLight,
                              borderRadius: BorderRadius.circular(6),
                              border: Border.all(
                                color: stepValid ? AppColors.success.withOpacity(0.4) : AppColors.error.withOpacity(0.4),
                              ),
                            ),
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Row(
                                  children: [
                                    Icon(
                                      stepValid ? Icons.check_circle_outline : Icons.cancel_outlined,
                                      size: 14,
                                      color: stepValid ? AppColors.success : AppColors.error,
                                    ),
                                    const SizedBox(width: 6),
                                    Expanded(
                                      child: Text(
                                        i == 0
                                            ? 'Credential (top level)'
                                            : 'Parent: $edgeLabel',
                                        style: const TextStyle(
                                          color: AppColors.textPrimary,
                                          fontWeight: FontWeight.w600, fontSize: 12,
                                        ),
                                      ),
                                    ),
                                    Container(
                                      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                                      decoration: BoxDecoration(
                                        color: stepValid ? AppColors.success.withOpacity(0.2) : AppColors.error.withOpacity(0.2),
                                        borderRadius: BorderRadius.circular(4),
                                      ),
                                      child: Text(
                                        stepValid ? 'VALID' : 'FAILED',
                                        style: TextStyle(
                                          color: stepValid ? AppColors.success : AppColors.error,
                                          fontSize: 10, fontWeight: FontWeight.w700,
                                        ),
                                      ),
                                    ),
                                  ],
                                ),
                                if (stepSaid.isNotEmpty) ...[
                                  const SizedBox(height: 4),
                                  Text(
                                    stepSaid.length > 48 ? '${stepSaid.substring(0, 48)}…' : stepSaid,
                                    style: const TextStyle(
                                      fontFamily: 'monospace', fontSize: 10, color: AppColors.textMuted,
                                    ),
                                  ),
                                ],
                                if (stepChecks != null) ...[
                                  const SizedBox(height: 6),
                                  Wrap(
                                    spacing: 6, runSpacing: 4,
                                    children: stepChecks.entries.map((e) {
                                      final passed = e.value as bool? ?? false;
                                      return Container(
                                        padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
                                        decoration: BoxDecoration(
                                          color: passed
                                              ? AppColors.success.withOpacity(0.1)
                                              : AppColors.error.withOpacity(0.1),
                                          borderRadius: BorderRadius.circular(3),
                                        ),
                                        child: Text(
                                          e.key.replaceAll('_', ' '),
                                          style: TextStyle(
                                            fontSize: 9,
                                            color: passed ? AppColors.success : AppColors.error,
                                          ),
                                        ),
                                      );
                                    }).toList(),
                                  ),
                                ],
                                if (stepErrors.isNotEmpty) ...[
                                  const SizedBox(height: 6),
                                  ...stepErrors.take(3).map((e) => Text(
                                    '• $e',
                                    style: TextStyle(color: AppColors.error, fontSize: 10),
                                  )),
                                ],
                              ],
                            ),
                          );
                        }),
                      ],
                      // Warnings
                      if (warnings.isNotEmpty) ...[
                        const SizedBox(height: 8),
                        ...warnings.cast<String>().map((w) => Text(
                          '⚠ $w',
                          style: const TextStyle(color: Color(0xFFCC8800), fontSize: 11),
                        )),
                      ],
                    ],
                  ],
                ),
              ),
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(ctx),
                child: Text('Close', style: TextStyle(color: AppColors.textSecondary)),
              ),
              ElevatedButton(
                style: ElevatedButton.styleFrom(
                  backgroundColor: const Color(0xFF6A0DAD),
                  foregroundColor: Colors.white,
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
                ),
                onPressed: verifying ? null : () async {
                  final input = ctrl.text.trim();
                  if (input.isEmpty) {
                    setDialogState(() => dialogError = 'Paste a SAID or ACDC JSON first');
                    return;
                  }
                  setDialogState(() { verifying = true; dialogError = null; result = null; });
                  try {
                    // Detect input type: SAID starts with 'E', base64 JSON otherwise.
                    final res = input.startsWith('E') && !input.contains(' ') && !input.contains('{')
                        ? await _coreService.verifyCredentialChain(acdcSaid: input)
                        : await _coreService.verifyCredentialChain(acdcJsonB64: input);
                    setDialogState(() { verifying = false; result = res; });
                  } catch (e) {
                    setDialogState(() {
                      verifying = false;
                      dialogError = e.toString().replaceFirst('Exception: ', '');
                    });
                  }
                },
                child: verifying
                    ? const SizedBox(width: 16, height: 16,
                        child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                    : const Text('Verify'),
              ),
            ],
          );
        },
      ),
    );
    ctrl.dispose();
  }

  // ── Credential acceptance dialog (after fetching via delivery link) ─────────

  Future<void> _showCredentialAcceptDialog(Map<String, dynamic> data) async {
    final acdcJson = data['acdc_json'] as String? ?? '';
    final format = data['format'] as String? ?? 'acdc';
    final credType = data['credential_type'] as String? ?? 'Credential';
    final issuerName = data['issuer_name'] as String? ?? '';
    final issuerAid = data['issuer_aid'] as String? ?? '';
    final said = data['said'] as String? ?? '';

    // Try to parse claims from ACDC JSON
    Map<String, dynamic>? claims;
    try {
      final parsed = jsonDecode(acdcJson) as Map<String, dynamic>;
      claims = parsed['a'] as Map<String, dynamic>?;
    } catch (_) {}

    await showDialog<void>(
      context: context,
      builder: (ctx) {
        bool accepting = false;
        String? acceptError;
        return StatefulBuilder(
          builder: (ctx, setState) => AlertDialog(
            backgroundColor: AppColors.surface,
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
            title: Row(
              children: [
                const Icon(Icons.verified_outlined, size: 18, color: AppColors.success),
                const SizedBox(width: 8),
                const Text('Accept Credential',
                    style: TextStyle(color: AppColors.textPrimary, fontSize: 16, fontWeight: FontWeight.w600)),
              ],
            ),
            content: SizedBox(
              width: 440,
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text('You have been issued the following credential:',
                      style: TextStyle(color: AppColors.textSecondary, fontSize: 13)),
                  const SizedBox(height: 14),
                  Container(
                    padding: const EdgeInsets.all(14),
                    decoration: BoxDecoration(
                      color: AppColors.surfaceLight,
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: AppColors.border),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            _IssuerAvatar(name: issuerName.isNotEmpty ? issuerName : issuerAid, size: 32),
                            const SizedBox(width: 10),
                            Expanded(
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text(credType,
                                      style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w600,
                                          color: AppColors.textPrimary)),
                                  Text(issuerName.isNotEmpty ? issuerName
                                      : (issuerAid.length > 20 ? '${issuerAid.substring(0, 16)}…' : issuerAid),
                                      style: TextStyle(fontSize: 11, color: AppColors.textMuted)),
                                ],
                              ),
                            ),
                            _FormatBadge(format: format),
                          ],
                        ),
                        if (claims != null && claims.isNotEmpty) ...[
                          const SizedBox(height: 12),
                          const Divider(color: AppColors.border, height: 1),
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
                                      width: 110,
                                      child: Text(e.key.replaceAll('_', ' '),
                                          style: TextStyle(fontSize: 11, color: AppColors.textMuted)),
                                    ),
                                    Expanded(
                                      child: Text(e.value?.toString() ?? '',
                                          style: const TextStyle(fontSize: 11, color: AppColors.textPrimary)),
                                    ),
                                  ],
                                ),
                              )),
                        ],
                        if (said.isNotEmpty) ...[
                          const SizedBox(height: 8),
                          Text('SAID: ${said.length > 24 ? '${said.substring(0, 16)}…' : said}',
                              style: const TextStyle(fontSize: 10, color: AppColors.textMuted,
                                  fontFamily: 'monospace')),
                        ],
                      ],
                    ),
                  ),
                  if (acceptError != null) ...[
                    const SizedBox(height: 8),
                    Text(acceptError!, style: TextStyle(color: AppColors.error, fontSize: 12)),
                  ],
                ],
              ),
            ),
            actions: [
              TextButton(
                onPressed: () => Navigator.pop(ctx),
                child: Text('Decline', style: TextStyle(color: AppColors.textSecondary)),
              ),
              ElevatedButton(
                style: ElevatedButton.styleFrom(
                  backgroundColor: AppColors.success,
                  foregroundColor: Colors.white,
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
                ),
                onPressed: accepting ? null : () async {
                  setState(() { accepting = true; acceptError = null; });
                  try {
                    await _coreService.receiveCredential(acdcJson: acdcJson, format: format);
                    if (ctx.mounted) Navigator.pop(ctx);
                    await _load();
                  } catch (e) {
                    setState(() {
                      accepting = false;
                      acceptError = e.toString().replaceFirst('Exception: ', '');
                    });
                  }
                },
                child: accepting
                    ? const SizedBox(width: 16, height: 16,
                        child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                    : const Text('Accept'),
              ),
            ],
          ),
        );
      },
    );
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

  // ── Delete ─────────────────────────────────────────────────────────────────

  Future<void> _delete(CredentialRecord cred) async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: AppColors.surface,
        title: const Text('Remove Credential',
            style: TextStyle(color: AppColors.textPrimary, fontSize: 16, fontWeight: FontWeight.w600)),
        content: Text('Remove "${cred.credentialType.isNotEmpty ? cred.credentialType : cred.said.substring(0, 20)}..."?'
            '\n\nThis only removes it from your local wallet. The original credential is not revoked.',
            style: TextStyle(color: AppColors.textSecondary, fontSize: 13)),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false),
              child: Text('Cancel', style: TextStyle(color: AppColors.textSecondary))),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: AppColors.error, foregroundColor: Colors.white,
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6))),
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Remove'),
          ),
        ],
      ),
    );
    if (confirm != true) return;
    try {
      await _coreService.deleteCredential(cred.said);
      if (mounted) {
        setState(() {
          _all.remove(cred);
        });
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to remove: $e'), backgroundColor: AppColors.error),
        );
      }
    }
  }

  // ── Build ──────────────────────────────────────────────────────────────────

  @override
  bool get _isMobileLayout => AppLayout.isMobile(context);

  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.background,
      body: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          if (!_isMobileLayout) _buildHeader(),
          _buildFilterBar(),
          Expanded(child: _buildBody()),
        ],
      ),
      floatingActionButton: _isMobileLayout ? _buildMobileFab() : null,
    );
  }

  Widget _buildMobileFab() {
    return PopupMenuButton<String>(
      onSelected: (value) {
        switch (value) {
          case 'issue':
            _showIssueDialog();
            break;
          case 'receive':
            _showReceiveDialog();
            break;
          case 'verify':
            _showVerifyDialog();
            break;
          case 'refresh':
            _load();
            break;
        }
      },
      itemBuilder: (_) => [
        const PopupMenuItem(value: 'issue', child: ListTile(
          leading: Icon(Icons.send_outlined, color: AppColors.success, size: 20),
          title: Text('Issue', style: TextStyle(fontSize: 14)),
          dense: true, contentPadding: EdgeInsets.zero,
        )),
        const PopupMenuItem(value: 'receive', child: ListTile(
          leading: Icon(Icons.download_outlined, color: AppColors.primary, size: 20),
          title: Text('Receive', style: TextStyle(fontSize: 14)),
          dense: true, contentPadding: EdgeInsets.zero,
        )),
        const PopupMenuItem(value: 'verify', child: ListTile(
          leading: Icon(Icons.verified_outlined, color: Color(0xFF6A0DAD), size: 20),
          title: Text('Verify', style: TextStyle(fontSize: 14)),
          dense: true, contentPadding: EdgeInsets.zero,
        )),
        const PopupMenuDivider(),
        const PopupMenuItem(value: 'refresh', child: ListTile(
          leading: Icon(Icons.refresh, color: AppColors.textSecondary, size: 20),
          title: Text('Refresh', style: TextStyle(fontSize: 14)),
          dense: true, contentPadding: EdgeInsets.zero,
        )),
      ],
      offset: const Offset(0, -240),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      color: AppColors.surface,
      child: FloatingActionButton(
        onPressed: null, // handled by PopupMenuButton
        backgroundColor: AppColors.accent,
        foregroundColor: Colors.white,
        child: const Icon(Icons.add, size: 24),
      ),
    );
  }

  Widget _buildHeader() {
    return Container(
      padding: const EdgeInsets.fromLTRB(24, 24, 16, 0),
      child: Row(
        children: [
          const Icon(Icons.verified_user_outlined, size: 22, color: AppColors.primary),
          const SizedBox(width: 10),
          const Text('Credentials',
              style: TextStyle(fontSize: 20, fontWeight: FontWeight.w600, color: AppColors.textPrimary)),
          const Spacer(),
          _HeaderActionButton(
            icon: Icons.send_outlined,
            label: 'Issue',
            color: AppColors.success,
            onPressed: _showIssueDialog,
          ),
          const SizedBox(width: 8),
          _HeaderActionButton(
            icon: Icons.download_outlined,
            label: 'Receive',
            color: AppColors.primary,
            onPressed: _showReceiveDialog,
          ),
          const SizedBox(width: 8),
          _HeaderActionButton(
            icon: Icons.verified_outlined,
            label: 'Verify',
            color: const Color(0xFF6A0DAD),
            onPressed: _showVerifyDialog,
          ),
          const SizedBox(width: 4),
          IconButton(
            icon: const Icon(Icons.refresh, size: 18),
            color: AppColors.textSecondary,
            tooltip: 'Refresh',
            onPressed: _load,
          ),
        ],
      ),
    );
  }

  Widget _buildFilterBar() {
    return Container(
      padding: EdgeInsets.fromLTRB(_isMobileLayout ? 16 : 24, _isMobileLayout ? 16 : 12, _isMobileLayout ? 16 : 24, 0),
      child: Row(
        children: _CredFilter.values.map((f) {
          final label = switch (f) {
            _CredFilter.all      => 'All',
            _CredFilter.received => 'Received',
            _CredFilter.issued   => 'Issued',
            _CredFilter.expired  => 'Expired',
          };
          final isActive = _filter == f;
          return Padding(
            padding: const EdgeInsets.only(right: 8),
            child: InkWell(
              onTap: () => setState(() { _filter = f; }),
              borderRadius: BorderRadius.circular(20),
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
                decoration: BoxDecoration(
                  color: isActive ? AppColors.primary : AppColors.surface,
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(color: isActive ? AppColors.primary : AppColors.border),
                ),
                child: Text(label,
                    style: TextStyle(
                      fontSize: 12,
                      fontWeight: isActive ? FontWeight.w600 : FontWeight.w400,
                      color: isActive ? Colors.white : AppColors.textSecondary,
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
      return const Center(child: CircularProgressIndicator(color: AppColors.primary));
    }
    if (_error != null) {
      return Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.error_outline, size: 40, color: AppColors.error),
            const SizedBox(height: 12),
            Text('Failed to load credentials', style: TextStyle(color: AppColors.textPrimary, fontSize: 15)),
            const SizedBox(height: 4),
            Text(_error!, style: TextStyle(color: AppColors.textMuted, fontSize: 12)),
            const SizedBox(height: 16),
            ElevatedButton(onPressed: _load,
                style: ElevatedButton.styleFrom(backgroundColor: AppColors.primary, foregroundColor: Colors.white),
                child: const Text('Retry')),
          ],
        ),
      );
    }

    final list = _filtered;
    if (list.isEmpty) return _buildEmpty();

    return _buildList(list);
  }

  void _showDetailDialog(CredentialRecord cred) {
    showDialog<void>(
      context: context,
      builder: (ctx) => Dialog(
        backgroundColor: Theme.of(ctx).colorScheme.surface,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 560, maxHeight: 680),
          child: CredentialDetail(
            cred: cred,
            onClose: () => Navigator.pop(ctx),
            onDelete: () {
              Navigator.pop(ctx);
              _delete(cred);
            },
            onVerify: () {
              Navigator.pop(ctx);
              _showVerifyDialog(prefillSaid: cred.said);
            },
            serverUrl: widget.serverUrl,
          ),
        ),
      ),
    );
  }

  Widget _buildEmpty() {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.verified_user_outlined, size: 56, color: AppColors.textMuted.withOpacity(0.4)),
          const SizedBox(height: 16),
          Text(
            _filter == _CredFilter.all ? 'No credentials yet' : 'No ${_filter.name} credentials',
            style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w500, color: AppColors.textSecondary),
          ),
          const SizedBox(height: 8),
          Text(
            _filter == _CredFilter.all
                ? 'Use "Receive" to import a credential, or "Issue" to send one to a contact.'
                : 'Change the filter above to see all credentials.',
            style: TextStyle(fontSize: 13, color: AppColors.textMuted),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 40),
        ],
      ),
    );
  }

  Widget _buildList(List<CredentialRecord> list) {
    return Align(
      alignment: Alignment.topLeft,
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 640),
        child: ListView.separated(
          padding: const EdgeInsets.fromLTRB(24, 16, 24, 24),
          itemCount: list.length,
          separatorBuilder: (_, __) => const SizedBox(height: 10),
          itemBuilder: (_, i) => _CredentialCard(
            cred: list[i],
            selected: false,
            onTap: () => _showDetailDialog(list[i]),
            onDelete: () => _delete(list[i]),
          ),
        ),
      ),
    );
  }
}

// ── Credential card ───────────────────────────────────────────────────────────

IconData _credTypeIcon(String type) {
  final t = type.toLowerCase();
  if (t.contains('guardian')) return Icons.family_restroom;
  if (t.contains('pickup') || t.contains('school')) return Icons.school;
  if (t.contains('age') || t.contains('21') || t.contains('over')) return Icons.cake_outlined;
  if (t.contains('contact') || t.contains('attest')) return Icons.handshake_outlined;
  if (t.contains('license') || t.contains('driver')) return Icons.badge_outlined;
  if (t.contains('passport') || t.contains('travel')) return Icons.travel_explore;
  if (t.contains('health') || t.contains('medical')) return Icons.health_and_safety_outlined;
  return Icons.verified_user_outlined;
}

/// Build a short content summary for a credential card based on its type and ACDC attributes.
String _credContentSummary(CredentialRecord cred, String typeLabel) {
  Map<String, dynamic>? attrs;
  try {
    final decoded = cred.decodedAcdcJson;
    if (decoded.isNotEmpty) {
      final acdc = jsonDecode(decoded);
      if (acdc is Map) {
        final a = acdc['a'];
        if (a is Map) attrs = Map<String, dynamic>.from(a);
      }
    }
  } catch (_) {}

  if (attrs == null) return '';

  final tl = typeLabel.toLowerCase();
  // Guardianship: "Issuer Name (Dependent: dependent_name)"
  if (tl.contains('guardian')) {
    final dep = (attrs['dependent_name'] ?? '').toString();
    if (dep.isNotEmpty) {
      final issuer = cred.issuerName.isNotEmpty ? cred.issuerName : 'Guardian';
      return '$issuer (Dependent: $dep)';
    }
  }
  // Proof of Age: show "21+" or the minimum age
  if (tl.contains('age') || tl.contains('over')) {
    final over21 = attrs['over_21'];
    final minAge = (attrs['minimum_age'] ?? '').toString();
    if (over21 == true || over21 == 'true' || over21 == 'True') {
      return '21+';
    }
    if (minAge.isNotEmpty) return '$minAge+';
    return 'Age verified';
  }
  // School Pickup: child name + school
  if (tl.contains('pickup') || tl.contains('school')) {
    final child = (attrs['child_name'] ?? '').toString();
    final school = (attrs['school_name'] ?? '').toString();
    if (child.isNotEmpty && school.isNotEmpty) return '$child — $school';
    if (child.isNotEmpty) return child;
  }
  // Contact Attestation: subject name + relationship
  if (tl.contains('contact') && tl.contains('attest')) {
    final name = (attrs['subject_name'] ?? '').toString();
    final rel = (attrs['relationship'] ?? '').toString();
    if (name.isNotEmpty && rel.isNotEmpty) return '$name ($rel)';
    if (name.isNotEmpty) return name;
  }
  // Identity Attestation: subject name + assurance level
  if (tl.contains('identity') && tl.contains('attest')) {
    final name = (attrs['subject_name'] ?? '').toString();
    final level = (attrs['assurance_level'] ?? '').toString().toUpperCase();
    if (name.isNotEmpty && level.isNotEmpty) return '$name — $level';
    if (name.isNotEmpty) return name;
  }
  // Generic fallback: first non-empty string value that isn't a SAID
  for (final e in attrs.entries) {
    if (e.key == 'd' || e.key == 'i') continue;
    final v = (e.value ?? '').toString();
    if (v.isNotEmpty && !(v.startsWith('E') && v.length >= 44 && !v.contains(' '))) {
      return v;
    }
  }
  return '';
}

Color _credTypeColor(String type) {
  final t = type.toLowerCase();
  if (t.contains('guardian')) return const Color(0xFF8A3FFC);
  if (t.contains('pickup') || t.contains('school')) return const Color(0xFF007D79);
  if (t.contains('age') || t.contains('21') || t.contains('over')) return const Color(0xFFFF832B);
  if (t.contains('contact') || t.contains('attest')) return const Color(0xFF24A148);
  if (t.contains('health') || t.contains('medical')) return const Color(0xFFDA1E28);
  return const Color(0xFF4589FF);
}

class _CredentialCard extends StatelessWidget {
  final CredentialRecord cred;
  final bool selected;
  final VoidCallback onTap;
  final VoidCallback onDelete;

  const _CredentialCard({
    required this.cred,
    required this.selected,
    required this.onTap,
    required this.onDelete,
  });

  @override
  Widget build(BuildContext context) {
    final typeLabel = cred.credentialType.isNotEmpty
        ? cred.credentialType
        : _deriveTypeFromSchemaSaid(cred.schemaSaid, cred.decodedAcdcJson);
    final typeColor = _credTypeColor(typeLabel);
    final typeIcon = _credTypeIcon(typeLabel);

    // Build a content summary based on credential type
    final contentSummary = _credContentSummary(cred, typeLabel);
    // Issuer / from line
    final fromLine = cred.issuerName.isNotEmpty
        ? 'From ${cred.issuerName}'
        : (cred.issuerAid.isNotEmpty
            ? 'From ${cred.issuerAid.substring(0, (cred.issuerAid.length).clamp(0, 16))}...'
            : '');

    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(10),
      child: Container(
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: AppColors.surface,
          borderRadius: BorderRadius.circular(10),
          border: Border.all(
            color: selected ? AppColors.primary : AppColors.border,
            width: selected ? 1.5 : 1,
          ),
        ),
        child: Row(
          children: [
            // Credential type icon
            Container(
              width: 44,
              height: 44,
              decoration: BoxDecoration(
                color: typeColor.withOpacity(0.12),
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: typeColor.withOpacity(0.25)),
              ),
              child: Icon(typeIcon, size: 20, color: typeColor),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  // Type (title) + badges in upper right
                  Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Expanded(
                        child: Text(
                          typeLabel,
                          style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w600,
                              color: AppColors.textPrimary),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      const SizedBox(width: 6),
                      _FormatBadge(format: cred.format),
                      const SizedBox(width: 4),
                      _RoleBadge(status: cred.status),
                      if (cred.expiryDate.isNotEmpty) ...[
                        const SizedBox(width: 4),
                        _ExpiryBadge(cred: cred),
                      ],
                    ],
                  ),
                  // From (issuer)
                  if (fromLine.isNotEmpty) ...[
                    const SizedBox(height: 2),
                    Text(fromLine,
                        style: const TextStyle(fontSize: 12, color: AppColors.textMuted),
                        maxLines: 1, overflow: TextOverflow.ellipsis),
                  ],
                  // Content summary
                  if (contentSummary.isNotEmpty) ...[
                    const SizedBox(height: 4),
                    Text(
                      contentSummary,
                      style: TextStyle(fontSize: 13, color: typeColor, fontWeight: FontWeight.w500),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ],
                ],
              ),
            ),
            const SizedBox(width: 8),
            IconButton(
              icon: const Icon(Icons.delete_outline, size: 16),
              color: AppColors.textMuted,
              tooltip: 'Remove',
              padding: EdgeInsets.zero,
              constraints: const BoxConstraints(minWidth: 28, minHeight: 28),
              onPressed: onDelete,
            ),
          ],
        ),
      ),
    );
  }
}

// ── Credential detail panel ───────────────────────────────────────────────────

class CredentialDetail extends StatefulWidget {
  final CredentialRecord cred;
  final VoidCallback onDelete;
  final VoidCallback onClose;
  final VoidCallback onVerify;
  final String? serverUrl;

  const CredentialDetail({
    super.key,
    required this.cred,
    required this.onDelete,
    required this.onClose,
    required this.onVerify,
    this.serverUrl,
  });

  @override
  State<CredentialDetail> createState() => CredentialDetailState();
}

class CredentialDetailState extends State<CredentialDetail> {
  List<Map<String, dynamic>>? _chain;
  bool _verifying = false;
  String? _verifyError;
  bool? _chainValid;

  @override
  void initState() {
    super.initState();
    _verifyChain();
  }

  @override
  void didUpdateWidget(CredentialDetail old) {
    super.didUpdateWidget(old);
    if (old.cred.said != widget.cred.said) {
      _chain = null;
      _chainValid = null;
      _verifyError = null;
      _verifyChain();
    }
  }

  Future<void> _verifyChain() async {
    setState(() { _verifying = true; _verifyError = null; });
    try {
      final svc = CoreService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);
      final result = await svc.verifyCredentialChain(acdcSaid: widget.cred.said);
      svc.dispose();
      if (!mounted) return;
      try {
        final chainValid = result['valid'] == true;
        final rawChain = result['chain'];
        final List<Map<String, dynamic>> parsedChain = [];
        if (rawChain is List) {
          for (final item in rawChain) {
            if (item is Map) {
              parsedChain.add(
                item.map((k, v) => MapEntry(k.toString(), v)),
              );
            }
          }
        }
        setState(() {
          _verifying = false;
          _chainValid = chainValid;
          _chain = parsedChain;
        });
      } catch (mapError) {
        setState(() {
          _verifying = false;
          _verifyError = 'Chain data format error: $mapError';
        });
      }
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _verifying = false;
        _verifyError = e.toString().replaceFirst('Exception: ', '');
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    try {
      return _buildDetailContent(context);
    } catch (e) {
      // Error boundary fallback — show raw credential info instead of crashing
      final cred = widget.cred;
      return Container(
        color: AppColors.surface,
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                const Icon(Icons.warning_amber_rounded, size: 20, color: AppColors.warning),
                const SizedBox(width: 8),
                const Expanded(
                  child: Text('Could not render credential details',
                      style: TextStyle(fontSize: 14, fontWeight: FontWeight.w600,
                          color: AppColors.textPrimary)),
                ),
                IconButton(
                  icon: const Icon(Icons.close, size: 18),
                  color: AppColors.textMuted,
                  onPressed: widget.onClose,
                  padding: EdgeInsets.zero,
                  constraints: const BoxConstraints(minWidth: 28, minHeight: 28),
                ),
              ],
            ),
            const SizedBox(height: 16),
            Text('SAID: ${cred.said}',
                style: const TextStyle(fontSize: 12, fontFamily: 'monospace',
                    color: AppColors.textSecondary)),
            const SizedBox(height: 6),
            Text('Issuer: ${cred.issuerAid}',
                style: const TextStyle(fontSize: 12, fontFamily: 'monospace',
                    color: AppColors.textSecondary)),
            const SizedBox(height: 6),
            Text('Type: ${cred.credentialType.isNotEmpty ? cred.credentialType : cred.schemaSaid}',
                style: const TextStyle(fontSize: 12, fontFamily: 'monospace',
                    color: AppColors.textSecondary)),
            const SizedBox(height: 6),
            Text('Format: ${cred.format}  |  Status: ${cred.status}',
                style: const TextStyle(fontSize: 12, fontFamily: 'monospace',
                    color: AppColors.textSecondary)),
            const SizedBox(height: 12),
            Text('Rendering error: $e',
                style: const TextStyle(fontSize: 11, color: AppColors.textMuted)),
          ],
        ),
      );
    }
  }

  Widget _buildDetailContent(BuildContext context) {
    Map<String, dynamic>? attrs;
    String? schemaHint;
    try {
      final raw = jsonDecode(widget.cred.decodedAcdcJson);
      final acdc = Map<String, dynamic>.from(raw as Map);
      final a = acdc['a'];
      if (a is Map) attrs = Map<String, dynamic>.from(a);
      schemaHint = acdc['s']?.toString();
    } catch (_) {}

    final cred = widget.cred;
    final typeLabel = cred.credentialType.isNotEmpty
        ? cred.credentialType
        : _deriveTypeFromSchemaSaid(schemaHint ?? cred.schemaSaid, cred.decodedAcdcJson);
    final typeColor = _credTypeColor(typeLabel);

    return Container(
      color: AppColors.surface,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header
          Container(
            padding: const EdgeInsets.fromLTRB(20, 20, 12, 16),
            decoration: const BoxDecoration(
              border: Border(bottom: BorderSide(color: AppColors.border)),
            ),
            child: Row(
              children: [
                _IssuerAvatar(
                  name: cred.issuerName.isNotEmpty ? cred.issuerName : '?',
                  logoUrl: cred.issuerLogoUrl.isNotEmpty ? cred.issuerLogoUrl : null,
                  size: 36,
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(typeLabel,
                          style: const TextStyle(fontSize: 15, fontWeight: FontWeight.w600,
                              color: AppColors.textPrimary)),
                      if (cred.issuerName.isNotEmpty)
                        Text('Issued by ${cred.issuerName}',
                            style: const TextStyle(fontSize: 12, color: AppColors.textMuted)),
                    ],
                  ),
                ),
                IconButton(
                  icon: const Icon(Icons.close, size: 18),
                  color: AppColors.textMuted,
                  onPressed: widget.onClose,
                  padding: EdgeInsets.zero,
                  constraints: const BoxConstraints(minWidth: 28, minHeight: 28),
                ),
              ],
            ),
          ),

          Expanded(
            child: ListView(
              padding: const EdgeInsets.all(20),
              children: [
                // Status badges row
                Row(
                  children: [
                    _FormatBadge(format: cred.format),
                    const SizedBox(width: 8),
                    if (cred.expiryDate.isNotEmpty) _ExpiryBadge(cred: cred),
                    const SizedBox(width: 8),
                    _StatusBadge(status: cred.status),
                  ],
                ),
                const SizedBox(height: 20),

                // ── Issuer section ──────────────────────────────
                _sectionLabel('ISSUER'),
                Container(
                  padding: const EdgeInsets.all(14),
                  decoration: BoxDecoration(
                    color: AppColors.surfaceLight,
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: AppColors.border),
                  ),
                  child: Row(
                    children: [
                      _IssuerAvatar(
                        name: cred.issuerName.isNotEmpty ? cred.issuerName : cred.issuerAid,
                        logoUrl: cred.issuerLogoUrl.isNotEmpty ? cred.issuerLogoUrl : null,
                        size: 40,
                      ),
                      const SizedBox(width: 12),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              cred.issuerName.isNotEmpty ? cred.issuerName : 'Unknown Issuer',
                              style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w600,
                                  color: AppColors.textPrimary),
                            ),
                            const SizedBox(height: 4),
                            InkWell(
                              onTap: () => Clipboard.setData(ClipboardData(text: cred.issuerAid)),
                              child: Row(
                                children: [
                                  Expanded(
                                    child: Text(
                                      cred.issuerAid.length > 32
                                          ? '${cred.issuerAid.substring(0, 16)}...${cred.issuerAid.substring(cred.issuerAid.length - 8)}'
                                          : cred.issuerAid,
                                      style: const TextStyle(fontSize: 11, fontFamily: 'monospace',
                                          color: AppColors.textMuted),
                                    ),
                                  ),
                                  const SizedBox(width: 4),
                                  const Icon(Icons.copy, size: 11, color: AppColors.textMuted),
                                ],
                              ),
                            ),
                            if (cred.issuedAt.isNotEmpty) ...[
                              const SizedBox(height: 4),
                              Text('Issued ${cred.issuedAt.length > 10 ? cred.issuedAt.substring(0, 10) : cred.issuedAt}',
                                  style: const TextStyle(fontSize: 11, color: AppColors.textMuted)),
                            ],
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 20),

                // ── Human-readable details ──────────────────────
                if (attrs != null && attrs.isNotEmpty) ...[
                  _sectionLabel('DETAILS'),
                  Container(
                    padding: const EdgeInsets.all(14),
                    decoration: BoxDecoration(
                      color: typeColor.withOpacity(0.04),
                      borderRadius: BorderRadius.circular(8),
                      border: Border.all(color: typeColor.withOpacity(0.12)),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: attrs.entries
                          .where((e) => e.key != 'd' && e.key != 'i')
                          .map((e) => _detailRow(e.key, e.value?.toString() ?? ''))
                          .toList(),
                    ),
                  ),
                  const SizedBox(height: 20),
                ],

                // ── Verification chain ──────────────────────────
                _sectionLabel('VERIFICATION'),
                Container(
                  padding: const EdgeInsets.all(14),
                  decoration: BoxDecoration(
                    color: AppColors.background,
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: AppColors.border),
                  ),
                  child: _buildChainSection(),
                ),
                const SizedBox(height: 20),

                // ── Technical (collapsed by default) ────────────
                Theme(
                  data: Theme.of(context).copyWith(dividerColor: Colors.transparent),
                  child: ExpansionTile(
                    tilePadding: EdgeInsets.zero,
                    title: const Text('Technical Details',
                        style: TextStyle(fontSize: 11, fontWeight: FontWeight.w600,
                            color: AppColors.textMuted, letterSpacing: 0.8)),
                    initiallyExpanded: false,
                    children: [
                      _copyRow('SAID', cred.said),
                      _copyRow('Issuer AID', cred.issuerAid),
                      _copyRow('Schema SAID', cred.schemaSaid),
                      if (cred.ixnSaid.isNotEmpty) _copyRow('IXN SAID', cred.ixnSaid),
                      _copyRow('Issued', cred.issuedAt),
                    ],
                  ),
                ),
                const SizedBox(height: 16),

                // Actions
                Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: [
                    OutlinedButton.icon(
                      onPressed: () {
                        Clipboard.setData(ClipboardData(text: cred.acdcJson));
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(content: Text('ACDC JSON copied'), duration: Duration(seconds: 2)),
                        );
                      },
                      icon: const Icon(Icons.copy, size: 14),
                      label: const Text('Copy JSON', style: TextStyle(fontSize: 12)),
                      style: OutlinedButton.styleFrom(
                        foregroundColor: AppColors.textSecondary,
                        side: BorderSide(color: AppColors.border),
                        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                      ),
                    ),
                    OutlinedButton.icon(
                      onPressed: widget.onVerify,
                      icon: const Icon(Icons.verified_outlined, size: 14),
                      label: const Text('Full Verify', style: TextStyle(fontSize: 12)),
                      style: OutlinedButton.styleFrom(
                        foregroundColor: const Color(0xFF9B59B6),
                        side: const BorderSide(color: Color(0xFF9B59B6)),
                        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                      ),
                    ),
                    OutlinedButton.icon(
                      onPressed: widget.onDelete,
                      icon: const Icon(Icons.delete_outline, size: 14),
                      label: const Text('Remove', style: TextStyle(fontSize: 12)),
                      style: OutlinedButton.styleFrom(
                        foregroundColor: AppColors.error,
                        side: BorderSide(color: AppColors.error.withOpacity(0.4)),
                        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildChainSection() {
    if (_verifying) {
      return const Row(
        children: [
          SizedBox(width: 14, height: 14, child: CircularProgressIndicator(strokeWidth: 2, color: AppColors.primary)),
          SizedBox(width: 10),
          Text('Verifying credential chain...', style: TextStyle(fontSize: 12, color: AppColors.textMuted)),
        ],
      );
    }
    if (_verifyError != null) {
      return Row(
        children: [
          const Icon(Icons.warning_amber_rounded, size: 16, color: AppColors.warning),
          const SizedBox(width: 8),
          Expanded(child: Text('Could not verify: $_verifyError',
              style: const TextStyle(fontSize: 12, color: AppColors.textMuted))),
          IconButton(
            icon: const Icon(Icons.refresh, size: 14),
            onPressed: _verifyChain,
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(minWidth: 24, minHeight: 24),
          ),
        ],
      );
    }
    if (_chain == null || _chain!.isEmpty) {
      return const Text('No chain data available.',
          style: TextStyle(fontSize: 12, color: AppColors.textMuted));
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Icon(
              _chainValid == true ? Icons.verified : Icons.gpp_maybe_outlined,
              size: 16,
              color: _chainValid == true ? AppColors.success : AppColors.warning,
            ),
            const SizedBox(width: 6),
            Text(
              _chainValid == true
                  ? 'Credential chain verified (${_chain!.length} ${_chain!.length == 1 ? "step" : "steps"})'
                  : 'Chain verification incomplete',
              style: TextStyle(
                fontSize: 12,
                fontWeight: FontWeight.w600,
                color: _chainValid == true ? AppColors.success : AppColors.warning,
              ),
            ),
          ],
        ),
        const SizedBox(height: 10),
        ..._chain!.asMap().entries.map((entry) {
          final idx = entry.key;
          final step = entry.value;
          final stepValid = step['valid'] == true;
          final edgeLabel = (step['edge_label'] ?? '').toString();
          final isLast = idx == _chain!.length - 1;

          // checks can be a Map<String,bool> or a List — handle both safely
          final rawChecks = step['checks'];
          Map<String, bool> checksMap = {};
          if (rawChecks is Map) {
            checksMap = rawChecks.map((k, v) => MapEntry(k.toString(), v == true));
          } else if (rawChecks is List) {
            for (final c in rawChecks) {
              checksMap[c.toString()] = true;
            }
          }

          // errors is a List<String>
          final rawErrors = step['errors'];
          List<String> errors = [];
          if (rawErrors is List) {
            errors = rawErrors.map((e) => e.toString()).toList();
          }

          return Padding(
            padding: const EdgeInsets.only(bottom: 4),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Chain connector
                Column(
                  children: [
                    Icon(
                      stepValid ? Icons.check_circle : Icons.cancel,
                      size: 16,
                      color: stepValid ? AppColors.success : AppColors.error,
                    ),
                    if (!isLast) Container(
                      width: 1.5, height: 20,
                      color: AppColors.border,
                    ),
                  ],
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        edgeLabel.isNotEmpty
                            ? 'Step ${idx + 1}: ${_formatKey(edgeLabel)}'
                            : 'Step ${idx + 1}: Root credential',
                        style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w600,
                            color: AppColors.textPrimary),
                      ),
                      if (checksMap.isNotEmpty)
                        Wrap(
                          spacing: 4,
                          runSpacing: 2,
                          children: checksMap.entries.map((e) {
                            final passed = e.value;
                            return Container(
                              margin: const EdgeInsets.only(top: 2),
                              padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
                              decoration: BoxDecoration(
                                color: (passed ? AppColors.success : AppColors.error).withOpacity(0.08),
                                borderRadius: BorderRadius.circular(3),
                              ),
                              child: Text(
                                e.key.replaceAll('_', ' '),
                                style: TextStyle(fontSize: 9, color: passed ? AppColors.success : AppColors.error),
                              ),
                            );
                          }).toList(),
                        ),
                      if (errors.isNotEmpty)
                        ...errors.map((e) => Padding(
                          padding: const EdgeInsets.only(top: 2),
                          child: Text(e, style: const TextStyle(fontSize: 10, color: AppColors.error)),
                        )),
                    ],
                  ),
                ),
              ],
            ),
          );
        }),
      ],
    );
  }

  Widget _sectionLabel(String label) => Padding(
    padding: const EdgeInsets.only(bottom: 8),
    child: Text(label,
        style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w600,
            color: AppColors.textMuted, letterSpacing: 0.8)),
  );

  Widget _detailRow(String key, String value) {
    // Format booleans nicely
    String displayValue = value;
    if (value == 'true') displayValue = 'Yes';
    if (value == 'false') displayValue = 'No';

    return Padding(
      padding: const EdgeInsets.only(bottom: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 130,
            child: Text(_formatKey(key),
                style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w500, color: AppColors.textMuted)),
          ),
          Expanded(
            child: Text(displayValue,
                style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w500, color: AppColors.textPrimary)),
          ),
        ],
      ),
    );
  }

  Widget _copyRow(String label, String value) => InkWell(
    onTap: () => Clipboard.setData(ClipboardData(text: value)),
    child: Padding(
      padding: const EdgeInsets.only(bottom: 6),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 120,
            child: Text(label,
                style: const TextStyle(fontSize: 12, color: AppColors.textMuted)),
          ),
          Expanded(
            child: Text(
              value.length > 40 ? '${value.substring(0, 20)}...${value.substring(value.length - 10)}' : value,
              style: const TextStyle(fontSize: 12, color: AppColors.textPrimary, fontFamily: 'monospace'),
            ),
          ),
          const Icon(Icons.copy, size: 12, color: AppColors.textMuted),
        ],
      ),
    ),
  );

  String _formatKey(String key) {
    return key.replaceAll('_', ' ').replaceAllMapped(
      RegExp(r'([A-Z])'),
      (m) => ' ${m.group(1)}',
    ).trim().split(' ').map((w) => w.isNotEmpty ? '${w[0].toUpperCase()}${w.substring(1)}' : '').join(' ');
  }

}

// ── Small reusable widgets ────────────────────────────────────────────────────

class _IssuerAvatar extends StatelessWidget {
  final String name;
  final String? logoUrl;
  final double size;
  const _IssuerAvatar({required this.name, this.logoUrl, this.size = 40});

  @override
  Widget build(BuildContext context) {
    if (logoUrl != null && logoUrl!.isNotEmpty) {
      return ClipRRect(
        borderRadius: BorderRadius.circular(8),
        child: Image.network(
          logoUrl!,
          width: size,
          height: size,
          fit: BoxFit.cover,
          errorBuilder: (_, __, ___) => _letterAvatar(),
        ),
      );
    }
    return _letterAvatar();
  }

  Widget _letterAvatar() {
    final letter = name.isNotEmpty ? name[0].toUpperCase() : '?';
    const colors = [
      Color(0xFF4589FF), Color(0xFF24A148), Color(0xFFFF832B),
      Color(0xFF8A3FFC), Color(0xFF007D79), Color(0xFFDA1E28),
    ];
    final color = colors[name.isNotEmpty ? name.codeUnitAt(0) % colors.length : 0];
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        color: color.withOpacity(0.15),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: color.withOpacity(0.3)),
      ),
      child: Center(
        child: Text(letter,
            style: TextStyle(fontSize: size * 0.4, fontWeight: FontWeight.w700, color: color)),
      ),
    );
  }
}

class _FormatBadge extends StatelessWidget {
  final String format;
  const _FormatBadge({required this.format});

  @override
  Widget build(BuildContext context) {
    final label = switch (format) {
      'acdc'   => 'ACDC',
      'w3c_vc' => 'W3C VC',
      'sd_jwt' => 'SD-JWT',
      'mdl'    => 'MDL',
      _        => format.toUpperCase(),
    };
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: AppColors.primary.withOpacity(0.08),
        borderRadius: BorderRadius.circular(4),
        border: Border.all(color: AppColors.primary.withOpacity(0.2)),
      ),
      child: Text(label,
          style: const TextStyle(fontSize: 9, fontWeight: FontWeight.w700,
              color: AppColors.primary, letterSpacing: 0.3)),
    );
  }
}

class _ExpiryBadge extends StatelessWidget {
  final CredentialRecord cred;
  const _ExpiryBadge({required this.cred});

  @override
  Widget build(BuildContext context) {
    final Color color;
    String label;
    if (cred.isExpired) {
      color = AppColors.error;
      label = 'Expired';
    } else if (cred.expiringWithin30Days) {
      color = AppColors.warning;
      label = 'Expiring';
    } else {
      color = AppColors.success;
      try {
        final dt = DateTime.parse(cred.expiryDate);
        label = 'Exp ${dt.year}-${dt.month.toString().padLeft(2, '0')}-${dt.day.toString().padLeft(2, '0')}';
      } catch (_) {
        label = 'Valid';
      }
    }
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

class _StatusBadge extends StatelessWidget {
  final String status;
  const _StatusBadge({required this.status});

  @override
  Widget build(BuildContext context) {
    final color = switch (status) {
      'issued'   => AppColors.primary,
      'received' => AppColors.success,
      'revoked'  => AppColors.error,
      _          => AppColors.textMuted,
    };
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: color.withOpacity(0.08),
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(status,
          style: TextStyle(fontSize: 10, fontWeight: FontWeight.w600, color: color)),
    );
  }
}

class _RoleBadge extends StatelessWidget {
  final String status;
  const _RoleBadge({required this.status});

  @override
  Widget build(BuildContext context) {
    final isIssued = status == 'issued';
    final color = isIssued ? AppColors.success : AppColors.primary;
    final label = isIssued ? 'Issued' : 'Accepted';
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: color.withOpacity(0.10),
        borderRadius: BorderRadius.circular(4),
        border: Border.all(color: color.withOpacity(0.25)),
      ),
      child: Text(label,
          style: TextStyle(fontSize: 10, fontWeight: FontWeight.w600, color: color)),
    );
  }
}

class _HeaderActionButton extends StatelessWidget {
  final IconData icon;
  final String label;
  final Color color;
  final VoidCallback onPressed;
  const _HeaderActionButton({
    required this.icon,
    required this.label,
    required this.color,
    required this.onPressed,
  });

  @override
  Widget build(BuildContext context) {
    return FilledButton.icon(
      onPressed: onPressed,
      icon: Icon(icon, size: 16),
      label: Text(label,
          style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w500, letterSpacing: 0.2)),
      style: FilledButton.styleFrom(
        backgroundColor: color,
        foregroundColor: Colors.white,
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
        minimumSize: const Size(0, 36),
        tapTargetSize: MaterialTapTargetSize.shrinkWrap,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
        elevation: 0,
      ),
    );
  }
}

// ── Issue Credential Dialog ───────────────────────────────────────────────────
//
// Three-step flow inside a single dialog:
//   Step 1: Pick credential type (schema)
//   Step 2: Fill in claims (form driven by schema fields)
//   Step 3: Pick recipient from accepted contacts

class _IssueCredentialDialog extends StatefulWidget {
  final List<BuiltinSchema> schemas;
  final List<ContactResponse> contacts;
  final CoreService coreService;
  final VoidCallback onIssued;

  const _IssueCredentialDialog({
    required this.schemas,
    required this.contacts,
    required this.coreService,
    required this.onIssued,
  });

  @override
  State<_IssueCredentialDialog> createState() => _IssueCredentialDialogState();
}

class _IssueCredentialDialogState extends State<_IssueCredentialDialog> {
  int _step = 0; // 0=pick schema, 1=fill claims, 2=pick contact, 3=success
  BuiltinSchema? _schema;
  ContactResponse? _contact;
  final Map<String, TextEditingController> _controllers = {};
  final Map<String, bool> _boolValues = {};
  bool _issuing = false;
  String? _error;
  String? _issuedAcdcJson; // returned after success
  String? _issuedSaid;
  String? _deliveryUrl;
  bool _deliveryUrlCopied = false;
  bool _shareExternally = false; // true = show QR/link on success even for known contact
  bool _delivered = false; // true = recipient server responded OK

  @override
  void dispose() {
    for (final c in _controllers.values) c.dispose();
    super.dispose();
  }

  /// Example data per schema for demo purposes.
  static const _dummyData = <String, Map<String, String>>{
    'Guardianship Credential': {
      'dependent_name': 'Emma Anderson',
      'guardian_type': 'minor_child',
      'effective_date': '2025-06-15',
      'jurisdiction': 'State of Utah',
      'notes': 'Primary legal guardian, full custody',
    },
    'Proof of Age': {
      'over_21': 'true',
      'minimum_age': '21',
      'verified_by': 'Government-issued photo ID',
      'issued_date': '2026-03-20',
    },
    'Contact Attestation': {
      'attestation': 'in_person_verified',
      'subject_name': 'Sarah Chen',
      'relationship': 'colleague',
      'verified_date': '2026-03-15',
      'notes': 'Met at quarterly offsite, verified against govt ID',
    },
    'Identity Attestation': {
      'subject_name': 'James Roberts',
      'assurance_level': 'ial3',
      'auth_assurance': 'aal3',
      'confidence_score': '92',
      'verification_methods': 'government_id, biometric_liveness',
      'jurisdiction': 'US-UT',
      'issued_date': '2026-03-18',
      'issuer_type': 'witness',
    },
    'School Pickup Authorization': {
      'child_name': 'Emma Anderson',
      'school_name': 'Lincoln Elementary',
      'authorized_until': '2026-06-15',
      'authorized_from': '2026-01-10',
      'authorized_days': 'Monday, Wednesday, Friday',
      'notes': 'Grandparent authorized for after-school pickup',
    },
  };

  void _selectSchema(BuiltinSchema schema) {
    _controllers.clear();
    _boolValues.clear();
    final dummy = _dummyData[schema.name] ?? {};
    for (final f in schema.fields) {
      if (f.key == 'd' || f.key == 'i') continue; // auto-filled by backend
      if (f.type == 'boolean') {
        _boolValues[f.key] = dummy.containsKey(f.key) ? dummy[f.key] == 'true' : false;
      } else {
        _controllers[f.key] = TextEditingController(text: dummy[f.key] ?? '');
      }
    }
    setState(() { _schema = schema; _step = 1; });
  }

  Future<void> _issue() async {
    if ((_contact == null && !_shareExternally) || _schema == null) return;
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
          holderAid: _contact?.aid ?? '',
          claims: claims,
        ),
        widget.coreService.getOobi(),
      ]);
      final result = Map<String, dynamic>.from(results[0] as Map);
      final oobi = results[1] as OobiResponse;
      final said = result['acdc_said']?.toString() ?? '';
      final endpointBase = oobi.endpointUrl.isNotEmpty ? oobi.endpointUrl : oobi.baseUrl;
      final baseClean = endpointBase.endsWith('/') ? endpointBase.substring(0, endpointBase.length - 1) : endpointBase;
      final delivered = result['delivered'] == true;
      setState(() {
        _issuing = false;
        _issuedSaid = said;
        _issuedAcdcJson = result['acdc_json_b64']?.toString() ?? '';
        _deliveryUrl = said.isNotEmpty ? '$baseClean/public/credential/$said' : null;
        _delivered = delivered;
        _step = 3; // success step
      });
    } catch (e) {
      setState(() {
        _issuing = false;
        _error = e.toString().replaceFirst('Exception: ', '');
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      backgroundColor: AppColors.surface,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
      title: _buildTitle(),
      content: SizedBox(
        width: 520,
        child: _buildStepContent(),
      ),
      actions: _buildActions(),
    );
  }

  Widget _buildTitle() {
    final titles = ['Issue a Credential', 'Fill in Details', 'Choose Recipient', 'Credential Issued'];
    return Row(
      children: [
        Text(titles[_step.clamp(0, 3)],
            style: const TextStyle(color: AppColors.textPrimary, fontSize: 16, fontWeight: FontWeight.w600)),
        const Spacer(),
        if (_step > 0 && _step < 3)
          _StepIndicator(current: _step, total: 3),
      ],
    );
  }

  Widget _buildStepContent() {
    switch (_step) {
      case 0: return _buildSchemaPicker();
      case 1: return _buildClaimsForm();
      case 2: return _buildContactPicker();
      case 3: return _buildSuccess();
      default: return const SizedBox.shrink();
    }
  }

  Widget _buildSchemaPicker() {
    if (widget.schemas.isEmpty) {
      return const Padding(
        padding: EdgeInsets.symmetric(vertical: 24),
        child: Center(child: Text('No schemas available', style: TextStyle(color: AppColors.textMuted))),
      );
    }
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('What type of credential do you want to issue?',
            style: TextStyle(color: AppColors.textSecondary, fontSize: 13)),
        const SizedBox(height: 12),
        ...widget.schemas
            .where((s) => s.name != 'Contact Attestation' && s.name != 'Identity Attestation')
            .map((s) => _SchemaOption(
          schema: s,
          onTap: () => _selectSchema(s),
        )),
      ],
    );
  }

  Widget _buildClaimsForm() {
    if (_schema == null) return const SizedBox.shrink();
    final visibleFields = _schema!.fields.where((f) => f.key != 'd' && f.key != 'i').toList();
    return SingleChildScrollView(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: AppColors.primary.withOpacity(0.06),
              borderRadius: BorderRadius.circular(6),
            ),
            child: Row(
              children: [
                const Icon(Icons.info_outline, size: 14, color: AppColors.primary),
                const SizedBox(width: 8),
                Expanded(child: Text(_schema!.description,
                    style: const TextStyle(fontSize: 12, color: AppColors.textSecondary))),
              ],
            ),
          ),
          const SizedBox(height: 14),
          if (_error != null) ...[
            Text(_error!, style: TextStyle(color: AppColors.error, fontSize: 12)),
            const SizedBox(height: 8),
          ],
          ...visibleFields.map((f) => Padding(
            padding: const EdgeInsets.only(bottom: 10),
            child: f.type == 'boolean'
                ? Row(
                    children: [
                      Checkbox(
                        value: _boolValues[f.key] ?? false,
                        onChanged: (v) => setState(() => _boolValues[f.key] = v ?? false),
                        activeColor: AppColors.primary,
                      ),
                      Text(f.label + (f.required ? ' *' : ''),
                          style: const TextStyle(fontSize: 13, color: AppColors.textPrimary)),
                    ],
                  )
                : TextField(
                    controller: _controllers[f.key],
                    style: const TextStyle(fontSize: 13, color: AppColors.textPrimary),
                    decoration: InputDecoration(
                      labelText: f.label + (f.required ? ' *' : ''),
                      labelStyle: TextStyle(fontSize: 12, color: AppColors.textSecondary),
                      hintText: f.placeholder.isNotEmpty ? f.placeholder : null,
                      hintStyle: TextStyle(fontSize: 12, color: AppColors.textMuted),
                      filled: true,
                      fillColor: AppColors.surfaceLight,
                      border: OutlineInputBorder(borderRadius: BorderRadius.circular(6),
                          borderSide: BorderSide(color: AppColors.border)),
                      enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(6),
                          borderSide: BorderSide(color: AppColors.border)),
                      contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                      isDense: true,
                    ),
                  ),
          )),
        ],
      ),
    );
  }

  Widget _buildContactPicker() {
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text('Who should receive this credential?',
            style: TextStyle(color: AppColors.textSecondary, fontSize: 13)),
        const SizedBox(height: 12),
        if (widget.contacts.isNotEmpty)
          ConstrainedBox(
            constraints: const BoxConstraints(maxHeight: 260),
            child: ListView.separated(
              shrinkWrap: true,
              itemCount: widget.contacts.length,
              separatorBuilder: (_, __) => const SizedBox(height: 4),
              itemBuilder: (_, i) {
                final c = widget.contacts[i];
                final isSelected = !_shareExternally && _contact?.aid == c.aid;
                return InkWell(
                  onTap: () => setState(() { _contact = c; _shareExternally = false; }),
                  borderRadius: BorderRadius.circular(6),
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                    decoration: BoxDecoration(
                      color: isSelected ? AppColors.primary.withOpacity(0.08) : Colors.transparent,
                      borderRadius: BorderRadius.circular(6),
                      border: Border.all(
                        color: isSelected ? AppColors.primary : AppColors.border,
                      ),
                    ),
                    child: Row(
                      children: [
                        _IssuerAvatar(
                          name: c.alias.isNotEmpty ? c.alias : c.aid,
                          size: 32,
                        ),
                        const SizedBox(width: 10),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(c.alias.isNotEmpty ? c.alias : 'Unknown',
                                  style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w500,
                                      color: AppColors.textPrimary)),
                              Text(
                                c.aid.length > 30 ? '${c.aid.substring(0, 20)}...' : c.aid,
                                style: TextStyle(fontSize: 11, color: AppColors.textMuted, fontFamily: 'monospace'),
                              ),
                            ],
                          ),
                        ),
                        if (isSelected) Icon(Icons.check_circle, size: 18, color: AppColors.primary),
                      ],
                    ),
                  ),
                );
              },
            ),
          ),
        if (widget.contacts.isEmpty)
          Padding(
            padding: const EdgeInsets.symmetric(vertical: 8),
            child: Text('No accepted contacts yet.',
                style: TextStyle(color: AppColors.textMuted, fontSize: 12)),
          ),
        const SizedBox(height: 8),
        // ── Share externally option ────────────────────────────────────
        InkWell(
          onTap: () => setState(() { _shareExternally = true; _contact = null; }),
          borderRadius: BorderRadius.circular(6),
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
            decoration: BoxDecoration(
              color: _shareExternally ? AppColors.accent.withOpacity(0.08) : Colors.transparent,
              borderRadius: BorderRadius.circular(6),
              border: Border.all(
                color: _shareExternally ? AppColors.accent : AppColors.border,
              ),
            ),
            child: Row(
              children: [
                Container(
                  width: 32, height: 32,
                  decoration: BoxDecoration(
                    color: AppColors.accent.withOpacity(0.12),
                    borderRadius: BorderRadius.circular(16),
                  ),
                  child: const Icon(Icons.share_outlined, size: 16, color: AppColors.accent),
                ),
                const SizedBox(width: 10),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: const [
                      Text('Share externally',
                          style: TextStyle(fontSize: 13, fontWeight: FontWeight.w500, color: AppColors.textPrimary)),
                      Text('Via QR code, link, or text — for someone not in your contacts',
                          style: TextStyle(fontSize: 11, color: AppColors.textMuted)),
                    ],
                  ),
                ),
                if (_shareExternally) Icon(Icons.check_circle, size: 18, color: AppColors.accent),
              ],
            ),
          ),
        ),
        if (_error != null) ...[
          const SizedBox(height: 8),
          Text(_error!, style: TextStyle(color: AppColors.error, fontSize: 12)),
        ],
      ],
    );
  }

  Widget _buildSuccess() {
    final recipientName = _contact?.alias ?? _contact?.aid ?? 'external recipient';
    // Show sharing UI when: sharing externally, OR delivered to a contact but their server didn't confirm
    final showShareUI = _shareExternally || !_delivered;

    return SingleChildScrollView(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const SizedBox(height: 8),
          Icon(Icons.check_circle_outline, size: 44, color: AppColors.success),
          const SizedBox(height: 10),
          Text(
            _shareExternally
                ? 'Credential issued — share it with the recipient below'
                : 'Credential issued to $recipientName',
            style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w500, color: AppColors.textPrimary),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 6),
          Text(
            _delivered && !_shareExternally
                ? 'Signed, anchored to your Key Event Log, and delivered.'
                : 'Signed and anchored to your Key Event Log.',
            style: TextStyle(fontSize: 12, color: AppColors.textMuted),
            textAlign: TextAlign.center,
          ),
          // ── Sharing UI: QR + link + copy (shown for external or undelivered) ──
          if (_deliveryUrl != null && showShareUI) ...[
            const SizedBox(height: 20),
            Container(
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: AppColors.surfaceLight,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: AppColors.border),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Icon(Icons.share_outlined, size: 14, color: AppColors.primary),
                      const SizedBox(width: 6),
                      Text(
                        _shareExternally ? 'SHARE CREDENTIAL' : 'DELIVERY LINK',
                        style: const TextStyle(fontSize: 10, fontWeight: FontWeight.w700,
                            color: AppColors.primary, letterSpacing: 0.8),
                      ),
                    ],
                  ),
                  const SizedBox(height: 10),
                  Center(
                    child: QrImageView(
                      data: _deliveryUrl!,
                      version: QrVersions.auto,
                      size: 140,
                      backgroundColor: Colors.white,
                      padding: const EdgeInsets.all(6),
                    ),
                  ),
                  const SizedBox(height: 8),
                  const Center(
                    child: Text('Scan to accept in the Identity Agent app',
                        style: TextStyle(fontSize: 10, color: AppColors.textMuted)),
                  ),
                  const SizedBox(height: 12),
                  Text(
                    _deliveryUrl!,
                    style: const TextStyle(fontSize: 10, color: AppColors.textSecondary,
                        fontFamily: 'monospace'),
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                  ),
                  const SizedBox(height: 10),
                  Row(
                    children: [
                      OutlinedButton.icon(
                        onPressed: () {
                          Clipboard.setData(ClipboardData(text: _deliveryUrl!));
                          setState(() => _deliveryUrlCopied = true);
                          Future.delayed(const Duration(seconds: 2), () {
                            if (mounted) setState(() => _deliveryUrlCopied = false);
                          });
                        },
                        icon: Icon(_deliveryUrlCopied ? Icons.check : Icons.copy, size: 13),
                        label: Text(_deliveryUrlCopied ? 'Copied!' : 'Copy Link',
                            style: const TextStyle(fontSize: 12)),
                        style: OutlinedButton.styleFrom(
                          foregroundColor: _deliveryUrlCopied ? AppColors.success : AppColors.textSecondary,
                          side: BorderSide(color: AppColors.border),
                          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ],
          if (_issuedAcdcJson != null && _issuedAcdcJson!.isNotEmpty) ...[
            const SizedBox(height: 10),
            OutlinedButton.icon(
              onPressed: () => Clipboard.setData(ClipboardData(text: _issuedAcdcJson!)),
              icon: const Icon(Icons.copy, size: 14),
              label: const Text('Copy ACDC JSON', style: TextStyle(fontSize: 12)),
              style: OutlinedButton.styleFrom(
                foregroundColor: AppColors.textSecondary,
                side: BorderSide(color: AppColors.border),
              ),
            ),
          ],
        ],
      ),
    );
  }

  List<Widget> _buildActions() {
    if (_step == 0) {
      return [
        TextButton(onPressed: () => Navigator.pop(context),
            child: Text('Cancel', style: TextStyle(color: AppColors.textSecondary))),
      ];
    }
    if (_step == 1) {
      return [
        TextButton(onPressed: () => setState(() { _step = 0; _error = null; }),
            child: Text('Back', style: TextStyle(color: AppColors.textSecondary))),
        ElevatedButton(
          onPressed: () => setState(() { _step = 2; _error = null; }),
          style: ElevatedButton.styleFrom(backgroundColor: AppColors.primary, foregroundColor: Colors.white,
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6))),
          child: const Text('Next: Choose Recipient'),
        ),
      ];
    }
    if (_step == 2) {
      final canIssue = _contact != null || _shareExternally;
      return [
        TextButton(onPressed: () => setState(() { _step = 1; _error = null; }),
            child: Text('Back', style: TextStyle(color: AppColors.textSecondary))),
        ElevatedButton(
          onPressed: (!canIssue || _issuing) ? null : _issue,
          style: ElevatedButton.styleFrom(backgroundColor: AppColors.success, foregroundColor: Colors.white,
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6))),
          child: _issuing
              ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
              : Text(_shareExternally ? 'Issue & Share' : 'Issue Credential'),
        ),
      ];
    }
    // Step 3: success
    return [
      ElevatedButton(
        onPressed: widget.onIssued,
        style: ElevatedButton.styleFrom(backgroundColor: AppColors.primary, foregroundColor: Colors.white,
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6))),
        child: const Text('Done'),
      ),
    ];
  }
}

class _SchemaOption extends StatelessWidget {
  final BuiltinSchema schema;
  final VoidCallback onTap;
  const _SchemaOption({required this.schema, required this.onTap});

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(8),
      child: Container(
        margin: const EdgeInsets.only(bottom: 8),
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          border: Border.all(color: AppColors.border),
          borderRadius: BorderRadius.circular(8),
          color: AppColors.surfaceLight,
        ),
        child: Row(
          children: [
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(schema.name,
                      style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w600,
                          color: AppColors.textPrimary)),
                  const SizedBox(height: 2),
                  Text(schema.description,
                      style: TextStyle(fontSize: 12, color: AppColors.textMuted),
                      maxLines: 2, overflow: TextOverflow.ellipsis),
                ],
              ),
            ),
            const Icon(Icons.chevron_right, size: 18, color: AppColors.textMuted),
          ],
        ),
      ),
    );
  }
}

class _StepIndicator extends StatelessWidget {
  final int current;
  final int total;
  const _StepIndicator({required this.current, required this.total});

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: List.generate(total, (i) => Container(
        width: 6, height: 6,
        margin: const EdgeInsets.only(left: 4),
        decoration: BoxDecoration(
          shape: BoxShape.circle,
          color: i < current ? AppColors.primary : AppColors.border,
        ),
      )),
    );
  }
}
