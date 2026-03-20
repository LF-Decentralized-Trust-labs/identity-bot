import 'package:flutter/material.dart';
import 'dart:io' show Platform;
import 'package:flutter/foundation.dart' show kIsWeb;
import '../theme/app_theme.dart';
import '../services/core_service.dart';
import '../services/keri_service.dart';
import '../services/mobile_on_device_keri_service.dart';
import '../widgets/consent_modal.dart';
import 'qr_scanner_screen.dart';

class ContactsScreen extends StatefulWidget {
  final KeriService keriService;
  final String? serverUrl;

  const ContactsScreen({super.key, required this.keriService, this.serverUrl});

  @override
  State<ContactsScreen> createState() => _ContactsScreenState();
}

class _ContactsScreenState extends State<ContactsScreen> {
  late final CoreService _coreService = CoreService(baseUrl: _resolveServerUrl());

  String? _resolveServerUrl() {
    if (widget.serverUrl != null) return widget.serverUrl;
    if (widget.keriService is MobileOnDeviceKeriService) {
      final standalone = widget.keriService as MobileOnDeviceKeriService;
      if (standalone.isCoreReady) {
        return standalone.mobileCore.baseUrl;
      }
    }
    return null;
  }
  List<ContactResponse> _contacts = [];
  bool _loading = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _loadContacts();
  }

  @override
  void dispose() {
    _coreService.dispose();
    super.dispose();
  }

  Future<void> _loadContacts() async {
    setState(() {
      _loading = true;
      _error = null;
    });

    try {
      final result = await _coreService.getContacts();
      setState(() {
        _contacts = result.contacts;
        _loading = false;
      });
    } catch (e) {
      setState(() {
        _error = e.toString();
        _loading = false;
      });
    }
  }

  Future<void> _deleteContact(String aid) async {
    try {
      await _coreService.deleteContact(aid);
      _loadContacts();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              'Failed to delete contact: ${e.toString()}',
              style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
            ),
            backgroundColor: AppColors.error,
          ),
        );
      }
    }
  }

  bool get _isMobilePlatform {
    if (kIsWeb) return false;
    try {
      return Platform.isIOS || Platform.isAndroid;
    } catch (_) {
      return false;
    }
  }

  void _openQrScanner() {
    Navigator.of(context).push(
      MaterialPageRoute(
        builder: (context) => QrScannerScreen(
          onScanned: (scannedData) {
            Navigator.of(context).pop();
            _showAddContactDialog(prefillOobiUrl: scannedData);
          },
        ),
      ),
    );
  }

  void _showAddContactDialog({String? prefillOobiUrl}) {
    final oobiController = TextEditingController(text: prefillOobiUrl ?? '');
    bool isResolving = false;
    String? resolveError;

    showDialog(
      context: context,
      builder: (context) {
        return StatefulBuilder(
          builder: (context, setDialogState) {
            return Dialog(
              backgroundColor: AppColors.surface,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(16),
                side: const BorderSide(color: AppColors.border, width: 1),
              ),
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        const Icon(Icons.link, color: AppColors.textMuted, size: 18),
                        const SizedBox(width: 8),
                        const Text(
                          'RESOLVE OOBI',
                          style: TextStyle(
                            color: AppColors.textMuted,
                            fontSize: 11,
                            fontWeight: FontWeight.w600,
                            letterSpacing: 1.5,
                            fontFamily: 'monospace',
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 6),
                    const Text(
                      'Enter an identity link to verify before adding',
                      style: TextStyle(
                        color: AppColors.textSecondary,
                        fontSize: 10,
                        fontFamily: 'monospace',
                      ),
                    ),
                    const SizedBox(height: 20),
                    const Text(
                      'OOBI URL',
                      style: TextStyle(
                        color: AppColors.textMuted,
                        fontSize: 10,
                        fontWeight: FontWeight.w600,
                        letterSpacing: 1.0,
                        fontFamily: 'monospace',
                      ),
                    ),
                    const SizedBox(height: 8),
                    TextField(
                      controller: oobiController,
                      style: const TextStyle(
                        color: AppColors.accent,
                        fontSize: 12,
                        fontFamily: 'monospace',
                      ),
                      decoration: InputDecoration(
                        hintText: 'Paste OOBI URL here...',
                        hintStyle: TextStyle(
                          color: AppColors.textMuted.withOpacity(0.5),
                          fontSize: 12,
                          fontFamily: 'monospace',
                        ),
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
                          borderSide: const BorderSide(color: AppColors.accent),
                        ),
                        contentPadding: const EdgeInsets.all(12),
                      ),
                    ),
                    if (resolveError != null) ...[
                      const SizedBox(height: 10),
                      Row(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Icon(Icons.error_outline, color: AppColors.error, size: 14),
                          const SizedBox(width: 6),
                          Expanded(
                            child: Text(
                              resolveError!,
                              style: const TextStyle(
                                color: AppColors.error,
                                fontSize: 10,
                                fontFamily: 'monospace',
                              ),
                            ),
                          ),
                        ],
                      ),
                    ],
                    const SizedBox(height: 24),
                    Row(
                      mainAxisAlignment: MainAxisAlignment.end,
                      children: [
                        InkWell(
                          onTap: () => Navigator.of(context).pop(),
                          borderRadius: BorderRadius.circular(8),
                          child: Container(
                            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                            decoration: BoxDecoration(
                              color: AppColors.surfaceLight,
                              borderRadius: BorderRadius.circular(8),
                            ),
                            child: const Text(
                              'CANCEL',
                              style: TextStyle(
                                color: AppColors.textSecondary,
                                fontSize: 11,
                                fontWeight: FontWeight.w600,
                                letterSpacing: 1.0,
                                fontFamily: 'monospace',
                              ),
                            ),
                          ),
                        ),
                        const SizedBox(width: 12),
                        InkWell(
                          onTap: isResolving
                              ? null
                              : () async {
                                  final oobiUrl = oobiController.text.trim();
                                  if (oobiUrl.isEmpty) return;

                                  setDialogState(() {
                                    isResolving = true;
                                    resolveError = null;
                                  });

                                  try {
                                    final resolved = await _coreService.resolveOobiContact(oobiUrl: oobiUrl);
                                    if (!mounted) return;
                                    Navigator.of(context).pop();
                                    _showConsentModal(resolved);
                                  } catch (e) {
                                    setDialogState(() {
                                      isResolving = false;
                                      resolveError = e.toString().replaceFirst('Exception: ', '');
                                    });
                                  }
                                },
                          borderRadius: BorderRadius.circular(8),
                          child: Container(
                            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                            decoration: BoxDecoration(
                              color: isResolving
                                  ? AppColors.accent.withOpacity(0.3)
                                  : AppColors.accent.withOpacity(0.15),
                              borderRadius: BorderRadius.circular(8),
                              border: Border.all(
                                color: AppColors.accent.withOpacity(0.3),
                                width: 1,
                              ),
                            ),
                            child: isResolving
                                ? const SizedBox(
                                    width: 14,
                                    height: 14,
                                    child: CircularProgressIndicator(
                                      strokeWidth: 2,
                                      color: AppColors.accent,
                                    ),
                                  )
                                : const Text(
                                    'RESOLVE',
                                    style: TextStyle(
                                      color: AppColors.accent,
                                      fontSize: 11,
                                      fontWeight: FontWeight.w600,
                                      letterSpacing: 1.0,
                                      fontFamily: 'monospace',
                                    ),
                                  ),
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
      },
    );
  }

  Future<void> _showConsentModal(ResolvedContactResponse resolved) async {
    final aidShort = resolved.aid.length > 20
        ? '${resolved.aid.substring(0, 20)}...'
        : resolved.aid;
    final avatarInitial = resolved.alias.isNotEmpty
        ? resolved.alias[0].toUpperCase()
        : null;

    final confirmed = await ConsentModal.show(
      context: context,
      title: 'ADD CONTACT',
      subtitle: 'Verify identity before adding to trusted contacts',
      name: resolved.displayName,
      avatarLabel: avatarInitial,
      icon: Icons.person_add_outlined,
      details: [
        ConsentDetailItem(
          label: 'AID',
          value: resolved.aid,
          isSelectable: true,
        ),
        ConsentDetailItem(
          label: 'Public Key',
          value: resolved.publicKey,
          isSelectable: true,
        ),
        ConsentDetailItem(
          label: 'OOBI Endpoint',
          value: resolved.oobiUrl,
          isSelectable: true,
        ),
        ConsentDetailItem(
          label: 'KEL Events',
          value: '${resolved.eventCount} event${resolved.eventCount != 1 ? 's' : ''} ${resolved.kelVerified ? '(verified)' : '(unverified)'}',
          isMonospace: true,
          isSelectable: false,
        ),
        if (resolved.created.isNotEmpty)
          ConsentDetailItem(
            label: 'Created',
            value: resolved.created,
            isMonospace: false,
          ),
      ],
      confirmLabel: 'ADD CONTACT',
      warningMessage: !resolved.kelVerified
          ? 'Key Event Log could not be verified. Proceed with caution.'
          : null,
    );

    if (confirmed == true && mounted) {
      try {
        await _coreService.addContact(
          oobiUrl: resolved.oobiUrl,
          alias: resolved.alias.isNotEmpty ? resolved.alias : null,
        );
        _loadContacts();
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(
                'Contact ${resolved.displayName} added',
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              ),
              backgroundColor: AppColors.coreActive,
            ),
          );
        }
      } catch (e) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(
                e.toString().replaceFirst('Exception: ', ''),
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              ),
              backgroundColor: AppColors.error,
            ),
          );
        }
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildHeader(),
            Expanded(
              child: _loading
                  ? Center(
                      child: SizedBox(
                        width: 30,
                        height: 30,
                        child: CircularProgressIndicator(
                          strokeWidth: 2,
                          color: AppColors.accent,
                        ),
                      ),
                    )
                  : _error != null
                      ? _buildErrorState()
                      : _contacts.isEmpty
                          ? _buildEmptyState()
                          : _buildContactsList(),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildHeader() {
    return Container(
      padding: const EdgeInsets.fromLTRB(20, 16, 20, 16),
      child: Row(
        children: [
          Container(
            width: 36,
            height: 36,
            decoration: BoxDecoration(
              color: AppColors.accent.withOpacity(0.15),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(
                color: AppColors.accent.withOpacity(0.3),
                width: 1,
              ),
            ),
            child: const Icon(
              Icons.people_outlined,
              color: AppColors.accent,
              size: 20,
            ),
          ),
          const SizedBox(width: 12),
          const Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'CONTACTS',
                style: TextStyle(
                  color: AppColors.textPrimary,
                  fontSize: 16,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 2.0,
                  fontFamily: 'monospace',
                ),
              ),
              Text(
                'TRUSTED IDENTIFIERS',
                style: TextStyle(
                  color: AppColors.textMuted,
                  fontSize: 10,
                  fontWeight: FontWeight.w500,
                  letterSpacing: 1.5,
                  fontFamily: 'monospace',
                ),
              ),
            ],
          ),
          const Spacer(),
          InkWell(
            onTap: _loadContacts,
            borderRadius: BorderRadius.circular(6),
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
              decoration: BoxDecoration(
                color: AppColors.surfaceLight,
                borderRadius: BorderRadius.circular(6),
              ),
              child: const Icon(Icons.refresh, color: AppColors.textSecondary, size: 18),
            ),
          ),
          if (_isMobilePlatform) ...[
            const SizedBox(width: 8),
            InkWell(
              onTap: _openQrScanner,
              borderRadius: BorderRadius.circular(6),
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                decoration: BoxDecoration(
                  color: AppColors.accent.withOpacity(0.15),
                  borderRadius: BorderRadius.circular(6),
                  border: Border.all(
                    color: AppColors.accent.withOpacity(0.3),
                    width: 1,
                  ),
                ),
                child: const Icon(Icons.qr_code_scanner, color: AppColors.accent, size: 18),
              ),
            ),
          ],
          const SizedBox(width: 8),
          InkWell(
            onTap: () => _showAddContactDialog(),
            borderRadius: BorderRadius.circular(6),
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
              decoration: BoxDecoration(
                color: AppColors.accent.withOpacity(0.15),
                borderRadius: BorderRadius.circular(6),
                border: Border.all(
                  color: AppColors.accent.withOpacity(0.3),
                  width: 1,
                ),
              ),
              child: const Icon(Icons.add, color: AppColors.accent, size: 18),
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
          Icon(
            Icons.people_outline,
            color: AppColors.textMuted.withOpacity(0.5),
            size: 48,
          ),
          const SizedBox(height: 16),
          const Text(
            'NO CONTACTS YET',
            style: TextStyle(
              color: AppColors.textMuted,
              fontSize: 13,
              fontWeight: FontWeight.w600,
              letterSpacing: 1.5,
              fontFamily: 'monospace',
            ),
          ),
          const SizedBox(height: 8),
          const Text(
            'Add a contact by resolving their OOBI URL',
            style: TextStyle(
              color: AppColors.textMuted,
              fontSize: 11,
              fontFamily: 'monospace',
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildErrorState() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.error_outline, color: AppColors.coreInactive, size: 40),
            const SizedBox(height: 16),
            const Text(
              'FAILED TO LOAD CONTACTS',
              style: TextStyle(
                color: AppColors.coreInactive,
                fontSize: 13,
                fontWeight: FontWeight.w600,
                letterSpacing: 1.5,
                fontFamily: 'monospace',
              ),
            ),
            const SizedBox(height: 8),
            Text(
              _error ?? '',
              style: const TextStyle(
                color: AppColors.textMuted,
                fontSize: 11,
                fontFamily: 'monospace',
              ),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildContactsList() {
    final mutualCount = _contacts.where((c) => c.isMutual).length;
    final pendingCount = _contacts.where((c) => c.isPendingOutbound || c.isPendingInbound).length;

    return SingleChildScrollView(
      padding: const EdgeInsets.symmetric(horizontal: 20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const SizedBox(height: 8),
          Row(
            children: [
              Text(
                '${_contacts.length} CONTACT${_contacts.length == 1 ? '' : 'S'}',
                style: const TextStyle(
                  color: AppColors.textMuted,
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  letterSpacing: 1.5,
                  fontFamily: 'monospace',
                ),
              ),
              if (mutualCount > 0) ...[
                const SizedBox(width: 10),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                  decoration: BoxDecoration(
                    color: AppColors.coreActive.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: Text(
                    '$mutualCount MUTUAL',
                    style: const TextStyle(
                      color: AppColors.coreActive,
                      fontSize: 9,
                      fontWeight: FontWeight.w600,
                      letterSpacing: 0.5,
                      fontFamily: 'monospace',
                    ),
                  ),
                ),
              ],
              if (pendingCount > 0) ...[
                const SizedBox(width: 6),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                  decoration: BoxDecoration(
                    color: AppColors.corePending.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: Text(
                    '$pendingCount PENDING',
                    style: const TextStyle(
                      color: AppColors.corePending,
                      fontSize: 9,
                      fontWeight: FontWeight.w600,
                      letterSpacing: 0.5,
                      fontFamily: 'monospace',
                    ),
                  ),
                ),
              ],
            ],
          ),
          const SizedBox(height: 12),
          ..._contacts.map((contact) => Padding(
                padding: const EdgeInsets.only(bottom: 12),
                child: _buildContactCard(contact),
              )),
          const SizedBox(height: 24),
        ],
      ),
    );
  }

  Color _statusColor(ContactResponse contact) {
    if (contact.isMutual) return AppColors.coreActive;
    if (contact.isPendingInbound || contact.isPendingOutbound) return AppColors.corePending;
    if (contact.isRejected) return AppColors.coreInactive;
    return AppColors.textMuted;
  }

  String _statusLabel(ContactResponse contact) {
    if (contact.isMutual) return 'MUTUAL';
    if (contact.isPendingOutbound) return 'PENDING';
    if (contact.isPendingInbound) return 'INCOMING';
    if (contact.isRejected) return 'REJECTED';
    return contact.verified ? 'VERIFIED' : 'UNVERIFIED';
  }

  IconData _statusIcon(ContactResponse contact) {
    if (contact.isMutual) return Icons.handshake_outlined;
    if (contact.isPendingOutbound) return Icons.call_made;
    if (contact.isPendingInbound) return Icons.call_received;
    if (contact.isRejected) return Icons.block;
    return Icons.person_outlined;
  }

  Widget _buildContactAvatar(ContactResponse contact) {
    final statusColor = _statusColor(contact);
    final initial = contact.displayName.isNotEmpty
        ? contact.displayName[0].toUpperCase()
        : '?';

    return Container(
      width: 40,
      height: 40,
      decoration: BoxDecoration(
        color: statusColor.withOpacity(0.12),
        border: Border.all(color: statusColor.withOpacity(0.25), width: 1.5),
        borderRadius: BorderRadius.circular(20),
      ),
      child: Center(
        child: Text(
          initial,
          style: TextStyle(
            color: statusColor,
            fontSize: 16,
            fontWeight: FontWeight.w600,
            fontFamily: 'monospace',
          ),
        ),
      ),
    );
  }

  Widget _buildContactCard(ContactResponse contact) {
    final aidDisplay = contact.aid.length > 16
        ? contact.aid.substring(0, 16)
        : contact.aid;
    final displayName = contact.alias.isNotEmpty ? contact.alias : 'Unknown Contact';
    final statusColor = _statusColor(contact);
    final borderColor = contact.isMutual 
        ? AppColors.coreActive.withOpacity(0.3) 
        : AppColors.border;

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: AppColors.surface,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: borderColor, width: 1),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              _buildContactAvatar(contact),
              const SizedBox(width: 10),
              Expanded(
                child: Text(
                  displayName,
                  style: const TextStyle(
                    color: AppColors.textPrimary,
                    fontSize: 14,
                    fontWeight: FontWeight.w600,
                    fontFamily: 'monospace',
                    letterSpacing: 0.5,
                  ),
                ),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  color: statusColor.withOpacity(0.12),
                  borderRadius: BorderRadius.circular(4),
                ),
                child: Text(
                  _statusLabel(contact),
                  style: TextStyle(
                    color: statusColor,
                    fontSize: 9,
                    fontWeight: FontWeight.w700,
                    letterSpacing: 1.0,
                    fontFamily: 'monospace',
                  ),
                ),
              ),
              const SizedBox(width: 8),
              InkWell(
                onTap: () => _deleteContact(contact.aid),
                borderRadius: BorderRadius.circular(4),
                child: Container(
                  padding: const EdgeInsets.all(4),
                  child: const Icon(
                    Icons.delete_outline,
                    color: AppColors.textMuted,
                    size: 16,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            aidDisplay,
            style: const TextStyle(
              color: AppColors.accent,
              fontSize: 12,
              fontWeight: FontWeight.w600,
              fontFamily: 'monospace',
              letterSpacing: 0.5,
            ),
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
                  contact.role.toUpperCase(),
                  style: const TextStyle(
                    color: AppColors.accent,
                    fontSize: 9,
                    fontWeight: FontWeight.w600,
                    letterSpacing: 1.0,
                    fontFamily: 'monospace',
                  ),
                ),
              ),
              const Spacer(),
              const Icon(Icons.access_time, color: AppColors.textMuted, size: 12),
              const SizedBox(width: 6),
              Text(
                contact.discoveredAt.isNotEmpty
                    ? contact.discoveredAt
                    : 'Unknown',
                style: const TextStyle(
                  color: AppColors.textMuted,
                  fontSize: 10,
                  fontFamily: 'monospace',
                ),
              ),
            ],
          ),
          if (contact.isPendingInbound) ...[
            const SizedBox(height: 10),
            Row(
              mainAxisAlignment: MainAxisAlignment.end,
              children: [
                InkWell(
                  onTap: () async {
                    try {
                      await _coreService.rejectContact(contact.aid);
                      _loadContacts();
                    } catch (e) {
                      if (mounted) {
                        ScaffoldMessenger.of(context).showSnackBar(
                          SnackBar(content: Text(e.toString()), backgroundColor: AppColors.error),
                        );
                      }
                    }
                  },
                  borderRadius: BorderRadius.circular(6),
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                    decoration: BoxDecoration(
                      color: AppColors.coreInactive.withOpacity(0.1),
                      borderRadius: BorderRadius.circular(6),
                      border: Border.all(color: AppColors.coreInactive.withOpacity(0.3)),
                    ),
                    child: const Text(
                      'REJECT',
                      style: TextStyle(
                        color: AppColors.coreInactive,
                        fontSize: 9,
                        fontWeight: FontWeight.w700,
                        letterSpacing: 1.0,
                        fontFamily: 'monospace',
                      ),
                    ),
                  ),
                ),
                const SizedBox(width: 8),
                InkWell(
                  onTap: () async {
                    try {
                      await _coreService.acceptContact(contact.aid);
                      _loadContacts();
                    } catch (e) {
                      if (mounted) {
                        ScaffoldMessenger.of(context).showSnackBar(
                          SnackBar(content: Text(e.toString()), backgroundColor: AppColors.error),
                        );
                      }
                    }
                  },
                  borderRadius: BorderRadius.circular(6),
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                    decoration: BoxDecoration(
                      color: AppColors.coreActive.withOpacity(0.15),
                      borderRadius: BorderRadius.circular(6),
                      border: Border.all(color: AppColors.coreActive.withOpacity(0.3)),
                    ),
                    child: const Text(
                      'ACCEPT',
                      style: TextStyle(
                        color: AppColors.coreActive,
                        fontSize: 9,
                        fontWeight: FontWeight.w700,
                        letterSpacing: 1.0,
                        fontFamily: 'monospace',
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ],
        ],
      ),
    );
  }
}
