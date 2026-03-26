import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'dart:io' show Platform;
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:qr_flutter/qr_flutter.dart';
import '../theme/app_theme.dart';
import '../services/core_service.dart';
import '../services/keri_service.dart';
import '../services/mobile_on_device_keri_service.dart';
import '../widgets/consent_modal.dart';
import '../services/identity_level_service.dart';
import '../services/setup_task_service.dart';
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
  List<GuardianshipResponse> _guardianships = [];
  ContactResponse? _selectedContact;
  bool _loading = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _loadContacts();
    _loadGuardianships();
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
        // Refresh selected contact if it still exists
        if (_selectedContact != null) {
          final stillExists = _contacts.where((c) => c.aid == _selectedContact!.aid);
          _selectedContact = stillExists.isNotEmpty ? stillExists.first : null;
        }
      });
      _syncWitnessCount(result.contacts);
    } catch (e) {
      setState(() {
        _error = e.toString();
        _loading = false;
      });
    }
  }

  Future<void> _loadGuardianships() async {
    try {
      final resp = await _coreService.getGuardianships();
      if (mounted) setState(() => _guardianships = resp.guardianships);
    } catch (_) {
      // Guardianship labels are optional — don't block contacts
    }
  }

  String? _guardianshipLabel(ContactResponse contact) {
    for (final g in _guardianships) {
      if (g.dependentAid == contact.aid) {
        return 'You are guardian of ${g.dependentName}';
      }
      if (g.guardianAid == contact.aid) {
        return '${contact.alias.isNotEmpty ? contact.alias : "This contact"} is your guardian';
      }
      if (g.coGuardians.contains(contact.aid)) {
        return 'Co-guardian with you for ${g.dependentName}';
      }
    }
    return null;
  }

  /// Counts mutual contacts with role "witness" and updates the Identity Level tier.
  void _syncWitnessCount(List<ContactResponse> contacts) {
    final count = contacts.where((c) => c.isAccepted && c.isWitness).length;
    IdentityLevelService.setWitnessCount(count);
  }

  /// Shows a contact-type picker dialog and returns the chosen type, or null if cancelled.
  Future<String?> _pickRole(BuildContext context, {String initial = 'general'}) async {
    String selected = initial;
    return showDialog<String>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setS) => AlertDialog(
          backgroundColor: AppColors.surface,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
            side: BorderSide(color: AppColors.border),
          ),
          title: const Text(
            'CONTACT TYPE',
            style: TextStyle(
              color: AppColors.textPrimary,
              fontSize: 13,
              fontWeight: FontWeight.w700,
              letterSpacing: 1.0,
              fontFamily: 'monospace',
            ),
          ),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Text(
                'Choose your relationship with this contact.',
                style: TextStyle(
                  color: AppColors.textSecondary,
                  fontSize: 12,
                  fontFamily: 'monospace',
                ),
              ),
              const SizedBox(height: 16),
              for (final type in ['general', 'trusted', 'professional'])
                RadioListTile<String>(
                  value: type,
                  groupValue: selected,
                  onChanged: (v) => setS(() => selected = v!),
                  title: Text(
                    type == 'general'      ? 'General — acquaintance or casual contact' :
                    type == 'trusted'      ? 'Trusted — someone you personally know and trust' :
                                            'Professional — colleague or professional connection',
                    style: const TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 12,
                      fontFamily: 'monospace',
                    ),
                  ),
                  activeColor: AppColors.accent,
                  dense: true,
                ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(null),
              child: const Text('CANCEL', style: TextStyle(color: AppColors.textMuted, fontFamily: 'monospace')),
            ),
            ElevatedButton(
              onPressed: () => Navigator.of(ctx).pop(selected),
              style: ElevatedButton.styleFrom(
                backgroundColor: AppColors.accent,
                foregroundColor: Colors.white,
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
              ),
              child: const Text('CONFIRM', style: TextStyle(fontFamily: 'monospace')),
            ),
          ],
        ),
      ),
    );
  }

  Future<void> _acceptWithRole(ContactResponse contact) async {
    String selectedRole = 'general';
    bool trusted = false;

    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setS) => AlertDialog(
          backgroundColor: AppColors.surface,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
            side: BorderSide(color: AppColors.border),
          ),
          title: Text(
            'ACCEPT ${contact.displayName.toUpperCase()}',
            style: const TextStyle(
              color: AppColors.textPrimary,
              fontSize: 13,
              fontWeight: FontWeight.w700,
              letterSpacing: 1.0,
              fontFamily: 'monospace',
            ),
          ),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Trust toggle
              InkWell(
                onTap: () => setS(() { trusted = !trusted; }),
                borderRadius: BorderRadius.circular(8),
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
                  decoration: BoxDecoration(
                    color: trusted
                        ? AppColors.coreActive.withOpacity(0.08)
                        : AppColors.surfaceLight,
                    border: Border.all(
                      color: trusted
                          ? AppColors.coreActive.withOpacity(0.4)
                          : AppColors.border,
                    ),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Row(
                    children: [
                      Checkbox(
                        value: trusted,
                        onChanged: (v) => setS(() { trusted = v!; }),
                        activeColor: AppColors.coreActive,
                        materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
                        visualDensity: VisualDensity.compact,
                      ),
                      const SizedBox(width: 6),
                      const Expanded(
                        child: Text(
                          'I know and trust this contact',
                          style: TextStyle(
                            color: AppColors.textPrimary,
                            fontSize: 12,
                            fontFamily: 'monospace',
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 16),
              const Text(
                'CONTACT TYPE',
                style: TextStyle(
                  color: AppColors.textMuted,
                  fontSize: 10,
                  fontWeight: FontWeight.w600,
                  letterSpacing: 1.0,
                  fontFamily: 'monospace',
                ),
              ),
              for (final type in ['general', 'trusted', 'professional'])
                RadioListTile<String>(
                  value: type,
                  groupValue: selectedRole,
                  onChanged: (v) => setS(() => selectedRole = v!),
                  title: Text(
                    type == 'general'
                        ? 'General — acquaintance or casual contact'
                        : type == 'trusted'
                            ? 'Trusted — someone you personally know and trust'
                            : 'Professional — colleague or professional connection',
                    style: const TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 12,
                      fontFamily: 'monospace',
                    ),
                  ),
                  activeColor: AppColors.accent,
                  dense: true,
                  contentPadding: EdgeInsets.zero,
                ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(null),
              child: const Text('CANCEL',
                  style: TextStyle(color: AppColors.textMuted, fontFamily: 'monospace')),
            ),
            ElevatedButton(
              onPressed: () => Navigator.of(ctx).pop(true),
              style: ElevatedButton.styleFrom(
                backgroundColor: AppColors.accent,
                foregroundColor: Colors.white,
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
              ),
              child: const Text('ACCEPT', style: TextStyle(fontFamily: 'monospace')),
            ),
          ],
        ),
      ),
    );

    if (confirmed != true || !mounted) return;
    try {
      final finalType = trusted ? 'trusted' : selectedRole;
      await _coreService.acceptContact(contact.aid, contactType: finalType);
      if (finalType == 'trusted') {
        // trusted contact acknowledged
      }
      _loadContacts();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(e.toString()), backgroundColor: AppColors.error),
        );
      }
    }
  }

  Future<void> _changeRole(ContactResponse contact) async {
    final role = await _pickRole(context, initial: contact.contactType);
    if (role == null || !mounted) return;
    try {
      await _coreService.updateContact(contact.aid, contactType: role);
      _loadContacts();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text(e.toString()), backgroundColor: AppColors.error),
        );
      }
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

  bool get _isMobileLayout {
    final isNarrowScreen = MediaQuery.of(context).size.width < 768;
    return _isMobilePlatform || isNarrowScreen;
  }

  Future<void> _showShareDialog() async {
    try {
      final oobi = await _coreService.getOobi();
      if (!mounted) return;
      if (_isMobileLayout) {
        Navigator.of(context).push(
          MaterialPageRoute(builder: (_) => _ContactsShareScreen(oobi: oobi)),
        );
      } else {
        showDialog(
          context: context,
          builder: (_) => _DesktopAddContactDialog(
            oobi: oobi,
            coreService: _coreService,
            onResolved: (resolved) {
              Navigator.of(context).pop();
              _showConsentModal(resolved);
            },
          ),
        );
      }
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Could not load OOBI: ${e.toString().split(': ').last}'),
            backgroundColor: AppColors.error),
      );
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
    final avatarInitial = resolved.alias.isNotEmpty
        ? resolved.alias[0].toUpperCase()
        : null;

    final result = await ConsentModal.show(
      context: context,
      title: 'ADD CONTACT',
      subtitle: 'Review their identity before adding',
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
      showTrustToggle: true,
    );

    if (result?.confirmed == true && mounted) {
      try {
        await _coreService.addContact(
          oobiUrl: resolved.oobiUrl,
          alias: resolved.alias.isNotEmpty ? resolved.alias : null,
          trusted: result!.trusted,
        );
        if (result.trusted == true) {
          // trusted contact added
        }
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
                  ? const Center(
                      child: CircularProgressIndicator(color: AppColors.accent),
                    )
                  : _error != null
                      ? _buildErrorState()
                      : _contacts.isEmpty
                          ? _buildEmptyState()
                          : _isMobileLayout
                              ? _buildContactsList()
                              : _buildDesktopLayout(),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildDesktopLayout() {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Container(
          width: 320,
          decoration: const BoxDecoration(
            border: Border(right: BorderSide(color: AppColors.border)),
          ),
          child: _buildContactsPanelList(),
        ),
        Expanded(
          child: _selectedContact != null
              ? _buildDetailPanel(_selectedContact!)
              : _buildSelectContactHint(),
        ),
      ],
    );
  }

  Widget _buildContactsPanelList() {
    return ListView.builder(
      padding: const EdgeInsets.symmetric(vertical: 8),
      itemCount: _contacts.length,
      itemBuilder: (context, i) {
        final contact = _contacts[i];
        final isSelected = _selectedContact?.aid == contact.aid;
        return _buildContactRow(contact, isSelected);
      },
    );
  }

  Widget _buildContactRow(ContactResponse contact, bool isSelected) {
    final statusColor = _statusColor(contact);
    final displayName = contact.alias.isNotEmpty ? contact.alias : 'Unknown Contact';
    return InkWell(
      onTap: () => setState(() => _selectedContact = contact),
      child: Container(
        color: isSelected ? AppColors.accent.withOpacity(0.08) : null,
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
        child: Row(
          children: [
            _buildContactAvatar(contact),
            const SizedBox(width: 10),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    displayName,
                    style: const TextStyle(
                      color: AppColors.textPrimary,
                      fontSize: 14,
                      fontWeight: FontWeight.w600,
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                  const SizedBox(height: 2),
                  Text(
                    contact.aid.length > 14 ? '${contact.aid.substring(0, 14)}…' : contact.aid,
                    style: const TextStyle(
                      color: AppColors.textMuted,
                      fontSize: 11,
                      fontFamily: 'monospace',
                    ),
                  ),
                ],
              ),
            ),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
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
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildDetailPanel(ContactResponse contact) {
    final statusColor = _statusColor(contact);
    final displayName = contact.alias.isNotEmpty ? contact.alias : 'Unknown Contact';
    final initial = displayName.isNotEmpty ? displayName[0].toUpperCase() : '?';
    return SingleChildScrollView(
      padding: const EdgeInsets.all(32),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 64,
                height: 64,
                decoration: BoxDecoration(
                  color: statusColor.withOpacity(0.12),
                  border: Border.all(color: statusColor.withOpacity(0.3), width: 2),
                  borderRadius: BorderRadius.circular(32),
                ),
                child: Center(
                  child: Text(
                    initial,
                    style: TextStyle(
                      color: statusColor,
                      fontSize: 24,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      displayName,
                      style: const TextStyle(
                        color: AppColors.textPrimary,
                        fontSize: 20,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    const SizedBox(height: 4),
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
                          fontSize: 11,
                          fontWeight: FontWeight.w600,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 24),
          const Divider(color: AppColors.border),
          const SizedBox(height: 16),
          _buildDetailField('Autonomous Identifier', contact.aid, monospace: true, selectable: true),
          const SizedBox(height: 16),
          const Divider(color: AppColors.border),
          const SizedBox(height: 12),

          // ── Contact Type dropdown ──────────────────────────────────────────
          const Text(
            'Contact Type',
            style: TextStyle(color: AppColors.textSecondary, fontSize: 12, fontWeight: FontWeight.w500),
          ),
          const SizedBox(height: 6),
          DropdownButtonHideUnderline(
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
              decoration: BoxDecoration(
                color: AppColors.surfaceLight,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: AppColors.border),
              ),
              child: DropdownButton<String>(
                value: contact.contactType,
                dropdownColor: AppColors.surface,
                isDense: true,
                style: const TextStyle(color: AppColors.textPrimary, fontSize: 13),
                icon: const Icon(Icons.keyboard_arrow_down, color: AppColors.textMuted, size: 18),
                items: const [
                  DropdownMenuItem(value: 'general',      child: Text('General Contact')),
                  DropdownMenuItem(value: 'trusted',      child: Text('Trusted Contact')),
                  DropdownMenuItem(value: 'professional', child: Text('Professional Contact')),
                ],
                onChanged: contact.isPendingInbound ? null : (value) async {
                  if (value == null) return;
                  try {
                    await _coreService.updateContact(contact.aid, contactType: value);
                    // trusted contact updated
                    await _loadContacts();
                  } catch (e) {
                    if (mounted) {
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(content: Text(e.toString()), backgroundColor: AppColors.error),
                      );
                    }
                  }
                },
              ),
            ),
          ),

          // ── Witness badge (auto-managed by backend via KERI witness protocol) ──
          if (contact.isWitness) ...[
            const SizedBox(height: 10),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
              decoration: BoxDecoration(
                color: AppColors.accent.withOpacity(0.1),
                borderRadius: BorderRadius.circular(6),
                border: Border.all(color: AppColors.accent.withOpacity(0.3)),
              ),
              child: const Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(Icons.verified_outlined, size: 13, color: AppColors.accent),
                  SizedBox(width: 5),
                  Text('Witness', style: TextStyle(color: AppColors.accent, fontSize: 11, fontWeight: FontWeight.w600)),
                ],
              ),
            ),
          ],

          const SizedBox(height: 16),
          const Divider(color: AppColors.border),
          const SizedBox(height: 12),

          // ── Other info ───────────────────────────────────────────────────
          _buildDetailField(
            'Discovered',
            contact.discoveredAt.isNotEmpty ? contact.discoveredAt : 'Unknown',
          ),
          const SizedBox(height: 20),

          // ── Actions ───────────────────────────────────────────────────────
          if (contact.isPendingInbound) ...[
            Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                OutlinedButton(
                  onPressed: () async {
                    try {
                      await _coreService.rejectContact(contact.aid);
                      setState(() => _selectedContact = null);
                      _loadContacts();
                    } catch (e) {
                      if (mounted) {
                        ScaffoldMessenger.of(context).showSnackBar(
                          SnackBar(content: Text(e.toString()), backgroundColor: AppColors.error),
                        );
                      }
                    }
                  },
                  style: OutlinedButton.styleFrom(
                    foregroundColor: AppColors.error,
                    side: const BorderSide(color: AppColors.error),
                  ),
                  child: const Text('Reject'),
                ),
                const SizedBox(width: 12),
                ElevatedButton(
                  onPressed: () => _acceptWithRole(contact),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppColors.accent,
                    foregroundColor: Colors.white,
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                  ),
                  child: const Text('Accept'),
                ),
              ],
            ),
            const SizedBox(height: 12),
          ],
          OutlinedButton.icon(
            onPressed: () {
              _deleteContact(contact.aid);
              setState(() => _selectedContact = null);
            },
            icon: const Icon(Icons.delete_outline, size: 16),
            label: const Text('Remove Contact'),
            style: OutlinedButton.styleFrom(
              foregroundColor: AppColors.error,
              side: const BorderSide(color: AppColors.error),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildDetailField(String label, String value, {bool monospace = false, bool selectable = false}) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: const TextStyle(
            color: AppColors.textSecondary,
            fontSize: 12,
            fontWeight: FontWeight.w500,
          ),
        ),
        const SizedBox(height: 4),
        if (selectable)
          SelectableText(
            value,
            style: TextStyle(
              color: AppColors.textPrimary,
              fontSize: 13,
              fontFamily: monospace ? 'monospace' : null,
            ),
          )
        else
          Text(
            value,
            style: TextStyle(
              color: AppColors.textPrimary,
              fontSize: 13,
              fontFamily: monospace ? 'monospace' : null,
            ),
          ),
      ],
    );
  }

  Widget _buildSelectContactHint() {
    return const Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.person_outline, color: AppColors.textMuted, size: 48),
          SizedBox(height: 12),
          Text(
            'Select a contact to view details.',
            style: TextStyle(color: AppColors.textMuted, fontSize: 14),
          ),
        ],
      ),
    );
  }

  Widget _buildHeader() {
    return Padding(
      padding: const EdgeInsets.fromLTRB(32, 32, 32, 0),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('Contacts', style: Theme.of(context).textTheme.headlineMedium),
                const SizedBox(height: 4),
                const Text(
                  'Verified identifiers in your network.',
                  style: TextStyle(color: AppColors.textSecondary, fontSize: 14),
                ),
              ],
            ),
          ),
          IconButton(
            onPressed: _loadContacts,
            icon: const Icon(Icons.refresh),
            color: AppColors.textSecondary,
            tooltip: 'Refresh',
          ),
          if (_isMobilePlatform)
            IconButton(
              onPressed: _openQrScanner,
              icon: const Icon(Icons.qr_code_scanner),
              color: AppColors.accent,
              tooltip: 'Scan QR',
            ),
          const SizedBox(width: 8),
          FilledButton.icon(
            onPressed: _showShareDialog,
            icon: const Icon(Icons.person_add_outlined, size: 16),
            label: const Text('Add Contact',
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
            'No contacts yet',
            style: TextStyle(
              color: AppColors.textMuted,
              fontSize: 14,
              fontWeight: FontWeight.w600,
            ),
          ),
          const SizedBox(height: 8),
          const Text(
            'Add a contact by resolving their OOBI URL.',
            style: TextStyle(
              color: AppColors.textMuted,
              fontSize: 13,
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
              'Failed to load contacts',
              style: TextStyle(
                color: AppColors.coreInactive,
                fontSize: 14,
                fontWeight: FontWeight.w600,
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
    final mutualCount = _contacts.where((c) => c.isAccepted).length;
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
    if (contact.isPendingInbound || contact.isPendingOutbound) return AppColors.corePending;
    if (contact.isRejected) return AppColors.coreInactive;
    if (contact.verified || contact.isAccepted) return AppColors.coreActive;
    return AppColors.textMuted;
  }

  String _statusLabel(ContactResponse contact) {
    if (contact.isPendingOutbound) return 'PENDING';
    if (contact.isPendingInbound) return 'INCOMING';
    if (contact.isRejected) return 'REJECTED';
    return contact.verified || contact.isAccepted ? 'VERIFIED' : 'UNVERIFIED';
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
    final borderColor = contact.isAccepted
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
                  contact.contactType.toUpperCase(),
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
          // Guardianship role label
          if (_guardianshipLabel(contact) != null) ...[
            const SizedBox(height: 6),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
              decoration: BoxDecoration(
                color: AppColors.warning.withOpacity(0.10),
                borderRadius: BorderRadius.circular(4),
                border: Border.all(color: AppColors.warning.withOpacity(0.25)),
              ),
              child: Text(
                _guardianshipLabel(contact)!,
                style: TextStyle(
                  color: AppColors.warning,
                  fontSize: 10,
                  fontWeight: FontWeight.w600,
                ),
              ),
            ),
          ],
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
                  onTap: () => _acceptWithRole(contact),
                  borderRadius: BorderRadius.circular(6),
                  child: Container(
                    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                    decoration: BoxDecoration(
                      color: AppColors.coreActive.withOpacity(0.15),
                      borderRadius: BorderRadius.circular(6),
                      border: Border.all(color: AppColors.coreActive.withOpacity(0.3)),
                    ),
                    child: const Text(
                      'ACCEPT AS...',
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

// ── Share Identity screen ─────────────────────────────────────────────────────

class _ContactsShareScreen extends StatefulWidget {
  final OobiResponse oobi;
  const _ContactsShareScreen({required this.oobi});

  @override
  State<_ContactsShareScreen> createState() => _ContactsShareScreenState();
}

class _ContactsShareScreenState extends State<_ContactsShareScreen> {
  bool _copied = false;

  void _copy() {
    Clipboard.setData(ClipboardData(text: widget.oobi.oobiUrl));
    setState(() => _copied = true);
    Future.delayed(const Duration(seconds: 2), () {
      if (mounted) setState(() => _copied = false);
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.background,
      appBar: AppBar(
        title: const Text('Share My Identity'),
        backgroundColor: AppColors.surface,
        foregroundColor: AppColors.textPrimary,
        elevation: 0,
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Share your OOBI URL so others can verify and add you as a contact.',
              style: TextStyle(color: AppColors.textSecondary, fontSize: 14, height: 1.5),
            ),
            const SizedBox(height: 20),
            const Text('OOBI URL',
                style: TextStyle(fontSize: 11, fontWeight: FontWeight.w600,
                    color: AppColors.textMuted, letterSpacing: 0.5)),
            const SizedBox(height: 8),
            Container(
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: AppColors.surface,
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: AppColors.accent.withOpacity(0.3)),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  SelectableText(
                    widget.oobi.oobiUrl,
                    style: const TextStyle(color: AppColors.accent, fontSize: 12,
                        fontFamily: 'monospace', height: 1.5),
                  ),
                  const SizedBox(height: 10),
                  Align(
                    alignment: Alignment.centerRight,
                    child: InkWell(
                      onTap: _copy,
                      borderRadius: BorderRadius.circular(6),
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
                        decoration: BoxDecoration(
                          color: _copied ? AppColors.success.withOpacity(0.12) : AppColors.surfaceLight,
                          borderRadius: BorderRadius.circular(6),
                          border: Border.all(color: _copied ? AppColors.success.withOpacity(0.3) : AppColors.border),
                        ),
                        child: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Icon(_copied ? Icons.check : Icons.copy,
                                color: _copied ? AppColors.success : AppColors.textSecondary, size: 14),
                            const SizedBox(width: 6),
                            Text(_copied ? 'Copied' : 'Copy',
                                style: TextStyle(
                                  color: _copied ? AppColors.success : AppColors.textSecondary,
                                  fontSize: 12, fontWeight: FontWeight.w600,
                                )),
                          ],
                        ),
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 24),
            const Text('QR Code',
                style: TextStyle(fontSize: 11, fontWeight: FontWeight.w600,
                    color: AppColors.textMuted, letterSpacing: 0.5)),
            const SizedBox(height: 8),
            const Text('Scan from another device to add this identity.',
                style: TextStyle(color: AppColors.textMuted, fontSize: 13)),
            const SizedBox(height: 16),
            Center(
              child: Container(
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: Colors.white,
                  borderRadius: BorderRadius.circular(12),
                ),
                child: QrImageView(
                  data: widget.oobi.oobiUrl,
                  version: QrVersions.auto,
                  size: 220,
                  backgroundColor: Colors.white,
                  eyeStyle: const QrEyeStyle(eyeShape: QrEyeShape.square, color: Color(0xFF0a0e1a)),
                  dataModuleStyle: const QrDataModuleStyle(
                      dataModuleShape: QrDataModuleShape.square, color: Color(0xFF0a0e1a)),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}

// ── Desktop add-contact dialog (QR share + resolve OOBI) ──────────────────────

class _DesktopAddContactDialog extends StatefulWidget {
  final OobiResponse oobi;
  final CoreService coreService;
  final void Function(ResolvedContactResponse resolved) onResolved;

  const _DesktopAddContactDialog({
    required this.oobi,
    required this.coreService,
    required this.onResolved,
  });

  @override
  State<_DesktopAddContactDialog> createState() => _DesktopAddContactDialogState();
}

class _DesktopAddContactDialogState extends State<_DesktopAddContactDialog> {
  bool _copied = false;

  void _copy() {
    Clipboard.setData(ClipboardData(text: widget.oobi.oobiUrl));
    setState(() => _copied = true);
    Future.delayed(const Duration(seconds: 2), () {
      if (mounted) setState(() => _copied = false);
    });
  }

  @override
  Widget build(BuildContext context) {
    return Dialog(
      backgroundColor: AppColors.surface,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(16),
        side: const BorderSide(color: AppColors.border),
      ),
      insetPadding: const EdgeInsets.symmetric(horizontal: 40, vertical: 40),
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 460),
        child: Padding(
          padding: const EdgeInsets.all(28),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // ── Header ────────────────────────────────────────────────────
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'Add Contact',
                          style: TextStyle(
                            color: AppColors.textPrimary,
                            fontSize: 18,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                        SizedBox(height: 4),
                        Text(
                          'Share this QR code with the person you want to add you as a contact. You\'ll be notified once they accept and invited to add them back.',
                          style: TextStyle(color: AppColors.textSecondary, fontSize: 12, height: 1.5),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(width: 8),
                  IconButton(
                    icon: const Icon(Icons.close, size: 18),
                    color: AppColors.textMuted,
                    onPressed: () => Navigator.of(context).pop(),
                    padding: EdgeInsets.zero,
                    constraints: const BoxConstraints(minWidth: 32, minHeight: 32),
                  ),
                ],
              ),
              const SizedBox(height: 24),

              // ── QR + URL side by side ─────────────────────────────────────
              Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Container(
                    padding: const EdgeInsets.all(10),
                    decoration: BoxDecoration(
                      color: Colors.white,
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: QrImageView(
                      data: widget.oobi.oobiUrl,
                      version: QrVersions.auto,
                      size: 148,
                      backgroundColor: Colors.white,
                      eyeStyle: const QrEyeStyle(eyeShape: QrEyeShape.square, color: Color(0xFF0a0e1a)),
                      dataModuleStyle: const QrDataModuleStyle(dataModuleShape: QrDataModuleShape.square, color: Color(0xFF0a0e1a)),
                    ),
                  ),
                  const SizedBox(width: 16),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text(
                          'Identity Link',
                          style: TextStyle(
                            color: AppColors.textSecondary,
                            fontSize: 11,
                            fontWeight: FontWeight.w500,
                          ),
                        ),
                        const SizedBox(height: 6),
                        Container(
                          padding: const EdgeInsets.all(10),
                          decoration: BoxDecoration(
                            color: AppColors.surfaceLight,
                            borderRadius: BorderRadius.circular(8),
                            border: Border.all(color: AppColors.accent.withOpacity(0.25)),
                          ),
                          child: SelectableText(
                            widget.oobi.oobiUrl,
                            style: const TextStyle(
                              color: AppColors.accent,
                              fontSize: 10,
                              fontFamily: 'monospace',
                              height: 1.5,
                            ),
                          ),
                        ),
                        const SizedBox(height: 10),
                        SizedBox(
                          width: double.infinity,
                          child: OutlinedButton.icon(
                            onPressed: _copy,
                            icon: Icon(
                              _copied ? Icons.check : Icons.copy,
                              size: 14,
                              color: _copied ? AppColors.success : AppColors.accent,
                            ),
                            label: Text(
                              _copied ? 'Copied!' : 'Copy Link',
                              style: TextStyle(
                                color: _copied ? AppColors.success : AppColors.accent,
                                fontSize: 12,
                              ),
                            ),
                            style: OutlinedButton.styleFrom(
                              side: BorderSide(color: _copied ? AppColors.success : AppColors.accent),
                              padding: const EdgeInsets.symmetric(vertical: 10),
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}
