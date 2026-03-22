import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../../theme/mobile_theme.dart';
import '../../services/core_service.dart';
import '../../services/identity_level_service.dart';
import '../../services/nfc_service.dart';
import '../../services/setup_task_service.dart';
import '../../config/agent_config.dart';

class MobileContactsScreen extends StatefulWidget {
  final String? serverUrl;

  const MobileContactsScreen({super.key, this.serverUrl});

  @override
  State<MobileContactsScreen> createState() => _MobileContactsScreenState();
}

class _MobileContactsScreenState extends State<MobileContactsScreen> {
  late final CoreService _coreService;
  List<ContactResponse> _contacts = [];
  List<ContactResponse> _filtered = [];
  bool _loading = true;
  final _searchController = TextEditingController();

  @override
  void initState() {
    super.initState();
    _coreService = CoreService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);
    _searchController.addListener(_filterContacts);
    _loadContacts();
  }

  @override
  void dispose() {
    _coreService.dispose();
    _searchController.dispose();
    super.dispose();
  }

  Future<void> _loadContacts() async {
    try {
      final result = await _coreService.getContacts();
      if (mounted) {
        setState(() {
          _contacts = result.contacts;
          _filtered = result.contacts;
          _loading = false;
        });
        _syncWitnessCount(result.contacts);
      }
    } catch (e) {
      debugPrint('[MobileContacts] Load error: $e');
      if (mounted) setState(() => _loading = false);
    }
  }

  void _syncWitnessCount(List<ContactResponse> contacts) {
    final count = contacts.where((c) => c.isAccepted && c.isWitness).length;
    IdentityLevelService.setWitnessCount(count);
  }

  Future<void> _writeNfcTag() async {
    final isAvailable = await NfcService.isAvailable();
    if (!isAvailable) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('NFC is not available on this device.')),
        );
      }
      return;
    }

    OobiResponse? oobi;
    try {
      oobi = await _coreService.getOobi(action: 'add_contact');
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Could not load identity link: $e'),
              backgroundColor: MobileColors.error),
        );
      }
      return;
    }

    if (!oobi.tunnelActive || oobi.oobiUrl.isEmpty) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('You need an active tunnel to write an NFC tap tag. Go to Settings to configure one.'),
          ),
        );
      }
      return;
    }

    // Show the write-tap sheet.
    if (!mounted) return;
    showModalBottomSheet<void>(
      context: context,
      backgroundColor: MobileColors.surface,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (ctx) => _NfcWriteSheet(
        oobiUrl: oobi!.oobiUrl,
        onDone: () => Navigator.of(ctx).pop(),
      ),
    );
  }

  void _filterContacts() {
    final query = _searchController.text.toLowerCase();
    setState(() {
      if (query.isEmpty) {
        _filtered = _contacts;
      } else {
        _filtered = _contacts.where((c) {
          return c.displayName.toLowerCase().contains(query) ||
              c.aid.toLowerCase().contains(query);
        }).toList();
      }
    });
  }

  void _showContactDetail(ContactResponse contact) async {
    final deleted = await Navigator.of(context).push<bool>(
      MaterialPageRoute(
        builder: (_) => Theme(
          data: MobileTheme.lightTheme,
          child: _ContactDetailScreen(contact: contact, serverUrl: widget.serverUrl),
        ),
      ),
    );
    if (deleted == true) {
      _loadContacts();
    }
  }

  @override
  Widget build(BuildContext context) {
    return Theme(
      data: MobileTheme.lightTheme,
      child: Scaffold(
        backgroundColor: MobileColors.background,
        appBar: AppBar(
          title: const Text('Contacts'),
          backgroundColor: MobileColors.surface,
          foregroundColor: MobileColors.textPrimary,
          elevation: 0,
          actions: [
            IconButton(
              onPressed: _writeNfcTag,
              icon: const Icon(Icons.nfc),
              tooltip: 'Write Identity Tap Tag',
            ),
          ],
        ),
        body: Column(
          children: [
            Padding(
              padding: const EdgeInsets.all(16),
              child: TextField(
                controller: _searchController,
                decoration: InputDecoration(
                  hintText: 'Search contacts...',
                  prefixIcon: const Icon(Icons.search, color: MobileColors.textMuted),
                  filled: true,
                  fillColor: MobileColors.surface,
                  border: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(12),
                    borderSide: const BorderSide(color: MobileColors.border),
                  ),
                  enabledBorder: OutlineInputBorder(
                    borderRadius: BorderRadius.circular(12),
                    borderSide: const BorderSide(color: MobileColors.border),
                  ),
                  contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                ),
              ),
            ),
            Expanded(
              child: _loading
                  ? const Center(child: CircularProgressIndicator(color: MobileColors.primary))
                  : _filtered.isEmpty
                      ? _buildEmptyState()
                      : RefreshIndicator(
                          onRefresh: _loadContacts,
                          color: MobileColors.primary,
                          child: ListView.builder(
                            padding: const EdgeInsets.symmetric(horizontal: 16),
                            itemCount: _filtered.length,
                            itemBuilder: (context, index) {
                              return _ContactCard(
                                contact: _filtered[index],
                                onTap: () => _showContactDetail(_filtered[index]),
                              );
                            },
                          ),
                        ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(Icons.people_outline, size: 48, color: MobileColors.textMuted),
          const SizedBox(height: 12),
          Text(
            _searchController.text.isNotEmpty ? 'No matching contacts' : 'No contacts yet',
            style: const TextStyle(color: MobileColors.textMuted, fontSize: 16),
          ),
          const SizedBox(height: 4),
          const Text(
            'Scan a QR code to add a contact',
            style: TextStyle(color: MobileColors.textMuted, fontSize: 13),
          ),
        ],
      ),
    );
  }
}

class _ContactCard extends StatelessWidget {
  final ContactResponse contact;
  final VoidCallback onTap;

  const _ContactCard({required this.contact, required this.onTap});

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        margin: const EdgeInsets.only(bottom: 8),
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: MobileColors.surface,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: MobileColors.border),
        ),
        child: Row(
          children: [
            _buildAvatar(),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    contact.displayName,
                    style: const TextStyle(
                      fontSize: 16,
                      fontWeight: FontWeight.w600,
                      color: MobileColors.textPrimary,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                  const SizedBox(height: 2),
                  Text(
                    contact.aid.length > 20
                        ? '${contact.aid.substring(0, 20)}...'
                        : contact.aid,
                    style: const TextStyle(
                      fontSize: 11,
                      color: MobileColors.textMuted,
                      fontFamily: 'monospace',
                    ),
                  ),
                ],
              ),
            ),
            Column(
              crossAxisAlignment: CrossAxisAlignment.end,
              children: [
                _buildStatusBadge(),
                if (contact.contactType != 'general' || contact.isWitness) ...[
                  const SizedBox(height: 4),
                  _buildRoleBadge(),
                ],
              ],
            ),
            const SizedBox(width: 8),
            const Icon(Icons.chevron_right, color: MobileColors.textMuted, size: 20),
          ],
        ),
      ),
    );
  }

  Uint8List? _decodePhoto(String photo) {
    if (photo.isEmpty) return null;
    try {
      final data = photo.contains(',') ? photo.split(',').last : photo;
      return base64Decode(data);
    } catch (_) {
      return null;
    }
  }

  Widget _buildAvatar() {
    final photoBytes = _decodePhoto(contact.photo);
    if (photoBytes != null) {
      return CircleAvatar(
        radius: 22,
        backgroundImage: MemoryImage(photoBytes),
      );
    }

    if (contact.jcard != null) {
      final name = contact.jcard!.fullName;
      if (name.isNotEmpty) {
        final initials = name.split(' ').take(2).map((w) => w.isNotEmpty ? w[0].toUpperCase() : '').join();
        return CircleAvatar(
          radius: 22,
          backgroundColor: MobileColors.primary.withOpacity(0.15),
          child: Text(
            initials,
            style: const TextStyle(
              color: MobileColors.primary,
              fontWeight: FontWeight.w600,
              fontSize: 14,
            ),
          ),
        );
      }
    }

    return CircleAvatar(
      radius: 22,
      backgroundColor: MobileColors.surfaceTertiary,
      child: const Icon(Icons.person, color: MobileColors.textMuted, size: 22),
    );
  }

  Widget _buildStatusBadge() {
    Color color;
    String label;

    if (contact.isAccepted) {
      color = MobileColors.success;
      label = 'Connected';
    } else if (contact.verified) {
      color = MobileColors.info;
      label = 'Verified';
    } else if (contact.isPendingInbound) {
      color = MobileColors.warning;
      label = 'Incoming';
    } else {
      color = MobileColors.textMuted;
      label = 'Added';
    }

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: color.withOpacity(0.1),
        borderRadius: BorderRadius.circular(6),
      ),
      child: Text(
        label,
        style: TextStyle(fontSize: 10, fontWeight: FontWeight.w600, color: color),
      ),
    );
  }

  Widget _buildRoleBadge() {
    Color color;
    String label;
    if (contact.isWitness) {
      color = MobileColors.primary;
      label = 'WITNESS';
    } else {
      color = MobileColors.textSecondary;
      label = contact.contactType.toUpperCase();
    }
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: color.withOpacity(0.08),
        borderRadius: BorderRadius.circular(4),
        border: Border.all(color: color.withOpacity(0.25)),
      ),
      child: Text(
        label,
        style: TextStyle(fontSize: 9, fontWeight: FontWeight.w700, color: color),
      ),
    );
  }
}

class _ContactDetailScreen extends StatefulWidget {
  final ContactResponse contact;
  final String? serverUrl;

  const _ContactDetailScreen({required this.contact, this.serverUrl});

  @override
  State<_ContactDetailScreen> createState() => _ContactDetailScreenState();
}

class _ContactDetailScreenState extends State<_ContactDetailScreen> {
  bool _deleting = false;
  late ContactResponse _contact;

  @override
  void initState() {
    super.initState();
    _contact = widget.contact;
  }

  Future<void> _showAcceptSheet() async {
    // Relationship type: 'general' | 'trusted' | 'professional'
    // Witness designation is handled automatically by the backend when trusted.
    String relationshipType = 'general';
    final coreService = CoreService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);

    await showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      backgroundColor: MobileColors.surface,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setS) => Padding(
          padding: const EdgeInsets.fromLTRB(24, 24, 24, 36),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Accept ${_contact.displayName}',
                style: const TextStyle(
                  color: MobileColors.textPrimary,
                  fontSize: 18,
                  fontWeight: FontWeight.w700,
                ),
              ),
              const SizedBox(height: 8),
              const Text(
                'How do you know this person?',
                style: TextStyle(color: MobileColors.textSecondary, fontSize: 13),
              ),
              const SizedBox(height: 16),
              for (final entry in const [
                ('general', 'General', 'Someone you know — acquaintance or casual contact'),
                ('trusted', 'Trusted', 'Someone you personally trust — can be invited as a witness'),
                ('professional', 'Professional', 'A colleague or professional connection'),
              ])
                GestureDetector(
                  onTap: () => setS(() => relationshipType = entry.$1),
                  child: Container(
                    margin: const EdgeInsets.only(bottom: 8),
                    padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                    decoration: BoxDecoration(
                      color: relationshipType == entry.$1
                          ? MobileColors.primary.withOpacity(0.08)
                          : MobileColors.surfaceSecondary,
                      border: Border.all(
                        color: relationshipType == entry.$1
                            ? MobileColors.primary.withOpacity(0.6)
                            : MobileColors.border,
                        width: relationshipType == entry.$1 ? 1.5 : 1,
                      ),
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: Row(
                      children: [
                        Radio<String>(
                          value: entry.$1,
                          groupValue: relationshipType,
                          onChanged: (v) => setS(() => relationshipType = v!),
                          activeColor: MobileColors.primary,
                          materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
                          visualDensity: VisualDensity.compact,
                        ),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(entry.$2,
                                  style: const TextStyle(
                                      color: MobileColors.textPrimary,
                                      fontSize: 14,
                                      fontWeight: FontWeight.w600)),
                              Text(entry.$3,
                                  style: const TextStyle(
                                      color: MobileColors.textSecondary,
                                      fontSize: 12)),
                            ],
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              if (relationshipType == 'trusted')
                Container(
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: Colors.green.withOpacity(0.06),
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: Colors.green.withOpacity(0.2)),
                  ),
                  child: const Row(
                    children: [
                      Icon(Icons.info_outline, size: 16, color: Colors.green),
                      SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          'If you need more witnesses, this contact may be automatically invited to witness your keys.',
                          style: TextStyle(color: Colors.green, fontSize: 12),
                        ),
                      ),
                    ],
                  ),
                ),
              const SizedBox(height: 20),
              Row(
                children: [
                  Expanded(
                    child: OutlinedButton(
                      onPressed: () async {
                        Navigator.of(ctx).pop();
                        try {
                          await coreService.rejectContact(_contact.aid);
                          coreService.dispose();
                          if (mounted) Navigator.of(context).pop(true);
                        } catch (e) {
                          coreService.dispose();
                          if (mounted) {
                            ScaffoldMessenger.of(context).showSnackBar(
                              SnackBar(content: Text('$e'),
                                  backgroundColor: MobileColors.error),
                            );
                          }
                        }
                      },
                      style: OutlinedButton.styleFrom(
                        side: const BorderSide(color: MobileColors.error),
                        foregroundColor: MobileColors.error,
                        padding: const EdgeInsets.symmetric(vertical: 14),
                        shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(10)),
                      ),
                      child: const Text('Decline'),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: ElevatedButton(
                      onPressed: () async {
                        Navigator.of(ctx).pop();
                        try {
                          await coreService.acceptContact(_contact.aid,
                              contactType: relationshipType);
                          coreService.dispose();
                          if (relationshipType == 'trusted') {
                            // trusted contact accepted
                          }
                          final all = await CoreService(
                                  baseUrl: widget.serverUrl ??
                                      AgentConfig.coreBaseUrl)
                              .getContacts();
                          IdentityLevelService.setWitnessCount(all.contacts
                              .where((c) => c.isAccepted && c.isWitness)
                              .length);
                          if (mounted) Navigator.of(context).pop(true);
                        } catch (e) {
                          coreService.dispose();
                          if (mounted) {
                            ScaffoldMessenger.of(context).showSnackBar(
                              SnackBar(content: Text('$e'),
                                  backgroundColor: MobileColors.error),
                            );
                          }
                        }
                      },
                      style: ElevatedButton.styleFrom(
                        backgroundColor: MobileColors.primary,
                        foregroundColor: MobileColors.textOnPrimary,
                        padding: const EdgeInsets.symmetric(vertical: 14),
                        shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(10)),
                      ),
                      child: const Text('Accept'),
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

  Future<void> _showChangeRoleSheet() async {
    String relationshipType = _contact.contactType;
    final coreService = CoreService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);

    await showModalBottomSheet<void>(
      context: context,
      backgroundColor: MobileColors.surface,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setS) => Padding(
          padding: const EdgeInsets.fromLTRB(24, 24, 24, 36),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'Change Relationship',
                style: TextStyle(
                  color: MobileColors.textPrimary,
                  fontSize: 18,
                  fontWeight: FontWeight.w700,
                ),
              ),
              const SizedBox(height: 8),
              const Text(
                'Changing to Trusted may trigger a witness invitation.',
                style: TextStyle(color: MobileColors.textSecondary, fontSize: 12),
              ),
              const SizedBox(height: 16),
              for (final entry in const [
                ('general', 'General', 'Acquaintance or casual contact'),
                ('trusted', 'Trusted', 'Personal trust — can become a witness'),
                ('professional', 'Professional', 'Colleague or professional connection'),
              ])
                RadioListTile<String>(
                  value: entry.$1,
                  groupValue: relationshipType,
                  onChanged: (v) => setS(() => relationshipType = v!),
                  title: Text(entry.$2,
                      style: const TextStyle(
                          color: MobileColors.textPrimary, fontSize: 14)),
                  subtitle: Text(entry.$3,
                      style: const TextStyle(
                          color: MobileColors.textSecondary, fontSize: 12)),
                  activeColor: MobileColors.primary,
                  dense: true,
                  contentPadding: EdgeInsets.zero,
                ),
              const SizedBox(height: 20),
              SizedBox(
                width: double.infinity,
                child: ElevatedButton(
                  onPressed: () async {
                    Navigator.of(ctx).pop();
                    try {
                      final updated = await coreService.updateContact(
                          _contact.aid, contactType: relationshipType);
                      coreService.dispose();
                      if (relationshipType == 'trusted' && _contact.contactType != 'trusted') {
                        // trusted contact updated
                      }
                      final all = await CoreService(
                              baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl)
                          .getContacts();
                      IdentityLevelService.setWitnessCount(all.contacts
                          .where((c) => c.isAccepted && c.isWitness)
                          .length);
                      if (mounted) setState(() => _contact = updated);
                    } catch (e) {
                      coreService.dispose();
                      if (mounted) {
                        ScaffoldMessenger.of(context).showSnackBar(
                          SnackBar(content: Text('$e'),
                              backgroundColor: MobileColors.error),
                        );
                      }
                    }
                  },
                  style: ElevatedButton.styleFrom(
                    backgroundColor: MobileColors.primary,
                    foregroundColor: MobileColors.textOnPrimary,
                    padding: const EdgeInsets.symmetric(vertical: 14),
                    shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(10)),
                  ),
                  child: const Text('Save',
                      style: TextStyle(fontWeight: FontWeight.w600)),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  void _copyToClipboard(String text, String label) {
    Clipboard.setData(ClipboardData(text: text));
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text('$label copied')),
    );
  }

  Future<void> _confirmDelete() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: const Text('Delete Contact'),
        content: Text(
          'Are you sure you want to delete ${_contact.displayName}? This cannot be undone.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('Cancel', style: TextStyle(color: MobileColors.textMuted)),
          ),
          ElevatedButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            style: ElevatedButton.styleFrom(
              backgroundColor: MobileColors.error,
              foregroundColor: Colors.white,
            ),
            child: const Text('Delete'),
          ),
        ],
      ),
    );

    if (confirmed == true && mounted) {
      setState(() => _deleting = true);
      try {
        final coreService = CoreService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);
        await coreService.deleteContact(_contact.aid);
        coreService.dispose();
        if (mounted) {
          Navigator.of(context).pop(true);
        }
      } catch (e) {
        if (mounted) {
          setState(() => _deleting = false);
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('Failed to delete: $e'),
              backgroundColor: MobileColors.error,
            ),
          );
        }
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: MobileColors.background,
      appBar: AppBar(
        title: Text(_contact.displayName),
        backgroundColor: MobileColors.surface,
        foregroundColor: MobileColors.textPrimary,
        elevation: 0,
        actions: [
          IconButton(
            onPressed: _deleting ? null : _confirmDelete,
            icon: _deleting
                ? const SizedBox(
                    width: 20, height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2, color: MobileColors.error),
                  )
                : const Icon(Icons.delete_outline, color: MobileColors.error),
          ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            _buildDetailAvatar(_contact),
            const SizedBox(height: 12),
            Text(
              _contact.displayName,
              style: const TextStyle(
                fontSize: 22,
                fontWeight: FontWeight.w700,
                color: MobileColors.textPrimary,
              ),
            ),
            const SizedBox(height: 4),
            _buildStatusChip(),
            const SizedBox(height: 20),
            _buildInfoCard(context),
            if (_contact.jcard != null) ...[
              const SizedBox(height: 12),
              _buildJCardInfo(),
            ],
            const SizedBox(height: 16),
            // Accept/Decline for incoming pending contacts
            if (_contact.isPendingInbound) ...[
              SizedBox(
                width: double.infinity,
                child: ElevatedButton.icon(
                  onPressed: _showAcceptSheet,
                  icon: const Icon(Icons.check, size: 18),
                  label: const Text('Accept as...'),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: MobileColors.primary,
                    foregroundColor: MobileColors.textOnPrimary,
                    padding: const EdgeInsets.symmetric(vertical: 14),
                    shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(10)),
                  ),
                ),
              ),
              const SizedBox(height: 8),
            ],
            // Contact type for non-pending contacts
            if (!_contact.isPendingInbound) ...[
              SizedBox(
                width: double.infinity,
                child: OutlinedButton.icon(
                  onPressed: _showChangeRoleSheet,
                  icon: const Icon(Icons.swap_horiz, size: 18),
                  label: Text('Contact Type: ${_contact.contactType[0].toUpperCase()}${_contact.contactType.substring(1)}'),
                  style: OutlinedButton.styleFrom(
                    foregroundColor: MobileColors.primary,
                    side: const BorderSide(color: MobileColors.primary),
                    padding: const EdgeInsets.symmetric(vertical: 14),
                    shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(10)),
                  ),
                ),
              ),
              const SizedBox(height: 8),
            ],
            SizedBox(
              width: double.infinity,
              child: OutlinedButton.icon(
                onPressed: _deleting ? null : _confirmDelete,
                icon: const Icon(Icons.delete_outline, size: 18),
                label: const Text('Delete Contact'),
                style: OutlinedButton.styleFrom(
                  foregroundColor: MobileColors.error,
                  side: const BorderSide(color: MobileColors.error),
                  padding: const EdgeInsets.symmetric(vertical: 14),
                  shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildDetailAvatar(ContactResponse contact) {
    if (contact.photo.isNotEmpty) {
      try {
        final photoData = contact.photo.contains(',')
            ? contact.photo.split(',').last
            : contact.photo;
        return CircleAvatar(
          radius: 40,
          backgroundImage: MemoryImage(base64Decode(photoData)),
        );
      } catch (_) {}
    }
    return CircleAvatar(
      radius: 40,
      backgroundColor: MobileColors.primary,
      child: Text(
        contact.displayName.isNotEmpty
            ? contact.displayName[0].toUpperCase()
            : '?',
        style: const TextStyle(
          color: MobileColors.textOnPrimary,
          fontWeight: FontWeight.w700,
          fontSize: 28,
        ),
      ),
    );
  }

  Widget _buildStatusChip() {
    Color color;
    String label;

    if (_contact.isPendingInbound) {
      color = MobileColors.warning;
      label = 'Incoming Request';
    } else if (_contact.isAccepted) {
      color = MobileColors.success;
      label = 'Connected';
    } else if (_contact.verified) {
      color = MobileColors.info;
      label = 'Verified';
    } else {
      color = MobileColors.textMuted;
      label = 'Contact';
    }

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 5),
      decoration: BoxDecoration(
        color: color.withOpacity(0.1),
        borderRadius: BorderRadius.circular(16),
      ),
      child: Text(
        label,
        style: TextStyle(
          fontSize: 12,
          fontWeight: FontWeight.w600,
          color: color,
        ),
      ),
    );
  }

  Widget _buildInfoCard(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: MobileColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: MobileColors.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          _DetailRow(
            label: 'AID',
            value: _contact.aid,
            monospace: true,
            onCopy: () => _copyToClipboard(_contact.aid, 'AID'),
          ),
          const Divider(height: 16),
          _DetailRow(
            label: 'OOBI URL',
            value: _contact.oobiUrl,
            monospace: true,
            onCopy: () => _copyToClipboard(_contact.oobiUrl, 'OOBI URL'),
          ),
          const Divider(height: 16),
          _DetailRow(label: 'Contact Type', value: _contact.contactType),
          const Divider(height: 16),
          _DetailRow(label: 'Status', value: _contact.status.isNotEmpty ? _contact.status : 'added'),
          const Divider(height: 16),
          _DetailRow(label: 'Verified', value: _contact.verified ? 'Yes' : 'No'),
          if (_contact.discoveredAt.isNotEmpty) ...[
            const Divider(height: 16),
            _DetailRow(label: 'Discovered', value: _contact.discoveredAt),
          ],
        ],
      ),
    );
  }

  Widget _buildJCardInfo() {
    final jcard = _contact.jcard!;
    final fields = <MapEntry<String, String>>[];

    if (jcard.fullName.isNotEmpty) fields.add(MapEntry('Name', jcard.fullName));
    if (jcard.org.isNotEmpty) fields.add(MapEntry('Organization', jcard.org));
    if (jcard.title.isNotEmpty) fields.add(MapEntry('Title', jcard.title));
    if (jcard.email.isNotEmpty) fields.add(MapEntry('Email', jcard.email));
    if (jcard.tel.isNotEmpty) fields.add(MapEntry('Phone', jcard.tel));

    if (fields.isEmpty) return const SizedBox.shrink();

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: MobileColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: MobileColors.border),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Row(
            children: [
              Icon(Icons.contact_mail, size: 18, color: MobileColors.primary),
              SizedBox(width: 8),
              Text(
                'Contact Info (jCard)',
                style: TextStyle(
                  fontSize: 15,
                  fontWeight: FontWeight.w600,
                  color: MobileColors.textPrimary,
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          ...fields.map((f) => Padding(
                padding: const EdgeInsets.symmetric(vertical: 4),
                child: _DetailRow(label: f.key, value: f.value),
              )),
        ],
      ),
    );
  }
}

class _DetailRow extends StatelessWidget {
  final String label;
  final String value;
  final bool monospace;
  final VoidCallback? onCopy;

  const _DetailRow({
    required this.label,
    required this.value,
    this.monospace = false,
    this.onCopy,
  });

  @override
  Widget build(BuildContext context) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                label,
                style: const TextStyle(
                  fontSize: 11,
                  color: MobileColors.textMuted,
                  fontWeight: FontWeight.w600,
                ),
              ),
              const SizedBox(height: 2),
              Text(
                value,
                style: TextStyle(
                  fontSize: 13,
                  color: MobileColors.textPrimary,
                  fontFamily: monospace ? 'monospace' : null,
                ),
              ),
            ],
          ),
        ),
        if (onCopy != null)
          IconButton(
            onPressed: onCopy,
            icon: const Icon(Icons.copy, size: 16, color: MobileColors.textMuted),
            padding: EdgeInsets.zero,
            constraints: const BoxConstraints(),
          ),
      ],
    );
  }
}

// ── NFC Write Sheet ─────────────────────────────────────────────────────────

class _NfcWriteSheet extends StatefulWidget {
  final String oobiUrl;
  final VoidCallback onDone;

  const _NfcWriteSheet({required this.oobiUrl, required this.onDone});

  @override
  State<_NfcWriteSheet> createState() => _NfcWriteSheetState();
}

class _NfcWriteSheetState extends State<_NfcWriteSheet>
    with SingleTickerProviderStateMixin {
  late final AnimationController _pulse;
  bool _success = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _pulse = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1200),
    )..repeat(reverse: true);
    _startWrite();
  }

  @override
  void dispose() {
    _pulse.dispose();
    NfcService.stopSession();
    super.dispose();
  }

  Future<void> _startWrite() async {
    setState(() {
      _error = null;
      _success = false;
    });
    await NfcService.writeOobi(
      widget.oobiUrl,
      onSuccess: () {
        if (mounted) setState(() { _success = true; });
        _pulse.stop();
        Future.delayed(const Duration(seconds: 1), widget.onDone);
      },
      onError: (err) {
        if (mounted) setState(() { _error = err; });
        _pulse.stop();
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: EdgeInsets.fromLTRB(24, 24, 24,
          24 + MediaQuery.of(context).padding.bottom),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          const Text(
            'Write Identity Tap Tag',
            style: TextStyle(
              color: MobileColors.textPrimary,
              fontSize: 18,
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 8),
          const Text(
            'Hold your phone to a blank NFC tag or sticker.\nAnyone who taps it will be prompted to add you as a contact.',
            textAlign: TextAlign.center,
            style: TextStyle(color: MobileColors.textSecondary, fontSize: 13, height: 1.5),
          ),
          const SizedBox(height: 32),
          if (_success)
            const Column(
              children: [
                Icon(Icons.check_circle, size: 64, color: MobileColors.success),
                SizedBox(height: 12),
                Text('Tag written!',
                    style: TextStyle(
                        color: MobileColors.success,
                        fontSize: 16,
                        fontWeight: FontWeight.w700)),
              ],
            )
          else if (_error != null)
            Column(
              children: [
                const Icon(Icons.error_outline, size: 64, color: MobileColors.error),
                const SizedBox(height: 12),
                Text(_error!,
                    textAlign: TextAlign.center,
                    style: const TextStyle(color: MobileColors.error, fontSize: 13)),
                const SizedBox(height: 16),
                OutlinedButton.icon(
                  onPressed: _startWrite,
                  icon: const Icon(Icons.refresh, size: 18),
                  label: const Text('Retry'),
                  style: OutlinedButton.styleFrom(
                    foregroundColor: MobileColors.primary,
                  ),
                ),
              ],
            )
          else
            AnimatedBuilder(
              animation: _pulse,
              builder: (_, __) => Opacity(
                opacity: 0.5 + 0.5 * _pulse.value,
                child: const Icon(Icons.nfc, size: 80, color: MobileColors.primary),
              ),
            ),
          const SizedBox(height: 24),
          if (!_success && _error == null)
            OutlinedButton(
              onPressed: widget.onDone,
              style: OutlinedButton.styleFrom(
                foregroundColor: MobileColors.textMuted,
              ),
              child: const Text('Cancel'),
            ),
        ],
      ),
    );
  }
}
