import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../../theme/mobile_theme.dart';
import '../../services/core_service.dart';
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
      }
    } catch (e) {
      debugPrint('[MobileContacts] Load error: $e');
      if (mounted) setState(() => _loading = false);
    }
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
            _buildStatusBadge(),
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

    if (contact.isMutual) {
      color = MobileColors.success;
      label = 'Mutual';
    } else if (contact.verified) {
      color = MobileColors.info;
      label = 'Verified';
    } else if (contact.isPendingInbound) {
      color = MobileColors.warning;
      label = 'Pending';
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
        style: TextStyle(
          fontSize: 10,
          fontWeight: FontWeight.w600,
          color: color,
        ),
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
          'Are you sure you want to delete ${widget.contact.displayName}? This cannot be undone.',
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
        await coreService.deleteContact(widget.contact.aid);
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
    final contact = widget.contact;
    return Scaffold(
      backgroundColor: MobileColors.background,
      appBar: AppBar(
        title: Text(contact.displayName),
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
            _buildDetailAvatar(contact),
            const SizedBox(height: 12),
            Text(
              contact.displayName,
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
            if (contact.jcard != null) ...[
              const SizedBox(height: 12),
              _buildJCardInfo(),
            ],
            const SizedBox(height: 24),
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
    final contact = widget.contact;
    Color color;
    String label;

    if (contact.isMutual) {
      color = MobileColors.success;
      label = 'Mutual Connection';
    } else if (contact.verified) {
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
    final contact = widget.contact;
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
            value: contact.aid,
            monospace: true,
            onCopy: () => _copyToClipboard(contact.aid, 'AID'),
          ),
          const Divider(height: 16),
          _DetailRow(
            label: 'OOBI URL',
            value: contact.oobiUrl,
            monospace: true,
            onCopy: () => _copyToClipboard(contact.oobiUrl, 'OOBI URL'),
          ),
          const Divider(height: 16),
          _DetailRow(label: 'Status', value: contact.status.isNotEmpty ? contact.status : 'added'),
          const Divider(height: 16),
          _DetailRow(label: 'Verified', value: contact.verified ? 'Yes' : 'No'),
          if (contact.discoveredAt.isNotEmpty) ...[
            const Divider(height: 16),
            _DetailRow(label: 'Discovered', value: contact.discoveredAt),
          ],
        ],
      ),
    );
  }

  Widget _buildJCardInfo() {
    final jcard = widget.contact.jcard!;
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
