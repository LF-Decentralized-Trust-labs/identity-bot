import 'dart:convert';
import 'dart:async';
import 'dart:typed_data';
import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';
import '../../theme/mobile_theme.dart';
import '../../services/core_service.dart';
import '../../config/agent_config.dart';
import '../../services/photo_picker_stub.dart'
    if (dart.library.html) '../../services/photo_picker_web.dart' as photo_picker;

class MobileProfileScreen extends StatefulWidget {
  final String? serverUrl;

  const MobileProfileScreen({super.key, this.serverUrl});

  @override
  State<MobileProfileScreen> createState() => _MobileProfileScreenState();
}

class _MobileProfileScreenState extends State<MobileProfileScreen> {
  late final CoreService _coreService;
  bool _loading = true;
  bool _editing = false;
  bool _saving = false;

  String _aid = '';
  String _agentUrl = '';
  String? _photoBase64;

  final _fnController = TextEditingController();
  final _givenNameController = TextEditingController();
  final _familyNameController = TextEditingController();
  final _orgController = TextEditingController();
  final _titleController = TextEditingController();
  final _emailController = TextEditingController();
  final _telController = TextEditingController();
  final _noteController = TextEditingController();

  @override
  void initState() {
    super.initState();
    _coreService = CoreService(baseUrl: widget.serverUrl ?? AgentConfig.coreBaseUrl);
    _loadData();
  }

  @override
  void dispose() {
    _coreService.dispose();
    _fnController.dispose();
    _givenNameController.dispose();
    _familyNameController.dispose();
    _orgController.dispose();
    _titleController.dispose();
    _emailController.dispose();
    _telController.dispose();
    _noteController.dispose();
    super.dispose();
  }

  Future<void> _loadData() async {
    try {
      final results = await Future.wait([
        _coreService.getProfile(),
        _coreService.getIdentity(),
        _coreService.getEndpoint(),
      ]);

      final profile = results[0] as ProfileResponse;
      final identity = results[1] as IdentityResponse;
      final endpoint = results[2] as Map<String, dynamic>;

      if (mounted) {
        setState(() {
          _fnController.text = profile.fullName;
          _givenNameController.text = profile.givenName;
          _familyNameController.text = profile.familyName;
          _orgController.text = profile.org;
          _titleController.text = profile.title;
          _emailController.text = profile.email;
          _telController.text = profile.tel;
          _noteController.text = profile.note;
          _photoBase64 = profile.photo.isNotEmpty ? profile.photo : null;
          _aid = identity.aid ?? '';
          _agentUrl = (endpoint['url'] as String?) ?? '';
          _loading = false;
        });
      }
    } catch (e) {
      debugPrint('[MobileProfile] Load error: $e');
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _saveProfile() async {
    setState(() => _saving = true);
    try {
      final profile = ProfileResponse(
        fullName: _fnController.text,
        givenName: _givenNameController.text,
        familyName: _familyNameController.text,
        org: _orgController.text,
        title: _titleController.text,
        email: _emailController.text,
        tel: _telController.text,
        note: _noteController.text,
        photo: _photoBase64 ?? '',
      );
      await _coreService.saveProfile(profile);
      if (mounted) {
        setState(() {
          _editing = false;
          _saving = false;
        });
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Profile saved'),
            backgroundColor: MobileColors.success,
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        setState(() => _saving = false);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to save: $e'),
            backgroundColor: MobileColors.error,
          ),
        );
      }
    }
  }

  void _copyToClipboard(String text, String label) {
    Clipboard.setData(ClipboardData(text: text));
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text('$label copied')),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Theme(
      data: MobileTheme.lightTheme,
      child: Scaffold(
        backgroundColor: MobileColors.background,
        appBar: AppBar(
          title: const Text('My Profile'),
          backgroundColor: MobileColors.surface,
          foregroundColor: MobileColors.textPrimary,
          elevation: 0,
          actions: [
            if (!_loading)
              IconButton(
                onPressed: () => setState(() => _editing = !_editing),
                icon: Icon(_editing ? Icons.close : Icons.edit, size: 22),
              ),
          ],
        ),
        body: _loading
            ? const Center(child: CircularProgressIndicator(color: MobileColors.primary))
            : SingleChildScrollView(
                padding: const EdgeInsets.all(16),
                child: Column(
                  children: [
                    _buildAvatarSection(),
                    const SizedBox(height: 20),
                    _buildIdentityInfo(),
                    const SizedBox(height: 16),
                    _buildPersonalCard(),
                    const SizedBox(height: 12),
                    _buildContactCard(),
                    const SizedBox(height: 12),
                    _buildAboutCard(),
                    if (_editing) ...[
                      const SizedBox(height: 20),
                      _buildActionButtons(),
                    ],
                    const SizedBox(height: 32),
                  ],
                ),
              ),
      ),
    );
  }

  Future<void> _pickAndCropPhoto() async {
    try {
      final base64 = await photo_picker.pickPhotoBase64();
      if (base64 == null || base64.isEmpty || !mounted) return;

      final bytes = base64Decode(base64);
      final croppedBase64 = await showDialog<String>(
        context: context,
        barrierDismissible: false,
        builder: (ctx) => _PhotoCropDialog(imageBytes: bytes),
      );

      if (croppedBase64 != null && croppedBase64.isNotEmpty && mounted) {
        setState(() => _photoBase64 = croppedBase64);
      }
    } catch (e) {
      debugPrint('[MobileProfile] Photo pick error: $e');
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Failed to load photo: $e'), backgroundColor: MobileColors.error),
        );
      }
    }
  }

  void _removePhoto() {
    setState(() => _photoBase64 = null);
  }

  Widget _buildAvatarSection() {
    return Column(
      children: [
        GestureDetector(
          onTap: _editing ? _pickAndCropPhoto : null,
          child: Stack(
            children: [
              _buildAvatar(48),
              if (_editing)
                Positioned(
                  bottom: 0,
                  right: 0,
                  child: Container(
                    width: 32,
                    height: 32,
                    decoration: const BoxDecoration(
                      color: MobileColors.primary,
                      shape: BoxShape.circle,
                    ),
                    child: const Icon(Icons.camera_alt, color: MobileColors.textOnPrimary, size: 16),
                  ),
                ),
            ],
          ),
        ),
        if (_editing && _photoBase64 != null && _photoBase64!.isNotEmpty) ...[
          const SizedBox(height: 8),
          TextButton.icon(
            onPressed: _removePhoto,
            icon: const Icon(Icons.delete_outline, size: 16, color: MobileColors.error),
            label: const Text('Remove Photo', style: TextStyle(color: MobileColors.error, fontSize: 13)),
          ),
        ],
        const SizedBox(height: 12),
        Text(
          _fnController.text.isNotEmpty ? _fnController.text : 'Identity Agent',
          style: const TextStyle(
            fontSize: 22,
            fontWeight: FontWeight.w700,
            color: MobileColors.textPrimary,
          ),
        ),
      ],
    );
  }

  Widget _buildAvatar(double radius) {
    if (_photoBase64 != null && _photoBase64!.isNotEmpty) {
      try {
        final bytes = base64Decode(_photoBase64!);
        return CircleAvatar(radius: radius, backgroundImage: MemoryImage(bytes));
      } catch (_) {}
    }

    final name = _fnController.text;
    final initials = name.isNotEmpty
        ? name.split(' ').take(2).map((w) => w.isNotEmpty ? w[0].toUpperCase() : '').join()
        : 'IA';

    return CircleAvatar(
      radius: radius,
      backgroundColor: MobileColors.primary,
      child: Text(
        initials,
        style: TextStyle(
          color: MobileColors.textOnPrimary,
          fontWeight: FontWeight.w600,
          fontSize: radius * 0.5,
        ),
      ),
    );
  }

  Widget _buildIdentityInfo() {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: MobileColors.surface,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: MobileColors.border),
      ),
      child: Column(
        children: [
          if (_agentUrl.isNotEmpty)
            _CopyableRow(
              label: 'Agent URL',
              value: _agentUrl,
              onCopy: () => _copyToClipboard(_agentUrl, 'Agent URL'),
            ),
          if (_aid.isNotEmpty) ...[
            if (_agentUrl.isNotEmpty) const Divider(height: 16),
            _CopyableRow(
              label: 'AID',
              value: _aid.length > 28 ? '${_aid.substring(0, 28)}...' : _aid,
              fullValue: _aid,
              onCopy: () => _copyToClipboard(_aid, 'AID'),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildPersonalCard() {
    return _SectionCard(
      title: 'Personal',
      icon: Icons.person_outline,
      children: [
        _buildField('Display Name', _fnController),
        _buildField('Given Name', _givenNameController),
        _buildField('Family Name', _familyNameController),
        _buildField('Organization', _orgController),
        _buildField('Title / Role', _titleController),
      ],
    );
  }

  Widget _buildContactCard() {
    return _SectionCard(
      title: 'Contact',
      icon: Icons.contact_mail_outlined,
      children: [
        _buildField('Email', _emailController, keyboardType: TextInputType.emailAddress),
        _buildField('Phone', _telController, keyboardType: TextInputType.phone),
      ],
    );
  }

  Widget _buildAboutCard() {
    return _SectionCard(
      title: 'About',
      icon: Icons.info_outline,
      children: [
        _buildField('Note', _noteController, maxLines: 3),
      ],
    );
  }

  Widget _buildField(String label, TextEditingController controller, {
    TextInputType? keyboardType,
    int maxLines = 1,
  }) {
    if (!_editing) {
      final value = controller.text;
      if (value.isEmpty) return const SizedBox.shrink();
      return Padding(
        padding: const EdgeInsets.symmetric(vertical: 6),
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
              style: const TextStyle(
                fontSize: 15,
                color: MobileColors.textPrimary,
              ),
            ),
          ],
        ),
      );
    }

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: TextField(
        controller: controller,
        keyboardType: keyboardType,
        maxLines: maxLines,
        decoration: InputDecoration(
          labelText: label,
          filled: true,
          fillColor: MobileColors.surfaceSecondary,
        ),
      ),
    );
  }

  Widget _buildActionButtons() {
    return Row(
      children: [
        Expanded(
          child: OutlinedButton(
            onPressed: () {
              setState(() => _editing = false);
              _loadData();
            },
            child: const Text('Cancel'),
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: ElevatedButton(
            onPressed: _saving ? null : _saveProfile,
            child: _saving
                ? const SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(
                      color: MobileColors.textOnPrimary,
                      strokeWidth: 2,
                    ),
                  )
                : const Text('Save'),
          ),
        ),
      ],
    );
  }
}

class _SectionCard extends StatelessWidget {
  final String title;
  final IconData icon;
  final List<Widget> children;

  const _SectionCard({
    required this.title,
    required this.icon,
    required this.children,
  });

  @override
  Widget build(BuildContext context) {
    final visibleChildren = children.where((w) => w is! SizedBox || (w as SizedBox).height != 0).toList();
    
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
          Row(
            children: [
              Icon(icon, size: 18, color: MobileColors.primary),
              const SizedBox(width: 8),
              Text(
                title,
                style: const TextStyle(
                  fontSize: 15,
                  fontWeight: FontWeight.w600,
                  color: MobileColors.textPrimary,
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          ...visibleChildren,
        ],
      ),
    );
  }
}

class _PhotoCropDialog extends StatefulWidget {
  final Uint8List imageBytes;

  const _PhotoCropDialog({required this.imageBytes});

  @override
  State<_PhotoCropDialog> createState() => _PhotoCropDialogState();
}

class _PhotoCropDialogState extends State<_PhotoCropDialog> {
  final TransformationController _transformController = TransformationController();
  final GlobalKey _cropKey = GlobalKey();
  bool _cropping = false;
  ui.Image? _decodedImage;

  @override
  void initState() {
    super.initState();
    _decodeImage();
  }

  Future<void> _decodeImage() async {
    final codec = await ui.instantiateImageCodec(widget.imageBytes);
    final frame = await codec.getNextFrame();
    if (mounted) {
      setState(() => _decodedImage = frame.image);

      WidgetsBinding.instance.addPostFrameCallback((_) {
        _centerImage();
      });
    }
  }

  void _centerImage() {
    if (_decodedImage == null) return;
    final cropSize = _getCropSize();
    final imgW = _decodedImage!.width.toDouble();
    final imgH = _decodedImage!.height.toDouble();

    final scale = cropSize / (imgW < imgH ? imgW : imgH);
    final scaledW = imgW * scale;
    final scaledH = imgH * scale;
    final dx = (cropSize - scaledW) / 2;
    final dy = (cropSize - scaledH) / 2;

    final matrix = Matrix4.identity()
      ..scale(scale)
      ..setTranslationRaw(dx, dy, 0);
    _transformController.value = matrix;
  }

  double _getCropSize() {
    final screenWidth = MediaQuery.of(context).size.width;
    return (screenWidth - 80).clamp(200.0, 350.0);
  }

  Future<void> _cropAndSave() async {
    if (_decodedImage == null) return;
    setState(() => _cropping = true);

    try {
      final boundary = _cropKey.currentContext?.findRenderObject() as RenderRepaintBoundary?;
      if (boundary == null) {
        setState(() => _cropping = false);
        return;
      }

      final image = await boundary.toImage(pixelRatio: 2.0);
      final byteData = await image.toByteData(format: ui.ImageByteFormat.png);
      if (byteData == null) {
        setState(() => _cropping = false);
        return;
      }

      final pngBytes = byteData.buffer.asUint8List();
      final b64 = base64Encode(pngBytes);

      if (mounted) {
        Navigator.of(context).pop(b64);
      }
    } catch (e) {
      debugPrint('[PhotoCrop] Crop error: $e');
      if (mounted) {
        setState(() => _cropping = false);
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Crop failed: $e'), backgroundColor: MobileColors.error),
        );
      }
    }
  }

  @override
  void dispose() {
    _transformController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final cropSize = _getCropSize();

    return Dialog(
      backgroundColor: Colors.transparent,
      insetPadding: const EdgeInsets.symmetric(horizontal: 20, vertical: 40),
      child: Container(
        decoration: BoxDecoration(
          color: MobileColors.surface,
          borderRadius: BorderRadius.circular(20),
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Padding(
              padding: EdgeInsets.fromLTRB(20, 20, 20, 12),
              child: Text(
                'Adjust Photo',
                style: TextStyle(
                  fontSize: 18,
                  fontWeight: FontWeight.w700,
                  color: MobileColors.textPrimary,
                ),
              ),
            ),
            const Padding(
              padding: EdgeInsets.symmetric(horizontal: 20),
              child: Text(
                'Pinch to zoom, drag to reposition',
                style: TextStyle(fontSize: 13, color: MobileColors.textMuted),
              ),
            ),
            const SizedBox(height: 16),
            if (_decodedImage == null)
              SizedBox(
                height: cropSize,
                child: const Center(
                  child: CircularProgressIndicator(color: MobileColors.primary),
                ),
              )
            else
              Center(
                child: Container(
                  width: cropSize,
                  height: cropSize,
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: MobileColors.primary, width: 2),
                  ),
                  child: ClipRRect(
                    borderRadius: BorderRadius.circular(10),
                    child: RepaintBoundary(
                      key: _cropKey,
                      child: InteractiveViewer(
                        transformationController: _transformController,
                        minScale: 0.5,
                        maxScale: 5.0,
                        constrained: false,
                        child: Image.memory(
                          widget.imageBytes,
                          fit: BoxFit.contain,
                        ),
                      ),
                    ),
                  ),
                ),
              ),
            const SizedBox(height: 20),
            Padding(
              padding: const EdgeInsets.fromLTRB(20, 0, 20, 20),
              child: Row(
                children: [
                  Expanded(
                    child: OutlinedButton(
                      onPressed: _cropping ? null : () => Navigator.of(context).pop(null),
                      style: OutlinedButton.styleFrom(
                        foregroundColor: MobileColors.textSecondary,
                        side: const BorderSide(color: MobileColors.border),
                        padding: const EdgeInsets.symmetric(vertical: 14),
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                      ),
                      child: const Text('Cancel'),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: ElevatedButton(
                      onPressed: _cropping ? null : _cropAndSave,
                      style: ElevatedButton.styleFrom(
                        backgroundColor: MobileColors.primary,
                        foregroundColor: MobileColors.textOnPrimary,
                        padding: const EdgeInsets.symmetric(vertical: 14),
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                      ),
                      child: _cropping
                          ? const SizedBox(
                              width: 20, height: 20,
                              child: CircularProgressIndicator(
                                color: MobileColors.textOnPrimary, strokeWidth: 2,
                              ),
                            )
                          : const Text('Save'),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}

class _CopyableRow extends StatelessWidget {
  final String label;
  final String value;
  final String? fullValue;
  final VoidCallback onCopy;

  const _CopyableRow({
    required this.label,
    required this.value,
    this.fullValue,
    required this.onCopy,
  });

  @override
  Widget build(BuildContext context) {
    return Row(
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
                style: const TextStyle(
                  fontSize: 13,
                  color: MobileColors.textPrimary,
                  fontFamily: 'monospace',
                ),
              ),
            ],
          ),
        ),
        IconButton(
          onPressed: onCopy,
          icon: const Icon(Icons.copy, size: 18, color: MobileColors.textMuted),
          padding: EdgeInsets.zero,
          constraints: const BoxConstraints(),
        ),
      ],
    );
  }
}
