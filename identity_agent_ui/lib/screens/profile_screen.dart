import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart' show kIsWeb;
import '../theme/app_theme.dart';
import '../services/core_service.dart';
import '../services/keri_service.dart';
import '../services/photo_picker_stub.dart'
    if (dart.library.html) '../services/photo_picker_web.dart' as photo_picker;

class ProfileScreen extends StatefulWidget {
  final KeriService keriService;
  final String? serverUrl;

  const ProfileScreen({
    super.key,
    required this.keriService,
    this.serverUrl,
  });

  @override
  State<ProfileScreen> createState() => _ProfileScreenState();
}

class _ProfileScreenState extends State<ProfileScreen> {
  late final CoreService _coreService = CoreService(baseUrl: widget.serverUrl);

  final _fnController = TextEditingController();
  final _givenNameController = TextEditingController();
  final _familyNameController = TextEditingController();
  final _orgController = TextEditingController();
  final _titleController = TextEditingController();
  final _emailController = TextEditingController();
  final _telController = TextEditingController();
  final _noteController = TextEditingController();

  bool _loading = true;
  bool _saving = false;
  String? _error;
  String? _successMessage;
  String _photoBase64 = '';

  @override
  void initState() {
    super.initState();
    _loadProfile();
  }

  @override
  void dispose() {
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

  Future<void> _loadProfile() async {
    try {
      final profile = await _coreService.getProfile();
      setState(() {
        _fnController.text = profile.fullName;
        _givenNameController.text = profile.givenName;
        _familyNameController.text = profile.familyName;
        _orgController.text = profile.org;
        _titleController.text = profile.title;
        _emailController.text = profile.email;
        _telController.text = profile.tel;
        _noteController.text = profile.note;
        _photoBase64 = profile.photo;
        _loading = false;
      });
    } catch (e) {
      setState(() {
        _error = 'Failed to load profile: $e';
        _loading = false;
      });
    }
  }

  Future<void> _saveProfile() async {
    setState(() {
      _saving = true;
      _error = null;
      _successMessage = null;
    });

    try {
      final profile = ProfileResponse(
        fullName: _fnController.text.trim(),
        givenName: _givenNameController.text.trim(),
        familyName: _familyNameController.text.trim(),
        org: _orgController.text.trim(),
        title: _titleController.text.trim(),
        email: _emailController.text.trim(),
        tel: _telController.text.trim(),
        note: _noteController.text.trim(),
        photo: _photoBase64,
      );
      await _coreService.saveProfile(profile);
      setState(() {
        _saving = false;
        _successMessage = 'Profile saved';
      });
      Future.delayed(const Duration(seconds: 3), () {
        if (mounted) {
          setState(() => _successMessage = null);
        }
      });
    } catch (e) {
      setState(() {
        _saving = false;
        _error = 'Failed to save profile: $e';
      });
    }
  }

  Future<void> _pickPhoto() async {
    try {
      final base64 = await photo_picker.pickPhotoBase64();
      if (base64 != null && base64.isNotEmpty) {
        setState(() {
          _photoBase64 = base64;
        });
      }
    } catch (e) {
      setState(() {
        _error = 'Failed to pick photo: $e';
      });
    }
  }

  void _removePhoto() {
    setState(() {
      _photoBase64 = '';
    });
  }

  Widget _buildPhotoSection() {
    Widget photoWidget;
    if (_photoBase64.isNotEmpty) {
      try {
        final bytes = base64Decode(_photoBase64);
        photoWidget = CircleAvatar(
          radius: 50,
          backgroundImage: MemoryImage(Uint8List.fromList(bytes)),
          backgroundColor: AppColors.surfaceLight,
        );
      } catch (_) {
        photoWidget = const CircleAvatar(
          radius: 50,
          backgroundColor: AppColors.surfaceLight,
          child: Icon(Icons.person, size: 50, color: AppColors.textMuted),
        );
      }
    } else {
      photoWidget = const CircleAvatar(
        radius: 50,
        backgroundColor: AppColors.surfaceLight,
        child: Icon(Icons.person, size: 50, color: AppColors.textMuted),
      );
    }

    return Column(
      children: [
        GestureDetector(
          onTap: _pickPhoto,
          child: Stack(
            alignment: Alignment.bottomRight,
            children: [
              photoWidget,
              Container(
                padding: const EdgeInsets.all(4),
                decoration: const BoxDecoration(
                  color: AppColors.accent,
                  shape: BoxShape.circle,
                ),
                child: const Icon(Icons.camera_alt, size: 16, color: AppColors.primary),
              ),
            ],
          ),
        ),
        if (_photoBase64.isNotEmpty)
          TextButton(
            onPressed: _removePhoto,
            child: const Text(
              'REMOVE PHOTO',
              style: TextStyle(
                color: AppColors.error,
                fontSize: 11,
                fontFamily: 'monospace',
                letterSpacing: 1.0,
              ),
            ),
          ),
      ],
    );
  }

  Widget _buildField(String label, TextEditingController controller, {int maxLines = 1, TextInputType? keyboardType}) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            label.toUpperCase(),
            style: const TextStyle(
              color: AppColors.textMuted,
              fontSize: 10,
              fontWeight: FontWeight.w600,
              letterSpacing: 1.5,
              fontFamily: 'monospace',
            ),
          ),
          const SizedBox(height: 6),
          TextField(
            controller: controller,
            maxLines: maxLines,
            keyboardType: keyboardType,
            style: const TextStyle(
              color: AppColors.textPrimary,
              fontSize: 14,
              fontFamily: 'monospace',
            ),
            decoration: InputDecoration(
              filled: true,
              fillColor: AppColors.surfaceLight,
              contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
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
            ),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: AppColors.primary,
      body: SafeArea(
        child: _loading
            ? const Center(child: CircularProgressIndicator(color: AppColors.accent))
            : SingleChildScrollView(
                padding: const EdgeInsets.all(20),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    const Text(
                      'PROFILE',
                      style: TextStyle(
                        color: AppColors.accent,
                        fontSize: 20,
                        fontWeight: FontWeight.w700,
                        letterSpacing: 2.0,
                        fontFamily: 'monospace',
                      ),
                      textAlign: TextAlign.center,
                    ),
                    const SizedBox(height: 4),
                    const Text(
                      'Your digital identity card (jCard)',
                      style: TextStyle(
                        color: AppColors.textSecondary,
                        fontSize: 12,
                        fontFamily: 'monospace',
                      ),
                      textAlign: TextAlign.center,
                    ),
                    const SizedBox(height: 24),
                    Center(child: _buildPhotoSection()),
                    const SizedBox(height: 24),
                    if (_error != null)
                      Container(
                        margin: const EdgeInsets.only(bottom: 16),
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          color: AppColors.error.withOpacity(0.1),
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(color: AppColors.error.withOpacity(0.3)),
                        ),
                        child: Text(
                          _error!,
                          style: const TextStyle(color: AppColors.error, fontSize: 12, fontFamily: 'monospace'),
                        ),
                      ),
                    if (_successMessage != null)
                      Container(
                        margin: const EdgeInsets.only(bottom: 16),
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          color: AppColors.accent.withOpacity(0.1),
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(color: AppColors.accent.withOpacity(0.3)),
                        ),
                        child: Row(
                          children: [
                            const Icon(Icons.check_circle, color: AppColors.accent, size: 16),
                            const SizedBox(width: 8),
                            Text(
                              _successMessage!,
                              style: const TextStyle(color: AppColors.accent, fontSize: 12, fontFamily: 'monospace'),
                            ),
                          ],
                        ),
                      ),
                    _buildField('Display Name', _fnController),
                    Row(
                      children: [
                        Expanded(child: _buildField('Given Name', _givenNameController)),
                        const SizedBox(width: 12),
                        Expanded(child: _buildField('Family Name', _familyNameController)),
                      ],
                    ),
                    _buildField('Organization', _orgController),
                    _buildField('Title / Role', _titleController),
                    _buildField('Email', _emailController, keyboardType: TextInputType.emailAddress),
                    _buildField('Phone', _telController, keyboardType: TextInputType.phone),
                    _buildField('Note', _noteController, maxLines: 3),
                    const SizedBox(height: 8),
                    SizedBox(
                      height: 48,
                      child: ElevatedButton(
                        onPressed: _saving ? null : _saveProfile,
                        style: ElevatedButton.styleFrom(
                          backgroundColor: AppColors.accent,
                          foregroundColor: AppColors.primary,
                          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                          textStyle: const TextStyle(
                            fontSize: 14,
                            fontWeight: FontWeight.w700,
                            letterSpacing: 1.5,
                            fontFamily: 'monospace',
                          ),
                        ),
                        child: _saving
                            ? const SizedBox(
                                height: 20,
                                width: 20,
                                child: CircularProgressIndicator(color: AppColors.primary, strokeWidth: 2),
                              )
                            : const Text('SAVE PROFILE'),
                      ),
                    ),
                    const SizedBox(height: 24),
                  ],
                ),
              ),
      ),
    );
  }
}
