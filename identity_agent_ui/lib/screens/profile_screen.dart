import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter/material.dart';
import '../theme/app_theme.dart';
// ignore_for_file: library_private_types_in_public_api
import 'package:agent_client/services/core_service.dart';
import 'package:agent_client/services/keri_service.dart';
import 'package:agent_client/services/mobile_on_device_keri_service.dart';
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
  late final CoreService _coreService = CoreService(baseUrl: _resolveServerUrl());

  String? _resolveServerUrl() {
    if (widget.serverUrl != null) return widget.serverUrl;
    if (widget.keriService is MobileOnDeviceKeriService) {
      final standalone = widget.keriService as MobileOnDeviceKeriService;
      if (standalone.isCoreReady) return standalone.mobileCore.baseUrl;
    }
    return null;
  }

  final _fnController         = TextEditingController();
  final _givenNameController  = TextEditingController();
  final _familyNameController = TextEditingController();
  final _orgController        = TextEditingController();   // kept for data round-trip
  final _titleController      = TextEditingController();  // kept for data round-trip
  final _emailController      = TextEditingController();
  final _telController        = TextEditingController();
  final _noteController       = TextEditingController();

  bool _loading        = true;
  bool _saving         = false;
  bool _savedIndicator = false;
  String? _error;
  String _photoBase64  = '';

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
        _fnController.text         = profile.fullName;
        _givenNameController.text  = profile.givenName;
        _familyNameController.text = profile.familyName;
        _orgController.text        = profile.org;
        _titleController.text      = profile.title;
        _emailController.text      = profile.email;
        _telController.text        = profile.tel;
        _noteController.text       = profile.note;
        _photoBase64               = profile.photo;
        _loading                   = false;
      });
    } catch (e) {
      setState(() {
        _error   = 'Failed to load profile: $e';
        _loading = false;
      });
    }
  }

  Future<void> _saveProfile() async {
    if (_saving) return;
    setState(() { _saving = true; _error = null; });
    try {
      await _coreService.saveProfile(ProfileResponse(
        fullName:   _fnController.text.trim(),
        givenName:  _givenNameController.text.trim(),
        familyName: _familyNameController.text.trim(),
        org:        _orgController.text.trim(),
        title:      _titleController.text.trim(),
        email:      _emailController.text.trim(),
        tel:        _telController.text.trim(),
        note:       _noteController.text.trim(),
        photo:      _photoBase64,
      ));
      if (mounted) {
        setState(() { _saving = false; _savedIndicator = true; });
        Future.delayed(const Duration(seconds: 2), () {
          if (mounted) setState(() => _savedIndicator = false);
        });
      }
    } catch (e) {
      if (mounted) setState(() { _saving = false; _error = 'Failed to save: $e'; });
    }
  }

  Future<void> _pickPhoto() async {
    try {
      final base64 = await photo_picker.pickAndCropPhotoBase64(context);
      if (base64 != null && base64.isNotEmpty) {
        setState(() => _photoBase64 = base64);
        _saveProfile();
      }
    } catch (e) {
      setState(() => _error = 'Failed to pick photo: $e');
    }
  }

  void _removePhoto() {
    setState(() => _photoBase64 = '');
    _saveProfile();
  }

  // ── Photo ────────────────────────────────────────────────────────────────────

  Widget _buildPhotoSection() {
    Widget avatar;
    if (_photoBase64.isNotEmpty) {
      try {
        avatar = CircleAvatar(
          radius: 52,
          backgroundImage: MemoryImage(Uint8List.fromList(base64Decode(_photoBase64))),
          backgroundColor: AppColors.surfaceLight,
        );
      } catch (_) {
        avatar = _defaultAvatar();
      }
    } else {
      avatar = _defaultAvatar();
    }

    return Row(
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        MouseRegion(
          cursor: SystemMouseCursors.click,
          child: GestureDetector(
            onTap: _pickPhoto,
            child: Stack(
              alignment: Alignment.bottomRight,
              children: [
                avatar,
                Container(
                  padding: const EdgeInsets.all(5),
                  decoration: const BoxDecoration(
                    color: AppColors.accent,
                    shape: BoxShape.circle,
                  ),
                  child: const Icon(Icons.camera_alt, size: 15, color: AppColors.primary),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(width: 20),
        Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Profile Photo',
              style: TextStyle(color: AppColors.textPrimary, fontSize: 14, fontWeight: FontWeight.w600),
            ),
            const SizedBox(height: 4),
            const Text(
              'Click photo to change',
              style: TextStyle(color: AppColors.textMuted, fontSize: 12),
            ),
            if (_photoBase64.isNotEmpty) ...[
              const SizedBox(height: 6),
              GestureDetector(
                onTap: _removePhoto,
                child: const Text(
                  'Remove',
                  style: TextStyle(color: AppColors.error, fontSize: 12),
                ),
              ),
            ],
          ],
        ),
      ],
    );
  }

  CircleAvatar _defaultAvatar() => const CircleAvatar(
        radius: 52,
        backgroundColor: AppColors.surfaceLight,
        child: Icon(Icons.person, size: 48, color: AppColors.textMuted),
      );

  // ── Field ────────────────────────────────────────────────────────────────────

  Widget _buildField(
    String label,
    TextEditingController controller, {
    int maxLines = 1,
    TextInputType? keyboardType,
    double? width,
  }) {
    Widget field = Padding(
      padding: const EdgeInsets.only(bottom: 16),
      child: Column(
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
          const SizedBox(height: 6),
          TextField(
            controller: controller,
            maxLines: maxLines,
            keyboardType: keyboardType,
            style: const TextStyle(color: AppColors.textPrimary, fontSize: 14),
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

    if (width != null) {
      return SizedBox(width: width, child: field);
    }
    return field;
  }

  // ── Build ────────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: SafeArea(
        child: _loading
            ? const Center(child: CircularProgressIndicator(color: AppColors.accent))
            : SingleChildScrollView(
                padding: EdgeInsets.fromLTRB(
                  AppLayout.isMobile(context) ? 16 : 32,
                  AppLayout.isMobile(context) ? 16 : 32,
                  AppLayout.isMobile(context) ? 16 : 32,
                  48,
                ),
                child: Align(
                  alignment: Alignment.topLeft,
                  child: ConstrainedBox(
                    constraints: const BoxConstraints(maxWidth: 560),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        // ── Header (desktop only) ───────────────────────────
                        if (!AppLayout.isMobile(context)) ...[
                          const Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Text(
                                'My Profile',
                                style: TextStyle(
                                  color: AppColors.textPrimary,
                                  fontSize: 22,
                                  fontWeight: FontWeight.w700,
                                ),
                              ),
                              SizedBox(height: 2),
                              Text(
                                'Your digital identity card.',
                                style: TextStyle(color: AppColors.textSecondary, fontSize: 13),
                              ),
                            ],
                          ),
                          const SizedBox(height: 28),
                        ],

                        // ── Photo ────────────────────────────────────────────
                        _buildPhotoSection(),
                        const SizedBox(height: 28),

                        // ── Error ────────────────────────────────────────────
                        if (_error != null) ...[
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
                        ],

                        // ── Fields ───────────────────────────────────────────
                        _buildField('Display Name', _fnController),
                        Row(
                          children: [
                            Expanded(child: _buildField('Given Name', _givenNameController)),
                            const SizedBox(width: 12),
                            Expanded(child: _buildField('Family Name', _familyNameController)),
                          ],
                        ),
                        _buildField('Email', _emailController, keyboardType: TextInputType.emailAddress),
                        _buildField('Phone', _telController, keyboardType: TextInputType.phone),
                        _buildField('Note / Bio', _noteController, maxLines: 3),
                        const SizedBox(height: 8),
                        Row(
                          children: [
                            SizedBox(
                              width: 160,
                              height: 42,
                              child: ElevatedButton(
                                onPressed: _saving ? null : _saveProfile,
                                child: _saving
                                    ? const SizedBox(
                                        width: 18,
                                        height: 18,
                                        child: CircularProgressIndicator(
                                          color: Colors.white,
                                          strokeWidth: 2,
                                        ),
                                      )
                                    : const Text('Save Profile'),
                              ),
                            ),
                            const SizedBox(width: 12),
                            AnimatedOpacity(
                              opacity: _savedIndicator ? 1.0 : 0.0,
                              duration: const Duration(milliseconds: 300),
                              child: const Row(
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  Icon(Icons.check_circle, color: Color(0xFF24A148), size: 15),
                                  SizedBox(width: 4),
                                  Text(
                                    'Saved',
                                    style: TextStyle(
                                      color: Color(0xFF24A148),
                                      fontSize: 12,
                                      fontWeight: FontWeight.w500,
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
              ),
      ),
    );
  }
}
