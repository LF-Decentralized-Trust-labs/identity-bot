import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:image_picker/image_picker.dart';
import '../widgets/avatar_crop_dialog.dart';

Future<String?> pickPhotoBase64() async {
  final picker = ImagePicker();
  final picked = await picker.pickImage(
    source: ImageSource.gallery,
    maxWidth: 1024,
    maxHeight: 1024,
    imageQuality: 85,
  );

  if (picked == null) return null;

  final bytes = await File(picked.path).readAsBytes();
  return base64Encode(bytes);
}

/// Picks a photo from the gallery, shows the pan-and-zoom crop dialog, and
/// returns the cropped image as a base64-encoded PNG string.
/// Returns null if the user cancels at any step.
Future<String?> pickAndCropPhotoBase64(BuildContext context) async {
  final picker = ImagePicker();
  final picked = await picker.pickImage(
    source: ImageSource.gallery,
    maxWidth: 2048,
    maxHeight: 2048,
    imageQuality: 95,
  );

  if (picked == null) return null;
  if (!context.mounted) return null;

  final bytes = await File(picked.path).readAsBytes();
  if (!context.mounted) return null;

  return AvatarCropDialog.toBase64(context, bytes);
}
