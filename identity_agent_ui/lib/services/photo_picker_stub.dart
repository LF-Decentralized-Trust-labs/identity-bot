import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'package:image_picker/image_picker.dart';

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
