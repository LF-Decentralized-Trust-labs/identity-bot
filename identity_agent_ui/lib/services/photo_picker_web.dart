import 'dart:async';
import 'dart:convert';
import 'dart:html' as html;
import 'dart:typed_data';
import 'package:flutter/material.dart';
import '../widgets/avatar_crop_dialog.dart';

Future<String?> pickPhotoBase64() async {
  final completer = Completer<String?>();
  final input = html.FileUploadInputElement()..accept = 'image/*';
  input.click();

  input.onChange.listen((event) {
    final files = input.files;
    if (files == null || files.isEmpty) {
      completer.complete(null);
      return;
    }

    final reader = html.FileReader();
    reader.readAsDataUrl(files[0]);
    reader.onLoadEnd.listen((event) {
      final result = reader.result as String?;
      if (result != null) {
        final commaIndex = result.indexOf(',');
        if (commaIndex != -1) {
          completer.complete(result.substring(commaIndex + 1));
        } else {
          completer.complete(null);
        }
      } else {
        completer.complete(null);
      }
    });
    reader.onError.listen((_) => completer.complete(null));
  });

  return completer.future;
}

/// Web version: picks a file via browser dialog, shows the crop dialog, and
/// returns a base64-encoded PNG. Returns null if cancelled at any step.
Future<String?> pickAndCropPhotoBase64(BuildContext context) async {
  final base64Raw = await pickPhotoBase64();
  if (base64Raw == null) return null;
  if (!context.mounted) return null;

  final bytes = Uint8List.fromList(base64Decode(base64Raw));
  return AvatarCropDialog.toBase64(context, bytes);
}
