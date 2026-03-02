import 'dart:async';
import 'dart:html' as html;

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
