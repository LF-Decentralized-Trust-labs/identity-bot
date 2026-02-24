import 'package:flutter/material.dart';

class AppColors {
  static const Color primary = Color(0xFF0A1628);
  static const Color surface = Color(0xFF0F1D32);
  static const Color surfaceLight = Color(0xFF162440);
  static const Color accent = Color(0xFF00E5A0);
  static const Color accentDim = Color(0xFF00B37D);
  static const Color warning = Color(0xFFFF6B35);
  static const Color error = Color(0xFFFF4757);
  static const Color textPrimary = Color(0xFFF0F4F8);
  static const Color textSecondary = Color(0xFF8B9DC3);
  static const Color textMuted = Color(0xFF4A5B7A);
  static const Color border = Color(0xFF1E3254);
  static const Color coreActive = Color(0xFF00E5A0);
  static const Color coreInactive = Color(0xFFFF4757);
  static const Color corePending = Color(0xFFFFBE0B);
}

class AppTheme {
  static ThemeData get darkTheme {
    return ThemeData(
      brightness: Brightness.dark,
      scaffoldBackgroundColor: AppColors.primary,
      colorScheme: const ColorScheme.dark(
        primary: AppColors.accent,
        secondary: AppColors.accentDim,
        surface: AppColors.surface,
        error: AppColors.error,
      ),
      fontFamily: 'monospace',
      textTheme: const TextTheme(
        headlineLarge: TextStyle(
          color: AppColors.textPrimary,
          fontSize: 28,
          fontWeight: FontWeight.w700,
          letterSpacing: -0.5,
        ),
        headlineMedium: TextStyle(
          color: AppColors.textPrimary,
          fontSize: 22,
          fontWeight: FontWeight.w600,
        ),
        titleLarge: TextStyle(
          color: AppColors.textPrimary,
          fontSize: 18,
          fontWeight: FontWeight.w600,
        ),
        titleMedium: TextStyle(
          color: AppColors.textSecondary,
          fontSize: 14,
          fontWeight: FontWeight.w500,
          letterSpacing: 1.2,
        ),
        bodyLarge: TextStyle(
          color: AppColors.textPrimary,
          fontSize: 16,
        ),
        bodyMedium: TextStyle(
          color: AppColors.textSecondary,
          fontSize: 14,
        ),
        labelSmall: TextStyle(
          color: AppColors.textMuted,
          fontSize: 11,
          fontWeight: FontWeight.w500,
          letterSpacing: 1.5,
        ),
      ),
      appBarTheme: const AppBarTheme(
        backgroundColor: Colors.transparent,
        elevation: 0,
      ),
      useMaterial3: true,
    );
  }
}
