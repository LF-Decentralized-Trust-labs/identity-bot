import 'package:flutter/material.dart';

import '../brand/brand.dart';

class MobileColors {
  static const Color primary = Color(0xFF4589FF);
  static const Color primaryLight = Color(0xFF78A9FF);
  static const Color primaryDark = Color(0xFF0F62FE);

  static const Color background = Color(0xFFF4F4F4);
  static const Color surface = Color(0xFFFFFFFF);
  static const Color surfaceSecondary = Color(0xFFF8F9FA);
  static const Color surfaceTertiary = Color(0xFFE8E8E8);

  static const Color textPrimary = Color(0xFF161616);
  static const Color textSecondary = Color(0xFF525252);
  static const Color textMuted = Color(0xFF8D8D8D);
  static const Color textOnPrimary = Color(0xFFFFFFFF);

  static const Color border = Color(0xFFE0E0E0);
  static const Color borderLight = Color(0xFFF0F0F0);
  static const Color divider = Color(0xFFE8E8E8);

  static const Color success = Color(0xFF24A148);
  static const Color warning = Color(0xFFF1C21B);
  static const Color error = Color(0xFFDA1E28);
  static const Color info = Color(0xFF4589FF);

  static const Color confidenceHigh = Color(0xFF24A148);
  static const Color confidenceMedium = Color(0xFFF1C21B);
  static const Color confidenceLow = Color(0xFFDA1E28);

  static const Color bottomNavBackground = Color(0xFFFFFFFF);
  static const Color drawerBackground = Color(0xFFFFFFFF);
  static const Color cardShadow = Color(0x1A000000);

  static const Color scannerBackground = Color(0xFF000000);
  static const Color scannerFrame = Color(0xFF4589FF);
  static const Color scannerLine = Color(0xFF4589FF);
}

class MobileTheme {
  static ThemeData get lightTheme {
    return ThemeData(
      brightness: Brightness.light,
      scaffoldBackgroundColor: MobileColors.background,
      colorScheme: ColorScheme.light(
        primary: currentBrand.primary,
        secondary: currentBrand.primaryLight,
        surface: MobileColors.surface,
        error: MobileColors.error,
        onPrimary: MobileColors.textOnPrimary,
        onSurface: MobileColors.textPrimary,
        onError: MobileColors.textOnPrimary,
      ),
      fontFamily: 'sans-serif',
      textTheme: const TextTheme(
        headlineLarge: TextStyle(
          color: MobileColors.textPrimary,
          fontSize: 28,
          fontWeight: FontWeight.w700,
          letterSpacing: -0.5,
        ),
        headlineMedium: TextStyle(
          color: MobileColors.textPrimary,
          fontSize: 22,
          fontWeight: FontWeight.w600,
        ),
        titleLarge: TextStyle(
          color: MobileColors.textPrimary,
          fontSize: 18,
          fontWeight: FontWeight.w600,
        ),
        titleMedium: TextStyle(
          color: MobileColors.textSecondary,
          fontSize: 16,
          fontWeight: FontWeight.w500,
        ),
        bodyLarge: TextStyle(
          color: MobileColors.textPrimary,
          fontSize: 16,
        ),
        bodyMedium: TextStyle(
          color: MobileColors.textSecondary,
          fontSize: 14,
        ),
        bodySmall: TextStyle(
          color: MobileColors.textMuted,
          fontSize: 12,
        ),
        labelLarge: TextStyle(
          color: MobileColors.primary,
          fontSize: 14,
          fontWeight: FontWeight.w600,
        ),
        labelSmall: TextStyle(
          color: MobileColors.textMuted,
          fontSize: 11,
          fontWeight: FontWeight.w500,
          letterSpacing: 0.5,
        ),
      ),
      appBarTheme: const AppBarTheme(
        backgroundColor: MobileColors.surface,
        foregroundColor: MobileColors.textPrimary,
        elevation: 0,
        centerTitle: true,
        titleTextStyle: TextStyle(
          color: MobileColors.textPrimary,
          fontSize: 18,
          fontWeight: FontWeight.w600,
        ),
      ),
      cardTheme: CardThemeData(
        color: MobileColors.surface,
        elevation: 2,
        shadowColor: MobileColors.cardShadow,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
        ),
        margin: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: MobileColors.primary,
          foregroundColor: MobileColors.textOnPrimary,
          elevation: 0,
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 14),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(8),
          ),
          textStyle: const TextStyle(
            fontSize: 14,
            fontWeight: FontWeight.w600,
          ),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: MobileColors.primary,
          side: const BorderSide(color: MobileColors.primary),
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 14),
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(8),
          ),
          textStyle: const TextStyle(
            fontSize: 14,
            fontWeight: FontWeight.w600,
          ),
        ),
      ),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: MobileColors.surfaceSecondary,
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: const BorderSide(color: MobileColors.border),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: const BorderSide(color: MobileColors.border),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: const BorderSide(color: MobileColors.primary, width: 2),
        ),
        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
        labelStyle: const TextStyle(color: MobileColors.textSecondary),
        hintStyle: const TextStyle(color: MobileColors.textMuted),
      ),
      dividerTheme: const DividerThemeData(
        color: MobileColors.divider,
        thickness: 1,
        space: 1,
      ),
      useMaterial3: true,
    );
  }
}
