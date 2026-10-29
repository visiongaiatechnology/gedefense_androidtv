# GeDefense TV minimal ProGuard/R8 rules.
# The app uses no reflection-based serialization and no AndroidX. Keep only the entry points that
# R8 cannot infer from the manifest, plus line numbers for readable crash reports.

-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile

# Keep the application/activity entry points referenced from the manifest.
-keep class de.visiongaia.gedefense.tv.TvApplication { *; }
-keep class de.visiongaia.gedefense.tv.TvMainActivity { *; }
-keep class de.visiongaia.gedefense.tv.platform.TvThreatIntelJobService { *; }

# Vendored dependency-free core keeps predictable class names for the local verification harness.
-keepnames class de.visiongaia.gedefense.mobile.core.** { *; }
-keepnames class de.visiongaia.gedefense.tv.core.** { *; }
