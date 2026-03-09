# ── R8 / ProGuard rules for AeroBox ──

# Keep Room entities and DAO (required by annotation processor)
-keep class com.aerobox.data.model.** { *; }
-keep class com.aerobox.data.database.** { *; }

# Keep JNI native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep gomobile-generated libbox classes
-keep class io.nekohasekai.libbox.** { *; }
-dontwarn io.nekohasekai.libbox.**

# OkHttp
-dontwarn okhttp3.**
-dontwarn okio.**
-dontwarn javax.annotation.**

# SnakeYAML references java.beans on desktop JDKs, but those code paths are not
# used by our Android Map-based parsing flow.
-keep class org.yaml.snakeyaml.** { *; }
-dontwarn org.yaml.snakeyaml.**
-dontwarn java.beans.**

# Strip verbose logging in release
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
}

# Optimize aggressively
-optimizationpasses 5
-allowaccessmodification
-repackageclasses ''
