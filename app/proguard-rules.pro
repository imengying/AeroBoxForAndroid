# ── R8 / ProGuard rules for AeroBox ──

# Preserve attributes needed by Kotlin reflection / generic type info / Room /
# OkHttp / SnakeYAML when they walk class metadata at runtime. Cheap to keep
# and avoids subtle release-only NPEs the day we add a generics-aware lib.
-keepattributes Signature, InnerClasses, EnclosingMethod, *Annotation*

# Room-generated code directly accesses these types, and ProxyType names are
# persisted in SQLite. Keep the persistence contract stable across releases.
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
# used by our SafeConstructor-based Android Map parsing flow.
-dontwarn java.beans.**

# Strip verbose logging in release
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
}
