# ── R8 / ProGuard rules for AeroBox ──

# Preserve attributes needed by Kotlin reflection / generic type info / Room /
# OkHttp / SnakeYAML when they walk class metadata at runtime. Cheap to keep
# and avoids subtle release-only NPEs the day we add a generics-aware lib.
-keepattributes Signature, InnerClasses, EnclosingMethod, *Annotation*

# ProxyType names are persisted in SQLite.
-keep enum com.aerobox.data.model.ProxyType { *; }

# Keep JNI native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

-keep class com.aerobox.core.native.RustCoreNative { *; }
-keep interface com.aerobox.core.native.RustCoreNative$PlatformCallbacks { *; }
-keepclassmembers class * implements com.aerobox.core.native.RustCoreNative$PlatformCallbacks {
    public boolean protect(int);
    public java.lang.String dnsServers();
    public boolean supportsSystemDns();
    public void startDnsQuery(long, long, long, byte[]);
    public void cancelDnsQuery(long);
    public java.lang.String connectionOwner(int, java.lang.String, int, java.lang.String, int);
    public java.lang.String physicalNetworks();
    public boolean protectOnNetwork(int, long, long);
}

# OkHttp
-dontwarn okhttp3.**
-dontwarn okio.**
-dontwarn javax.annotation.**

# SnakeYAML references java.beans on desktop JDKs, but those code paths are not
# used by our SafeConstructor-based Android Map parsing flow.
-keep,allowshrinking class org.yaml.snakeyaml.** { *; }
-dontwarn org.yaml.snakeyaml.**
-dontwarn java.beans.**

# Strip verbose logging in release
-assumenosideeffects class android.util.Log {
    public static int v(...);
    public static int d(...);
}
