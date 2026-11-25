# Release (R8) rules.
# Keep line numbers so Play / crash reports stay readable after obfuscation.
-keepattributes SourceFile,LineNumberTable,*Annotation*,Signature,InnerClasses,EnclosingMethod,Exceptions
-renamesourcefileattribute SourceFile

# --- Capacitor --------------------------------------------------------------
# The bridge finds plugins and their methods by annotation and reflection, and
# exposes a @JavascriptInterface to the WebView. Capacitor ships these rules in
# capacitor/proguard-rules.pro but not as consumer rules, so repeat them here.
-keep class com.getcapacitor.** { *; }
-keep @com.getcapacitor.annotation.CapacitorPlugin public class * {
    @com.getcapacitor.annotation.PermissionCallback <methods>;
    @com.getcapacitor.annotation.ActivityCallback <methods>;
    @com.getcapacitor.annotation.Permission <methods>;
    @com.getcapacitor.PluginMethod public <methods>;
}
-keep public class * extends com.getcapacitor.Plugin { *; }
-keep @com.getcapacitor.NativePlugin public class * {
    @com.getcapacitor.PluginMethod public <methods>;
}
-keep public class * extends org.apache.cordova.* {
    public <methods>;
    public <fields>;
}
-keepclassmembers class * {
    @android.webkit.JavascriptInterface <methods>;
}

# --- native shell ------------------------------------------------------------
# Plugins are registered by class and called reflectively by the bridge.
-keep class nz.co.oraflows.orasec.** { *; }

# --- Capgo plugins (reflection / JSON models) ----------------------------------
-keep class ee.forgr.** { *; }
-keep class app.capgo.** { *; }

# Stripe Terminal ships its own consumer R8 rules (no extra keeps needed).

# AGP 9 / R8 9.x repackages classes by default. That moved
# kotlin.collections.CollectionsKt__MutableCollectionsJVMKt out of its package
# while its package-private parent (kept by Stripe's Tap to Pay rules) stayed,
# and the app crashed at start-up (IllegalAccessError from FirebaseApp.<clinit>).
-dontrepackage

# --- Edge-to-edge -----------------------------------------------------------------
# MainActivity calls androidx.activity.EdgeToEdge.enable(), the call Play asks
# apps targeting SDK 35+ to make. Keep its class names (names only; R8 still
# shrinks and optimises them) so Play's edge-to-edge check can recognise the
# call, and so its "deprecated API" report names androidx.activity.EdgeToEdgeApi*
# instead of c.s/c.t/c.v/c.x. Those deprecated bar-colour calls are androidx's
# backward-compatible code for Android 6-14; on Android 15+ they are not used.
-keepnames class androidx.activity.EdgeToEdge** { *; }

# --- WorkManager / Room (via @capgo/capacitor-updater) -------------------------
# Room 2.6's consumer rule keeps RoomDatabase subclasses but not their
# constructors. In R8 full mode (AGP 9 default) a bare -keep class does not keep
# <init>(), so WorkDatabase_Impl lost its no-arg constructor and the release
# build crashed at start-up: "Unable to get provider
# androidx.startup.InitializationProvider ... NoSuchMethodException:
# androidx.work.impl.WorkDatabase_Impl.<init> []". Room creates it reflectively.
-keep class * extends androidx.room.RoomDatabase { <init>(); }
