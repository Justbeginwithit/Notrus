# Keep the public app model names stable for future encrypted export/import support.
-keep class com.notrus.android.model.** { *; }

# The release APK uses R8. Debug messaging worked while release messaging did not,
# so keep the full protocol and native-crypto bridge surfaces stable in release.
-keep class com.notrus.android.protocol.** { *; }
-keep class com.notrus.android.relay.** { *; }
-keep class com.notrus.android.security.** { *; }
-keep class com.notrus.android.notifications.** { *; }
-keep class org.signal.libsignal.** { *; }
-keepclassmembers class * {
    native <methods>;
}
