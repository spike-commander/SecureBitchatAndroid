# Add project specific ProGuard rules here.

# Keep libsodium native methods
-keep class org.libsodium.** { *; }

# Keep signal protocol classes
-keep class org.signal.** { *; }

# Keep our classes
-keep class com.securebitchat.** { *; }

# Gson
-keepattributes Signature
-keepattributes *Annotation*
-keep class com.google.gson.** { *; }
-keep class * implements com.google.gson.TypeAdapterFactory
-keep class * implements com.google.gson.JsonSerializer
-keep class * implements com.google.gson.JsonDeserializer

# Keep Ratchet classes
-keep class com.securebitchat.ratchet.** { *; }
-keep class com.securebitchat.protocols.** { *; }
-keep class com.securebitchat.rooms.** { *; }
