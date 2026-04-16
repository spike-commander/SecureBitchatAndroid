# SecureBitchat Android

A hardened security fork of BitChat for Android with production-ready security and private rooms.

## Features

- **Buffer Overflow Protection**: 64-byte signature validation
- **Payload Truncation**: Max 65,535 bytes
- **Mentions DoS Protection**: Max 10 mentions, 256 chars each
- **Replay Attack Protection**: 24-hour timestamp window
- **MITM Protection**: QR OOB fingerprint verification
- **Ephemeral Key Rotation**: Every 1 hour
- **Forward Secrecy**: Double Ratchet encryption
- **Compression Leak Prevention**: Fixed-padding
- **AEAD Encryption**: XChaCha20-Poly1305
- **Private Rooms**: Argon2id key derivation

## Building

### Prerequisites

- Android Studio Hedgehog or later
- Android SDK 34
- Kotlin 1.9+
- NDK (optional, for libsodium native)

### Build APK

```bash
cd SecureBitchatAndroid

# Using Gradle
./gradlew assembleDebug

# Or using Gradle wrapper
gradle assembleDebug
```

### Install on Device

```bash
adb install app/build/outputs/apk/debug/app-debug.apk
```

## Project Structure

```
SecureBitchatAndroid/
├── app/
│   ├── src/main/
│   │   ├── java/com/securebitchat/
│   │   │   ├── protocols/
│   │   │   │   └── SecureBinaryProtocol.kt  # Hardened protocol
│   │   │   ├── security/
│   │   │   │   ├── SecureIdentityManager.kt # MITM protection
│   │   │   │   └── SecureKeychainManager.kt # Secure storage
│   │   │   ├── ratchet/
│   │   │   │   └── RatchetService.kt         # Double Ratchet
│   │   │   ├── rooms/
│   │   │   │   └── PrivateRoomManager.kt     # Private rooms
│   │   │   ├── crypto/
│   │   │   │   └── XChaCha20Poly1305AEAD.kt  # AEAD encryption
│   │   │   ├── SecureBitchatApp.kt          # Application
│   │   │   ├── MainActivity.kt               # Main UI
│   │   │   └── SecureBLEService.kt           # BLE mesh
│   │   └── res/
│   └── build.gradle.kts
├── build.gradle.kts
├── settings.gradle.kts
├── gradle.properties
└── README.md
```

## Security Architecture

### Double Ratchet

Each message uses a unique encryption key derived from:
1. Root key (shared secret)
2. Chain keys (per-message derivation)
3. Ratchet step (DH key rotation)

### Private Rooms

1. Creator generates room ID and derives key using Argon2id
2. Invites shared via signed QR code (5-min validity)
3. Member changes trigger automatic rekey
4. All messages encrypted with AES-256-GCM
5. Traffic padding hides message sizes

### Key Rotation

- Ephemeral keys rotate every 1 hour
- Room keys rotate on member join/leave
- Ratchet steps rotate on DH exchange

## Testing

```bash
./gradlew test
./gradlew connectedAndroidTest
```

## License

Public domain - See LICENSE file
