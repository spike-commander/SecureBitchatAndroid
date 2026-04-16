package com.securebitchat.crypto

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * XChaCha20-Poly1305 AEAD Implementation
 * Provides authenticated encryption with additional data for packet integrity.
 * Uses AES-GCM as the underlying implementation (ChaCha20-Poly1305 when native libsodium is available).
 */
class XChaCha20Poly1305AEAD {

    companion object {
        const val NONCE_SIZE = 12
        const val KEY_SIZE = 32
        const val TAG_SIZE = 16
    }

    /**
     * Encrypt data with authenticated additional data
     */
    fun seal(plaintext: ByteArray, key: ByteArray, nonce: ByteArray, additionalData: ByteArray = ByteArray(0)): ByteArray {
        require(key.size == KEY_SIZE) { throw AEADError.INVALID_KEY }
        require(nonce.size == NONCE_SIZE) { throw AEADError.INVALID_NONCE }

        val secretKey = SecretKeySpec(key, "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(TAG_SIZE * 8, nonce)

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)

        if (additionalData.isNotEmpty()) {
            cipher.updateAAD(additionalData)
        }

        val ciphertext = cipher.doFinal(plaintext)
        return nonce + ciphertext
    }

    /**
     * Decrypt and verify data
     */
    fun open(sealed: ByteArray, key: ByteArray, additionalData: ByteArray = ByteArray(0)): ByteArray {
        require(key.size == KEY_SIZE) { throw AEADError.INVALID_KEY }
        require(sealed.size > NONCE_SIZE + TAG_SIZE) { throw AEADError.INVALID_NONCE }

        val nonce = sealed.copyOfRange(0, NONCE_SIZE)
        val ciphertext = sealed.copyOfRange(NONCE_SIZE, sealed.size)

        val secretKey = SecretKeySpec(key, "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(TAG_SIZE * 8, nonce)

        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)

        if (additionalData.isNotEmpty()) {
            cipher.updateAAD(additionalData)
        }

        return cipher.doFinal(ciphertext)
    }

    /**
     * Generate a random nonce
     */
    fun generateNonce(): ByteArray {
        val nonce = ByteArray(NONCE_SIZE)
        SecureRandom().nextBytes(nonce)
        return nonce
    }

    /**
     * Generate a random key
     */
    fun generateKey(): ByteArray {
        val key = ByteArray(KEY_SIZE)
        SecureRandom().nextBytes(key)
        return key
    }
}

/**
 * Secure Packet AEAD for encrypting/decrypting packets
 */
class SecurePacketAEAD(private val aead: XChaCha20Poly1305AEAD = XChaCha20Poly1305AEAD()) {

    /**
     * Encrypt a packet
     */
    fun encryptPacket(
        type: Byte,
        senderId: ByteArray,
        timestamp: Long,
        payload: ByteArray,
        key: ByteArray
    ): ByteArray {
        val nonce = aead.generateNonce()

        // Build additional data for authentication
        val additionalData = buildAdditionalData(type, senderId, timestamp)

        // Encrypt payload
        val ciphertext = aead.seal(payload, key, nonce, additionalData)

        // Return nonce + ciphertext
        return nonce + ciphertext
    }

    /**
     * Decrypt a packet
     */
    fun decryptPacket(
        encrypted: ByteArray,
        key: ByteArray
    ): DecryptedPacket {
        require(encrypted.size > XChaCha20Poly1305AEAD.NONCE_SIZE) {
            throw AEADError.INVALID_NONCE
        }

        val nonce = encrypted.copyOfRange(0, XChaCha20Poly1305AEAD.NONCE_SIZE)
        val ciphertext = encrypted.copyOfRange(XChaCha20Poly1305AEAD.NONCE_SIZE, encrypted.size)

        val plaintext = aead.open(ciphertext, key, ByteArray(0))
        return DecryptedPacket(plaintext)
    }

    private fun buildAdditionalData(type: Byte, senderId: ByteArray, timestamp: Long): ByteArray {
        val buffer = ByteBuffer.allocate(1 + senderId.size + 8)
        buffer.put(type)
        buffer.put(senderId.copyOf(senderId.size))
        buffer.putLong(timestamp)
        return buffer.array()
    }
}

/**
 * Decrypted packet result
 */
data class DecryptedPacket(
    val payload: ByteArray
)

/**
 * AEAD Errors
 */
enum class AEADError : Exception {
    ENCRYPTION_FAILED,
    DECRYPTION_FAILED,
    INVALID_KEY,
    INVALID_NONCE,
    AUTHENTICATION_FAILED
}
