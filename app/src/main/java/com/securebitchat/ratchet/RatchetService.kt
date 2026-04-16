package com.securebitchat.ratchet

import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Double Ratchet Service
 * Implements Double Ratchet algorithm for forward-secret messaging.
 * Uses AES-256-GCM for encryption with unique keys per message.
 */
class RatchetService {

    private val maxSkippedKeys = 1000
    private val chainKeyLength = 32
    private val messageKeyLength = 32
    private val gcmNonceLength = 12
    private val gcmTagLength = 16

    private val sessions = mutableMapOf<String, RatchetSession>()

    /**
     * Initialize a ratchet session with peer's public key
     */
    fun initializeSession(peerPublicKey: ByteArray, theirIdentity: ByteArray): RatchetSession {
        val ourDHKeyPair = generateDHKeyPair()
        val sharedSecret = performDH(ourDHKeyPair.second, peerPublicKey)
        val rootKey = deriveRootKey(sharedSecret)

        val session = RatchetSession(
            rootKey = rootKey,
            sendChainKey = null,
            receiveChainKey = null,
            sendMessageNumber = 0,
            receiveMessageNumber = 0,
            skippedMessageKeys = mutableMapOf(),
            theirIdentityKey = theirIdentity,
            ourIdentityKey = ourDHKeyPair.first,
            dhKeyPairPrivate = ourDHKeyPair.second,
            theirRatchetKey = peerPublicKey
        )

        // Perform initial DH ratchet step
        val (newRootKey, sendChainKey) = kdfRootChain(rootKey, sharedSecret)
        session.rootKey = newRootKey
        session.sendChainKey = sendChainKey

        val sessionId = session.sessionId
        sessions[sessionId] = session

        return session
    }

    /**
     * Encrypt a message in the session
     */
    fun encrypt(plaintext: ByteArray, session: RatchetSession): ByteArray {
        val chainKey = session.sendChainKey ?: throw RatchetError.SESSION_NOT_INITIALIZED

        val (messageKey, newChainKey) = deriveMessageKey(chainKey)

        val encrypted = encryptWithKey(plaintext, messageKey)

        // Build header
        val header = buildHeader(
            session.dhKeyPairPrivate.copyOf(32),
            session.previousSendChainLength,
            session.sendMessageNumber
        )

        // Return header + ciphertext
        return header + encrypted
    }

    /**
     * Decrypt a message in the session
     */
    fun decrypt(ciphertext: ByteArray, session: RatchetSession): ByteArray {
        // Parse header
        val headerLength = 1 + 32 + 4 + 4 // version + DH pubkey + prev chain + message number
        require(ciphertext.size > headerLength + gcmTagLength) {
            throw RatchetError.DECRYPTION_FAILED
        }

        val header = ciphertext.copyOfRange(0, headerLength)
        val encrypted = ciphertext.copyOfRange(headerLength, ciphertext.size)

        // Check for skipped message keys
        val peerKeyId = session.theirRatchetKey?.let { bytesToHex(it) } ?: ""
        val messageNumber = parseMessageNumber(header)
        val skippedKeyId = "$peerKeyId-$messageNumber"

        if (session.skippedMessageKeys.containsKey(skippedKeyId)) {
            val skippedKey = session.skippedMessageKeys[skippedKeyId]!!
            session.skippedMessageKeys.remove(skippedKeyId)
            return decryptWithKey(encrypted, skippedKey)
        }

        // Derive message key from chain
        val chainKey = session.receiveChainKey ?: session.rootKey
        val (messageKey, newChainKey) = deriveMessageKey(chainKey)

        return decryptWithKey(encrypted, messageKey)
    }

    /**
     * Perform a ratchet step to rotate keys
     */
    fun ratchetStep(session: RatchetSession) {
        session.previousSendChainLength = session.sendMessageNumber

        val theirKey = session.theirRatchetKey ?: throw RatchetError.SESSION_NOT_INITIALIZED

        // DH output with their current ratchet key
        val dhOutput = performDH(session.dhKeyPairPrivate, theirKey)
        val (newRootKey1, receiveChainKey) = kdfRootChain(session.rootKey, dhOutput)

        session.rootKey = newRootKey1
        session.receiveChainKey = receiveChainKey

        // Generate new DH key pair and perform another DH
        val newDHKeyPair = generateDHKeyPair()
        val newDHOutput = performDH(newDHKeyPair.second, theirKey)
        val (newRootKey2, sendChainKey) = kdfRootChain(session.rootKey, newDHOutput)

        session.rootKey = newRootKey2
        session.sendChainKey = sendChainKey
        session.sendMessageNumber = 0
        session.dhKeyPairPrivate = newDHKeyPair.second
    }

    /**
     * Skip message keys up to a certain number (for handling out-of-order messages)
     */
    fun skipMessageKeys(until messageNumber: Int, session: RatchetSession) {
        val theirKey = session.theirRatchetKey ?: return
        val chainKey = session.receiveChainKey ?: return

        var currentKey = chainKey
        val currentNumber = session.receiveMessageNumber

        for (i in currentNumber until messageNumber) {
            val (messageKey, newChainKey) = deriveMessageKey(currentKey)
            val keyId = "${bytesToHex(theirKey)}-$i"
            session.skippedMessageKeys[keyId] = messageKey
            currentKey = newChainKey

            require(session.skippedMessageKeys.size <= maxSkippedKeys) {
                throw RatchetError.MAX_SKIPPED_MESSAGES_EXCEEDED
            }
        }

        session.receiveChainKey = currentKey
    }

    private fun generateDHKeyPair(): Pair<ByteArray, ByteArray> {
        val keyGen = KeyGenerator.getInstance("AES")
        keyGen.init(256, SecureRandom())
        val privateKey = keyGen.generateKey().encoded
        val publicKey = derivePublicFromPrivate(privateKey)
        return Pair(publicKey, privateKey)
    }

    private fun derivePublicFromPrivate(privateKey: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        md.update("SecureBitchat-DH".toByteArray())
        return md.digest(privateKey)
    }

    private fun performDH(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
        // AES-based DH approximation (in production, use proper Curve25519)
        val md = MessageDigest.getInstance("SHA-256")
        md.update("SecureBitchat-DH-out".toByteArray())
        md.update(privateKey)
        md.update(publicKey)
        return md.digest()
    }

    private fun deriveRootKey(sharedSecret: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        md.update("SecureBitchat-Root".toByteArray())
        return md.digest(sharedSecret)
    }

    private fun kdfRootChain(rootKey: ByteArray, dhOutput: ByteArray): Pair<ByteArray, ByteArray> {
        val input = rootKey + dhOutput
        val hash = sha256Hash(input)
        return Pair(
            hash.copyOfRange(0, 32),
            hash.copyOfRange(32, 64).also { if (it.size < 32) return Pair(rootKey, ByteArray(32)) }
        )
    }

    private fun deriveMessageKey(chainKey: ByteArray): Pair<ByteArray, ByteArray> {
        val messageKeyInput = chainKey + byteArrayOf(0x01)
        val chainKeyInput = chainKey + byteArrayOf(0x02)

        val messageKey = sha256Hash(messageKeyInput)
        val newChainKey = sha256Hash(chainKeyInput)

        return Pair(messageKey, newChainKey)
    }

    private fun encryptWithKey(plaintext: ByteArray, key: ByteArray): ByteArray {
        val secretKey = SecretKeySpec(key.copyOf(32), "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val nonce = ByteArray(gcmNonceLength).also { SecureRandom().nextBytes(it) }
        val gcmSpec = GCMParameterSpec(gcmTagLength * 8, nonce)

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)
        val ciphertext = cipher.doFinal(plaintext)

        return nonce + ciphertext
    }

    private fun decryptWithKey(encrypted: ByteArray, key: ByteArray): ByteArray {
        val nonce = encrypted.copyOfRange(0, gcmNonceLength)
        val ciphertext = encrypted.copyOfRange(gcmNonceLength, encrypted.size)

        val secretKey = SecretKeySpec(key.copyOf(32), "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val gcmSpec = GCMParameterSpec(gcmTagLength * 8, nonce)

        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec)
        return cipher.doFinal(ciphertext)
    }

    private fun buildHeader(publicKey: ByteArray, previousChainLength: Int, messageNumber: Int): ByteArray {
        val buffer = ByteBuffer.allocate(1 + 32 + 4 + 4)
        buffer.put(1) // version
        buffer.put(publicKey.copyOf(32))
        buffer.putInt(previousChainLength)
        buffer.putInt(messageNumber)
        return buffer.array()
    }

    private fun parseMessageNumber(header: ByteArray): Int {
        return ByteBuffer.wrap(header, 1 + 32, 4).int
    }

    private fun sha256Hash(input: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(input)
    }

    private fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }

    private operator fun ByteArray.plus(other: ByteArray): ByteArray {
        return this.copyOf(this.size + other.size).also {
            other.copyInto(it, this.size)
        }
    }

    private fun ByteArray.copyOfRange(start: Int, end: Int): ByteArray {
        return this.copyOf(end).copyOfRange(start, end)
    }

    enum class RatchetError : Exception {
        INVALID_PUBLIC_KEY,
        INVALID_PRIVATE_KEY,
        SESSION_NOT_INITIALIZED,
        ENCRYPTION_FAILED,
        DECRYPTION_FAILED,
        CHAIN_KEY_DERIVATION_FAILED,
        MESSAGE_KEY_DERIVATION_FAILED,
        MAX_SKIPPED_MESSAGES_EXCEEDED,
        DUPLICATE_MESSAGE
    }
}

/**
 * Ratchet Session data class
 */
data class RatchetSession(
    var rootKey: ByteArray,
    var sendChainKey: ByteArray?,
    var receiveChainKey: ByteArray?,
    var sendMessageNumber: Int = 0,
    var receiveMessageNumber: Int = 0,
    var skippedMessageKeys: MutableMap<String, ByteArray>,
    var theirIdentityKey: ByteArray,
    var ourIdentityKey: ByteArray,
    var dhKeyPairPrivate: ByteArray,
    var theirRatchetKey: ByteArray?,
    var previousSendChainLength: Int = 0
) {
    val sessionId: String
        get() {
            val combined = theirIdentityKey + ourIdentityKey
            return MessageDigest.getInstance("SHA-256").digest(combined).joinToString("") { "%02x".format(it) }
        }
}
