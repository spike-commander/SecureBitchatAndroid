package com.securebitchat

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.securebitchat.rooms.PrivateRoomManager
import com.securebitchat.protocols.SecureBinaryProtocol
import com.securebitchat.protocols.SecureBitchatPacket
import android.util.Base64
import android.widget.Toast

/**
 * Main Activity for SecureBitchat
 */
class MainActivity : AppCompatActivity() {

    private lateinit var roomManager: PrivateRoomManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val app = application as SecureBitchatApp
        roomManager = app.privateRoomManager

        demonstrateSecurity()
    }

    private fun demonstrateSecurity() {
        // Demonstrate secure protocol
        demonstrateSecureProtocol()

        // Demonstrate private rooms
        demonstratePrivateRooms()
    }

    private fun demonstrateSecureProtocol() {
        val payload = "Hello, Secure World!".toByteArray()
        val timestamp = System.currentTimeMillis()

        val packet = SecureBitchatPacket(
            type = 0x01,
            senderId = ByteArray(8).also { java.util.Arrays.fill(it, 0xAB.toByte()) },
            recipientId = null,
            timestamp = timestamp,
            payload = payload,
            signature = null,
            ttl = 7
        )

        // Encode with security checks
        val encoded = SecureBinaryProtocol.encode(packet, padding = true)
        println("Encoded packet size: ${encoded.size} bytes")

        // Decode with replay protection
        val decoded = SecureBinaryProtocol.decode(encoded)
        println("Decoded payload: ${String(decoded.payload)}")

        // Test mention parsing with DoS protection
        try {
            val mentions = SecureBinaryProtocol.parseMentions("@alice @bob @charlie hello")
            println("Found mentions: $mentions")
        } catch (e: SecureBinaryProtocol.ProtocolError) {
            println("Mention parsing failed: $e")
        }

        // Test payload truncation protection
        try {
            val largePayload = ByteArray(SecureBinaryProtocol.MAX_PAYLOAD_SIZE + 1) { 0xFF.toByte() }
            val badPacket = SecureBitchatPacket(
                type = 0x01,
                senderId = ByteArray(8),
                recipientId = null,
                timestamp = timestamp,
                payload = largePayload,
                signature = null,
                ttl = 7
            )
            SecureBinaryProtocol.encode(badPacket)
            println("ERROR: Large payload should have been rejected!")
        } catch (e: Exception) {
            println("Large payload correctly rejected: $e")
        }

        Toast.makeText(this, "Security demo complete!", Toast.LENGTH_SHORT).show()
    }

    private fun demonstratePrivateRooms() {
        try {
            // Create a private room
            val room = roomManager.createRoom("Secret Room", "strongPassword123")
            println("Created room: ${room.name} (${room.id})")

            // Encrypt a message
            val secretMessage = "This is a secret!".toByteArray()
            val encrypted = roomManager.encryptMessage(secretMessage, room)
            println("Encrypted size: ${encrypted.size} bytes (padded)")

            // Decrypt the message
            val decrypted = roomManager.decryptMessage(encrypted, room)
            println("Decrypted: ${String(decrypted)}")

            // Generate invite QR
            val inviteQR = roomManager.generateInviteQR(room)
            println("Invite QR generated: ${inviteQR.take(20)}...")

            // Add a member (triggers rekey)
            val newMember = ByteArray(32).also { java.util.Arrays.fill(it, 0xCD.toByte()) }
            roomManager.addMember(newMember, room)
            println("Member added, room rekeyed")

            Toast.makeText(this, "Room demo complete!", Toast.LENGTH_SHORT).show()

        } catch (e: Exception) {
            println("Room demo failed: $e")
        }
    }
}
