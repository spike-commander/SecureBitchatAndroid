package com.securebitchat

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.bluetooth.le.BluetoothLeAdvertiser
import android.bluetooth.le.BluetoothLeScanner
import android.bluetooth.le.ScanCallback
import android.bluetooth.le.ScanFilter
import android.bluetooth.le.ScanResult
import android.bluetooth.le.ScanSettings
import android.content.Context
import android.content.Intent
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import com.securebitchat.crypto.SecurePacketAEAD
import com.securebitchat.protocols.SecureBinaryProtocol
import com.securebitchat.protocols.SecureBitchatPacket

/**
 * Secure BLE Service for mesh communication
 */
class SecureBLEService : Service() {

    private val binder = LocalBinder()
    private lateinit var bluetoothAdapter: BluetoothAdapter
    private lateinit var bleAdvertiser: BluetoothLeAdvertiser
    private lateinit var bleScanner: BluetoothLeScanner
    private val aead = SecurePacketAEAD()

    companion object {
        private const val TAG = "SecureBLEService"
        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_ID = "SecureBitchatBLE"

        // Service UUID for SecureBitchat
        val SERVICE_UUID = java.util.UUID.fromString("F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5A")
        val CHARACTERISTIC_UUID = java.util.UUID.fromString("A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D")
    }

    inner class LocalBinder : Binder() {
        fun getService(): SecureBLEService = this@SecureBLEService
    }

    override fun onCreate() {
        super.onCreate()
        initializeBluetooth()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIFICATION_ID, createNotification())
        return START_STICKY
    }

    override fun onBind(intent: Intent): IBinder = binder

    private fun initializeBluetooth() {
        val bluetoothManager = getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        bluetoothAdapter = bluetoothManager.adapter

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            bleAdvertiser = bluetoothAdapter.bluetoothLeAdvertiser
            bleScanner = bluetoothAdapter.bluetoothLeScanner
        }
    }

    /**
     * Start advertising SecureBitchat service
     */
    fun startAdvertising() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            val settings = AdvertiseSettings.Builder()
                .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
                .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_HIGH)
                .setConnectable(true)
                .build()

            val data = AdvertiseData.Builder()
                .setIncludeDeviceName(false) // Privacy: don't include name
                .addServiceUuid(java.util.UUID.fromString(SERVICE_UUID.toString()))
                .build()

            bleAdvertiser.startAdvertising(settings, data, advertiseCallback)
        }
    }

    /**
     * Start scanning for peers
     */
    fun startScanning() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            val filters = listOf(
                ScanFilter.Builder()
                    .setServiceUuid(android.os.ParcelUuid(SERVICE_UUID))
                    .build()
            )

            val settings = ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                .build()

            bleScanner.startScan(filters, settings, scanCallback)
        }
    }

    /**
     * Stop all BLE operations
     */
    fun stop() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            try {
                bleAdvertiser.stopAdvertising(advertiseCallback)
                bleScanner.stopScan(scanCallback)
            } catch (e: Exception) {
                Log.e(TAG, "Error stopping BLE: $e")
            }
        }
    }

    /**
     * Send encrypted message to peer
     */
    fun sendEncryptedMessage(
        payload: ByteArray,
        recipientId: ByteArray,
        encryptionKey: ByteArray
    ): Boolean {
        val packet = SecureBitchatPacket(
            type = 0x01, // Message type
            senderId = getMyPeerId(),
            recipientId = recipientId,
            timestamp = System.currentTimeMillis(),
            payload = payload,
            signature = null,
            ttl = 7,
            nonce = generateNonce()
        )

        return try {
            // Encode packet
            val encoded = SecureBinaryProtocol.encode(packet, padding = true)

            // Encrypt with AEAD
            val encrypted = aead.encryptPacket(
                type = packet.type,
                senderId = packet.senderId,
                timestamp = packet.timestamp,
                payload = encoded,
                key = encryptionKey
            )

            // TODO: Send via BLE characteristic
            Log.d(TAG, "Encrypted message ready: ${encrypted.size} bytes")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to send message: $e")
            false
        }
    }

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings?) {
            Log.d(TAG, "BLE advertising started")
        }

        override fun onStartFailure(errorCode: Int) {
            Log.e(TAG, "BLE advertising failed: $errorCode")
        }
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult?) {
            result?.device?.let { device ->
                Log.d(TAG, "Found device: ${device.address}")
                handleDiscoveredPeer(device, result)
            }
        }

        override fun onBatchResults(results: MutableList<ScanResult>?) {
            results?.forEach { result ->
                handleDiscoveredPeer(result.device, result)
            }
        }

        override fun onScanFailed(errorCode: Int) {
            Log.e(TAG, "BLE scan failed: $errorCode")
        }
    }

    private fun handleDiscoveredPeer(device: android.bluetooth.BluetoothDevice, result: ScanResult) {
        // TODO: Connect to peer and perform secure handshake
        Log.d(TAG, "Discovered peer: ${device.address}")
    }

    private fun getMyPeerId(): ByteArray {
        // In production, use stable peer ID derived from identity key
        return ByteArray(8).also {
            java.util.Arrays.fill(it, (Math.random() * 256).toByte())
        }
    }

    private fun generateNonce(): Long {
        return System.currentTimeMillis()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "SecureBitchat Mesh",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Bluetooth mesh networking for SecureBitchat"
            }

            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("SecureBitchat")
            .setContentText("Mesh networking active")
            .setSmallIcon(android.R.drawable.ic_menu_share)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    override fun onDestroy() {
        stop()
        super.onDestroy()
    }
}
