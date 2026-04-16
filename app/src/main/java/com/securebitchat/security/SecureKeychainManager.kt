package com.securebitchat.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import android.util.Base64

/**
 * Secure Keychain Manager
 * 
 * Android secure storage using EncryptedSharedPreferences and Android Keystore.
 * Provides secure storage for cryptographic keys and sensitive data.
 */
class SecureKeychainManager(private val context: Context) {

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val encryptedPrefs = EncryptedSharedPreferences.create(
        context,
        PREFS_NAME,
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    private val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    /**
     * Save data with a string key
     */
    fun save(key: String, data: ByteArray): Boolean {
        return try {
            val encoded = Base64.encodeToString(data, Base64.NO_WRAP)
            encryptedPrefs.edit().putString(key, encoded).apply()
            true
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Get data by key
     */
    fun getData(key: String): ByteArray? {
        return try {
            encryptedPrefs.getString(key, null)?.let {
                Base64.decode(it, Base64.NO_WRAP)
            }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Delete data by key
     */
    fun delete(key: String): Boolean {
        return try {
            encryptedPrefs.edit().remove(key).apply()
            true
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Save double value
     */
    fun saveDouble(key: String, value: Double) {
        encryptedPrefs.edit().putFloat(key, value.toFloat()).apply()
    }

    /**
     * Get double value
     */
    fun getDouble(key: String): Double? {
        return try {
            if (encryptedPrefs.contains(key)) {
                encryptedPrefs.getFloat(key, 0f).toDouble()
            } else null
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Generate and store a symmetric key in Android Keystore
     */
    fun generateSymmetricKey(alias: String): SecretKey {
        return if (keyStore.containsAlias(alias)) {
            keyStore.getKey(alias, null) as SecretKey
        } else {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                ANDROID_KEYSTORE
            )
            val keySpec = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(false)
                .build()

            keyGenerator.init(keySpec)
            keyGenerator.generateKey()
        }
    }

    /**
     * Delete all stored data
     */
    fun deleteAll() {
        encryptedPrefs.edit().clear().apply()
        // Clear key store entries
        keyStore.aliases().toList().forEach { alias ->
            keyStore.deleteEntry(alias)
        }
    }

    companion object {
        private const val PREFS_NAME = "secure_bitchat_prefs"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }
}
