package com.example.netguard.network

import okhttp3.CertificatePinner
import okhttp3.OkHttpClient
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import javax.net.ssl.*

/**
 * Transport Layer Security (TLS 1.3)
 * 
 * Implements SSL Pinning (Certificate Pinning) to prevent
 * Man-in-the-Middle (MitM) attacks.
 * 
 * SSL Pinning ensures the app only communicates with the
 * specific server certificate, preventing certificate
 * authority (CA) compromise attacks.
 */
class TransportLayerSecurity private constructor() {
    
    companion object {
        @Volatile
        private var INSTANCE: TransportLayerSecurity? = null
        
        fun getInstance(): TransportLayerSecurity {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: TransportLayerSecurity().also { INSTANCE = it }
            }
        }
    }
    
    /**
     * Certificate pin configuration
     */
    data class PinConfig(
        val hostname: String,
        val pins: List<String> // SHA-256 hashes of public key pins
    )
    
    /**
     * Create CertificatePinner for OkHttpClient
     * 
     * @param pinConfigs List of pin configurations for different hosts
     * @return CertificatePinner instance
     * 
     * Example:
     * pinConfigs = listOf(
     *     PinConfig(
     *         hostname = "api.example.com",
     *         pins = listOf(
     *             "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
     *             "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
     *         )
     *     )
     * )
     */
    fun createCertificatePinner(pinConfigs: List<PinConfig>): CertificatePinner {
        val builder = CertificatePinner.Builder()
        
        pinConfigs.forEach { config ->
            config.pins.forEach { pin ->
                builder.add(config.hostname, pin)
            }
        }
        
        return builder.build()
    }
    
    /**
     * Configure OkHttpClient with TLS 1.3 and SSL Pinning
     * 
     * @param pinConfigs Certificate pin configurations
     * @param enableTls13 Force TLS 1.3 (if supported)
     * @return Configured OkHttpClient.Builder
     */
    fun configureTlsPinning(
        pinConfigs: List<PinConfig>,
        enableTls13: Boolean = true
    ): OkHttpClient.Builder {
        val builder = OkHttpClient.Builder()
        
        // Apply certificate pinning
        val certificatePinner = createCertificatePinner(pinConfigs)
        builder.certificatePinner(certificatePinner)
        
        // Configure TLS 1.3 (if supported by platform)
        if (enableTls13) {
            try {
                // TLS 1.3 is supported on Android API 29+ (Android 10+)
                // For older versions, TLS 1.2 will be used
                val sslContext = SSLContext.getInstance("TLSv1.3")
                sslContext.init(null, null, null)
                
                builder.sslSocketFactory(
                    sslContext.socketFactory,
                    TrustManagerProxy()
                )
            } catch (e: Exception) {
                // TLS 1.3 not available, fall back to TLS 1.2
                val sslContext = SSLContext.getInstance("TLS")
                sslContext.init(null, null, null)
                
                builder.sslSocketFactory(
                    sslContext.socketFactory,
                    TrustManagerProxy()
                )
            }
        }
        
        return builder
    }
    
    /**
     * Extract SHA-256 pin from certificate
     * Helper method to generate pins from certificates
     * 
     * @param certificate X509Certificate to extract pin from
     * @return SHA-256 pin string
     */
    fun extractPinFromCertificate(certificate: X509Certificate): String {
        val publicKey = certificate.publicKey.encoded
        val sha256 = java.security.MessageDigest.getInstance("SHA-256")
        val hash = sha256.digest(publicKey)
        val base64 = android.util.Base64.encodeToString(hash, android.util.Base64.NO_WRAP)
        return "sha256/$base64"
    }
    
    /**
     * Custom TrustManager that validates certificates
     * In addition to pinning, this provides an extra layer of validation
     */
    private class TrustManagerProxy : X509TrustManager {
        private val defaultTrustManager: X509TrustManager
        
        init {
            val trustManagerFactory = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm()
            )
            trustManagerFactory.init(null as KeyStore?)
            defaultTrustManager = trustManagerFactory.trustManagers
                .first { it is X509TrustManager } as X509TrustManager
        }
        
        override fun checkClientTrusted(
            chain: Array<out X509Certificate>?,
            authType: String?
        ) {
            defaultTrustManager.checkClientTrusted(chain, authType)
        }
        
        override fun checkServerTrusted(
            chain: Array<out X509Certificate>?,
            authType: String?
        ) {
            defaultTrustManager.checkServerTrusted(chain, authType)
        }
        
        override fun getAcceptedIssuers(): Array<X509Certificate> {
            return defaultTrustManager.acceptedIssuers
        }
    }
    
    /**
     * Validate certificate chain
     * Additional validation beyond pinning
     */
    fun validateCertificateChain(chain: Array<X509Certificate>): Boolean {
        if (chain.isEmpty()) return false
        
        try {
            // Check certificate expiry
            val now = System.currentTimeMillis()
            chain.forEach { cert ->
                cert.checkValidity()
            }
            
            // Additional validations can be added here:
            // - Check certificate purpose
            // - Validate certificate chain
            // - Check revocation status (OCSP/CRL)
            
            return true
        } catch (e: Exception) {
            return false
        }
    }
}

/**
 * Predefined pin configurations for common scenarios
 */
object PinConfigurations {
    /**
     * Example configuration - replace with your actual server pins
     * 
     * To get your server's certificate pin:
     * 1. Connect to your server
     * 2. Extract the certificate
     * 3. Generate SHA-256 hash of the public key
     * 4. Format as "sha256/BASE64_HASH"
     */
    fun getDefaultPins(): List<TransportLayerSecurity.PinConfig> {
        return listOf(
            // Example - replace with actual pins
            TransportLayerSecurity.PinConfig(
                hostname = "api.example.com",
                pins = listOf(
                    // Primary pin
                    "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    // Backup pin (for certificate rotation)
                    "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
                )
            )
        )
    }
}

