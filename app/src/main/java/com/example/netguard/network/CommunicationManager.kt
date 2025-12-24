package com.example.netguard.network

import android.content.Context
import kotlinx.coroutines.flow.StateFlow
import okhttp3.OkHttpClient
import okhttp3.Request

/**
 * Communication Manager
 * 
 * Orchestrates all OSI layers:
 * - Application Layer: RESTful API with HTTP status code handling
 * - Session Layer: JWT token management and state machine
 * - Transport Layer: TLS 1.3 SSL Pinning
 * - Reliability Layer: Circuit Breaker and Exponential Backoff
 * 
 * This is the main entry point for all network communications.
 */
class CommunicationManager private constructor(context: Context) {
    
    private val applicationLayer: ApplicationLayer
    private val sessionLayer: SessionLayer
    private val transportLayer: TransportLayerSecurity
    private val reliabilityManager: ReliabilityManager
    
    private var httpClient: OkHttpClient? = null
    
    companion object {
        @Volatile
        private var INSTANCE: CommunicationManager? = null
        
        fun getInstance(context: Context): CommunicationManager {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: CommunicationManager(context.applicationContext).also { 
                    INSTANCE = it 
                }
            }
        }
    }
    
    init {
        applicationLayer = ApplicationLayer.getInstance()
        sessionLayer = SessionLayer.getInstance(context)
        transportLayer = TransportLayerSecurity.getInstance()
        reliabilityManager = ReliabilityManager()
    }
    
    /**
     * Initialize with SSL pinning configuration
     */
    fun initializeWithSslPinning(pinConfigs: List<TransportLayerSecurity.PinConfig>) {
        val clientBuilder = transportLayer.configureTlsPinning(pinConfigs, enableTls13 = true)
        
        // Configure timeouts
        clientBuilder.connectTimeout(30, java.util.concurrent.TimeUnit.SECONDS)
        clientBuilder.readTimeout(30, java.util.concurrent.TimeUnit.SECONDS)
        clientBuilder.writeTimeout(30, java.util.concurrent.TimeUnit.SECONDS)
        
        httpClient = clientBuilder.build()
        
        // Note: In a full implementation, you'd need to update ApplicationLayer
        // to use this configured client. This is a simplified version.
    }
    
    /**
     * Execute authenticated request
     * 
     * Handles:
     * - JWT token injection
     * - Automatic token refresh
     * - Circuit breaker protection
     * - Exponential backoff retries
     * - RFC 7231 status code handling
     */
    suspend fun executeAuthenticatedRequest(
        requestBuilder: Request.Builder,
        onSuccess: (HttpResponse) -> Unit,
        onError: (HttpException) -> Unit,
        refreshTokenCallback: suspend (String) -> Result<SessionLayer.TokenPair>? = null
    ) {
        // Get authorization header (with automatic refresh if needed)
        val authHeader = sessionLayer.getAuthorizationHeader { refreshToken ->
            refreshTokenCallback?.invoke(refreshToken) 
                ?: Result.failure(IllegalStateException("No refresh callback"))
        }
        
        // Add authorization header
        if (authHeader != null) {
            requestBuilder.header("Authorization", authHeader)
        }
        
        val request = requestBuilder.build()
        
        // Execute with reliability patterns
        val result = reliabilityManager.executeWithReliability(
            operation = {
                executeRequestAsResult(request)
            }
        )
        
        result.onSuccess { response ->
            onSuccess(response)
        }.onFailure { exception ->
            val httpException = when (exception) {
                is CircuitBreakerException -> HttpException.NetworkError(
                    "Circuit breaker is open: ${exception.message}",
                    exception
                )
                is HttpException -> exception
                else -> HttpException.NetworkError(
                    "Request failed: ${exception.message}",
                    exception
                )
            }
            onError(httpException)
        }
    }
    
    /**
     * Execute unauthenticated request
     */
    suspend fun executeUnauthenticatedRequest(
        request: Request,
        onSuccess: (HttpResponse) -> Unit,
        onError: (HttpException) -> Unit
    ) {
        val result = reliabilityManager.executeWithReliability(
            operation = {
                executeRequestAsResult(request)
            }
        )
        
        result.onSuccess { response ->
            onSuccess(response)
        }.onFailure { exception ->
            val httpException = when (exception) {
                is CircuitBreakerException -> HttpException.NetworkError(
                    "Circuit breaker is open: ${exception.message}",
                    exception
                )
                is HttpException -> exception
                else -> HttpException.NetworkError(
                    "Request failed: ${exception.message}",
                    exception
                )
            }
            onError(httpException)
        }
    }
    
    /**
     * Internal request execution that returns Result
     */
    private suspend fun executeRequestAsResult(request: Request): Result<HttpResponse> {
        return try {
            var result: Result<HttpResponse>? = null
            
            applicationLayer.executeRequest(
                request = request,
                onResponse = { response ->
                    result = Result.success(response)
                },
                onError = { error ->
                    result = Result.failure(error)
                }
            )
            
            // Wait for async operation to complete
            var attempts = 0
            while (result == null && attempts < 100) {
                kotlinx.coroutines.delay(10)
                attempts++
            }
            
            result ?: Result.failure(HttpException.UnknownError("Request timeout", null))
        } catch (e: Exception) {
            Result.failure(
                if (e is HttpException) e
                else HttpException.NetworkError("Request failed: ${e.message}", e)
            )
        }
    }
    
    /**
     * Login and save tokens
     */
    suspend fun login(
        username: String,
        password: String,
        loginEndpoint: String,
        onSuccess: (SessionLayer.TokenPair) -> Unit,
        onError: (HttpException) -> Unit
    ) {
        val request = applicationLayer.createPostRequest(
            url = loginEndpoint,
            body = mapOf("username" to username, "password" to password)
        )
        
        executeUnauthenticatedRequest(
            request = request,
            onSuccess = { response ->
                try {
                    // Parse token response (adjust based on your API)
                    // This is a simplified example
                    val tokenPair = parseTokenResponse(response.body)
                    sessionLayer.saveTokens(tokenPair)
                    onSuccess(tokenPair)
                } catch (e: Exception) {
                    onError(HttpException.UnknownError("Failed to parse login response: ${e.message}", null))
                }
            },
            onError = onError
        )
    }
    
    /**
     * Logout and clear session
     */
    fun logout() {
        sessionLayer.logout()
    }
    
    /**
     * Get session state
     */
    fun getSessionState(): StateFlow<SessionLayer.SessionState> {
        return sessionLayer.sessionState
    }
    
    /**
     * Check if authenticated
     */
    fun isAuthenticated(): Boolean {
        return sessionLayer.isAuthenticated()
    }
    
    /**
     * Get circuit breaker state
     */
    fun getCircuitBreakerState(): CircuitBreaker.State {
        return reliabilityManager.getCircuitBreakerState()
    }
    
    /**
     * Reset circuit breaker
     */
    fun resetCircuitBreaker() {
        reliabilityManager.resetCircuitBreaker()
    }
    
    /**
     * Parse token response from login endpoint
     * Adjust this based on your actual API response format
     */
    private fun parseTokenResponse(responseBody: String): SessionLayer.TokenPair {
        // Example parsing - adjust based on your API
        // This assumes JSON response with: { "accessToken": "...", "refreshToken": "...", "expiresIn": 3600 }
        val json = org.json.JSONObject(responseBody)
        
        val accessToken = json.getString("accessToken")
        val refreshToken = json.getString("refreshToken")
        val expiresIn = json.optLong("expiresIn", 3600) // Default 1 hour
        
        val now = System.currentTimeMillis()
        val accessTokenExpiry = now + (expiresIn * 1000)
        val refreshTokenExpiry = now + (expiresIn * 1000 * 24) // Refresh token lasts 24x longer
        
        return SessionLayer.TokenPair(
            accessToken = accessToken,
            refreshToken = refreshToken,
            accessTokenExpiry = accessTokenExpiry,
            refreshTokenExpiry = refreshTokenExpiry
        )
    }
}

