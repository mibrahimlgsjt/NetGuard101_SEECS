package com.example.netguard.network

import android.content.Context
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * Usage Example for Communication Manager
 * 
 * Demonstrates how to use the networking stack with all OSI layers:
 * - Application Layer (HTTP status codes)
 * - Session Layer (JWT tokens)
 * - Transport Layer (SSL Pinning)
 * - Reliability Layer (Circuit Breaker + Exponential Backoff)
 */
class NetworkUsageExample(private val context: Context) {
    
    private val communicationManager = CommunicationManager.getInstance(context)
    
    /**
     * Initialize the networking stack with SSL pinning
     */
    fun initialize() {
        // Configure SSL pinning for your server
        val pinConfigs = listOf(
            TransportLayerSecurity.PinConfig(
                hostname = "api.example.com",
                pins = listOf(
                    // Replace with your actual certificate pins
                    // Get these from your server's SSL certificate
                    "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
                )
            )
        )
        
        communicationManager.initializeWithSslPinning(pinConfigs)
    }
    
    /**
     * Example: Login and authenticate
     */
    fun loginExample(username: String, password: String) {
        CoroutineScope(Dispatchers.IO).launch {
            communicationManager.login(
                username = username,
                password = password,
                loginEndpoint = "https://api.example.com/auth/login",
                onSuccess = { tokenPair ->
                    println("Login successful! Access token: ${tokenPair.accessToken.take(20)}...")
                    // Token is automatically saved and session state updated
                },
                onError = { error ->
                    when (error) {
                        is HttpException.ClientError -> {
                            println("Client error: ${error.code} - ${error.message}")
                        }
                        is HttpException.ServerError -> {
                            println("Server error: ${error.code} - ${error.message}")
                        }
                        is HttpException.NetworkError -> {
                            println("Network error: ${error.message}")
                        }
                        else -> {
                            println("Unknown error: ${error.message}")
                        }
                    }
                }
            )
        }
    }
    
    /**
     * Example: Make authenticated API request
     */
    fun makeAuthenticatedRequest() {
        CoroutineScope(Dispatchers.IO).launch {
            val requestBuilder = ApplicationLayer.getInstance().createGetRequest(
                url = "https://api.example.com/user/profile",
                headers = mapOf(
                    "Content-Type" to "application/json",
                    "Accept" to "application/json"
                )
            )
            
            communicationManager.executeAuthenticatedRequest(
                requestBuilder = requestBuilder,
                onSuccess = { response ->
                    // Handle RFC 7231 status codes
                    when (response.statusCode) {
                        in 200..299 -> {
                            println("Success! Response: ${response.body}")
                        }
                        in 300..399 -> {
                            println("Redirect detected: ${response.statusCode}")
                        }
                        else -> {
                            println("Unexpected status: ${response.statusCode}")
                        }
                    }
                },
                onError = { error ->
                    when (error) {
                        is HttpException.ClientError -> {
                            if (error.code == 401) {
                                // Unauthorized - token might be expired
                                println("Unauthorized - session may have expired")
                            } else {
                                println("Client error: ${error.code}")
                            }
                        }
                        is HttpException.ServerError -> {
                            // 5xx errors trigger exponential backoff retries
                            println("Server error: ${error.code} - Will retry with backoff")
                        }
                        is HttpException.NetworkError -> {
                            println("Network error: ${error.message}")
                        }
                        else -> {
                            println("Error: ${error.message}")
                        }
                    }
                },
                refreshTokenCallback = { refreshToken ->
                    // Implement your token refresh endpoint
                    refreshAccessToken(refreshToken)
                }
            )
        }
    }
    
    /**
     * Example: Refresh access token
     */
    private suspend fun refreshAccessToken(refreshToken: String): Result<SessionLayer.TokenPair> {
        val request = ApplicationLayer.getInstance().createPostRequest(
            url = "https://api.example.com/auth/refresh",
            body = mapOf("refreshToken" to refreshToken)
        )
        
        return try {
            // Execute refresh request
            // Parse response and return TokenPair
            // This is a simplified example
            Result.failure(Exception("Implement token refresh endpoint"))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
    
    /**
     * Example: Monitor session state
     */
    fun monitorSessionState() {
        CoroutineScope(Dispatchers.Main).launch {
            communicationManager.getSessionState().collect { state ->
                when (state) {
                    is SessionLayer.SessionState.UNAUTHENTICATED -> {
                        println("Session: Not authenticated")
                    }
                    is SessionLayer.SessionState.AUTHENTICATED -> {
                        println("Session: Authenticated")
                    }
                    is SessionLayer.SessionState.REFRESHING -> {
                        println("Session: Refreshing tokens...")
                    }
                    is SessionLayer.SessionState.EXPIRED -> {
                        println("Session: Expired - re-authentication required")
                    }
                }
            }
        }
    }
    
    /**
     * Example: Monitor circuit breaker state
     */
    fun checkCircuitBreakerState() {
        val state = communicationManager.getCircuitBreakerState()
        when (state) {
            CircuitBreaker.State.CLOSED -> {
                println("Circuit Breaker: CLOSED - Normal operation")
            }
            CircuitBreaker.State.OPEN -> {
                println("Circuit Breaker: OPEN - Too many failures, blocking requests")
                // Optionally reset after some time
                // communicationManager.resetCircuitBreaker()
            }
            CircuitBreaker.State.HALF_OPEN -> {
                println("Circuit Breaker: HALF_OPEN - Testing recovery")
            }
        }
    }
    
    /**
     * Example: Logout and clear session
     */
    fun logoutExample() {
        communicationManager.logout()
        println("Logged out - all tokens cleared")
    }
    
    /**
     * Example: Make POST request with body
     */
    fun makePostRequest() {
        CoroutineScope(Dispatchers.IO).launch {
            val requestBody = mapOf(
                "name" to "John Doe",
                "email" to "john@example.com"
            )
            
            val requestBuilder = ApplicationLayer.getInstance().createPostRequest(
                url = "https://api.example.com/users",
                body = requestBody,
                headers = mapOf(
                    "Content-Type" to "application/json"
                )
            )
            
            communicationManager.executeAuthenticatedRequest(
                requestBuilder = requestBuilder,
                onSuccess = { response ->
                    when (response.statusCode) {
                        201 -> {
                            println("Resource created successfully")
                        }
                        200 -> {
                            println("Request successful")
                        }
                        else -> {
                            println("Status: ${response.statusCode}")
                        }
                    }
                },
                onError = { error ->
                    println("Error: ${error.message}")
                }
            )
        }
    }
}

