package com.example.netguard.network

import android.content.Context
import android.content.SharedPreferences
import com.google.gson.Gson
import com.google.gson.JsonSyntaxException
import io.jsonwebtoken.*
import io.jsonwebtoken.security.Keys
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.security.Key
import java.util.*

/**
 * Session Layer (OSI Layer 5)
 * 
 * Manages user sessions, JWT tokens with strict expiry and refresh logic,
 * token persistence, and secure logout (clearing cache).
 * 
 * Implements a state machine for session management:
 * - UNAUTHENTICATED: No valid session
 * - AUTHENTICATED: Valid session with access token
 * - REFRESHING: Currently refreshing tokens
 * - EXPIRED: Session expired, needs re-authentication
 */
class SessionLayer private constructor(context: Context) {
    
    private val prefs: SharedPreferences = context.getSharedPreferences(
        "idps_session_prefs",
        Context.MODE_PRIVATE
    )
    
    private val gson = Gson()
    
    // State machine for session management
    private val _sessionState = MutableStateFlow<SessionState>(SessionState.UNAUTHENTICATED)
    val sessionState: StateFlow<SessionState> = _sessionState.asStateFlow()
    
    // Token storage keys
    private val KEY_ACCESS_TOKEN = "access_token"
    private val KEY_REFRESH_TOKEN = "refresh_token"
    private val KEY_TOKEN_EXPIRY = "token_expiry"
    private val KEY_REFRESH_EXPIRY = "refresh_expiry"
    
    companion object {
        @Volatile
        private var INSTANCE: SessionLayer? = null
        
        fun getInstance(context: Context): SessionLayer {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: SessionLayer(context.applicationContext).also { INSTANCE = it }
            }
        }
    }
    
    init {
        // Restore session state from persistence
        restoreSession()
    }
    
    /**
     * Session State Machine States
     */
    sealed class SessionState {
        object UNAUTHENTICATED : SessionState()
        data class AUTHENTICATED(val accessToken: String, val refreshToken: String) : SessionState()
        object REFRESHING : SessionState()
        object EXPIRED : SessionState()
    }
    
    /**
     * Token data class
     */
    data class TokenPair(
        val accessToken: String,
        val refreshToken: String,
        val accessTokenExpiry: Long,
        val refreshTokenExpiry: Long
    )
    
    /**
     * JWT Claims data class
     */
    data class JwtClaims(
        val userId: String?,
        val username: String?,
        val roles: List<String>?,
        val issuedAt: Long?,
        val expiresAt: Long?
    )
    
    /**
     * Save tokens to persistent storage
     */
    fun saveTokens(tokenPair: TokenPair) {
        prefs.edit().apply {
            putString(KEY_ACCESS_TOKEN, tokenPair.accessToken)
            putString(KEY_REFRESH_TOKEN, tokenPair.refreshToken)
            putLong(KEY_TOKEN_EXPIRY, tokenPair.accessTokenExpiry)
            putLong(KEY_REFRESH_EXPIRY, tokenPair.refreshTokenExpiry)
            apply()
        }
        
        // Update state machine
        _sessionState.value = SessionState.AUTHENTICATED(
            tokenPair.accessToken,
            tokenPair.refreshToken
        )
    }
    
    /**
     * Get current access token
     */
    fun getAccessToken(): String? {
        return prefs.getString(KEY_ACCESS_TOKEN, null)
    }
    
    /**
     * Get current refresh token
     */
    fun getRefreshToken(): String? {
        return prefs.getString(KEY_REFRESH_TOKEN, null)
    }
    
    /**
     * Check if access token is valid (not expired)
     */
    fun isAccessTokenValid(): Boolean {
        val token = getAccessToken() ?: return false
        val expiry = prefs.getLong(KEY_TOKEN_EXPIRY, 0)
        
        if (expiry <= System.currentTimeMillis()) {
            return false
        }
        
        return try {
            // Parse JWT to verify structure
            val claims = parseJwtClaims(token)
            claims.expiresAt?.let { it > System.currentTimeMillis() } ?: false
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Check if refresh token is valid
     */
    fun isRefreshTokenValid(): Boolean {
        val token = getRefreshToken() ?: return false
        val expiry = prefs.getLong(KEY_REFRESH_EXPIRY, 0)
        
        if (expiry <= System.currentTimeMillis()) {
            return false
        }
        
        return try {
            val claims = parseJwtClaims(token)
            claims.expiresAt?.let { it > System.currentTimeMillis() } ?: false
        } catch (e: Exception) {
            false
        }
    }
    
    /**
     * Parse JWT claims without verification (for reading expiry)
     * Note: In production, you should verify the signature
     */
    fun parseJwtClaims(token: String): JwtClaims {
        try {
            // Split JWT into parts
            val parts = token.split(".")
            if (parts.size != 3) {
                throw IllegalArgumentException("Invalid JWT format")
            }
            
            // Decode payload (base64url)
            val payload = parts[1]
            val decoded = Base64.getUrlDecoder().decode(payload)
            val json = String(decoded)
            val claimsMap = gson.fromJson(json, Map::class.java) as Map<*, *>
            
            return JwtClaims(
                userId = claimsMap["sub"]?.toString() ?: claimsMap["userId"]?.toString(),
                username = claimsMap["username"]?.toString(),
                roles = (claimsMap["roles"] as? List<*>)?.map { it.toString() },
                issuedAt = (claimsMap["iat"] as? Number)?.toLong(),
                expiresAt = (claimsMap["exp"] as? Number)?.toLong()
            )
        } catch (e: Exception) {
            throw IllegalArgumentException("Failed to parse JWT: ${e.message}", e)
        }
    }
    
    /**
     * Refresh access token using refresh token
     */
    suspend fun refreshAccessToken(
        refreshCallback: suspend (String) -> Result<TokenPair>
    ): Result<TokenPair> {
        val refreshToken = getRefreshToken()
        
        if (refreshToken == null || !isRefreshTokenValid()) {
            _sessionState.value = SessionState.EXPIRED
            return Result.failure(IllegalStateException("No valid refresh token available"))
        }
        
        _sessionState.value = SessionState.REFRESHING
        
        return try {
            val result = refreshCallback(refreshToken)
            result.onSuccess { tokenPair ->
                saveTokens(tokenPair)
            }.onFailure {
                _sessionState.value = SessionState.EXPIRED
            }
            result
        } catch (e: Exception) {
            _sessionState.value = SessionState.EXPIRED
            Result.failure(e)
        }
    }
    
    /**
     * Get authorization header with current access token
     * Automatically refreshes if needed
     */
    suspend fun getAuthorizationHeader(
        refreshCallback: suspend (String) -> Result<TokenPair> = { 
            Result.failure(IllegalStateException("No refresh callback provided"))
        }
    ): String? {
        return when {
            isAccessTokenValid() -> {
                "Bearer ${getAccessToken()}"
            }
            isRefreshTokenValid() -> {
                // Attempt to refresh
                val refreshResult = refreshAccessToken(refreshCallback)
                refreshResult.getOrNull()?.let {
                    "Bearer ${it.accessToken}"
                } ?: null
            }
            else -> {
                _sessionState.value = SessionState.EXPIRED
                null
            }
        }
    }
    
    /**
     * Restore session from persistent storage
     */
    private fun restoreSession() {
        val accessToken = getAccessToken()
        val refreshToken = getRefreshToken()
        
        when {
            accessToken != null && isAccessTokenValid() -> {
                _sessionState.value = SessionState.AUTHENTICATED(accessToken, refreshToken ?: "")
            }
            refreshToken != null && isRefreshTokenValid() -> {
                // Token expired but refresh token valid - will refresh on next request
                _sessionState.value = SessionState.AUTHENTICATED(accessToken ?: "", refreshToken)
            }
            else -> {
                _sessionState.value = SessionState.UNAUTHENTICATED
            }
        }
    }
    
    /**
     * Secure logout - clear all tokens and cache
     */
    fun logout() {
        prefs.edit().apply {
            remove(KEY_ACCESS_TOKEN)
            remove(KEY_REFRESH_TOKEN)
            remove(KEY_TOKEN_EXPIRY)
            remove(KEY_REFRESH_EXPIRY)
            clear() // Clear all session data
            apply()
        }
        
        _sessionState.value = SessionState.UNAUTHENTICATED
    }
    
    /**
     * Check current session state
     */
    fun isAuthenticated(): Boolean {
        return _sessionState.value is SessionState.AUTHENTICATED && isAccessTokenValid()
    }
}

