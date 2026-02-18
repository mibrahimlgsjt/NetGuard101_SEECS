package com.example.netguard.network

import com.google.gson.Gson
import com.google.gson.JsonSyntaxException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * Application Layer (OSI Layer 7)
 * 
 * Implements RESTful interface with strict HTTP Status Code handling
 * following RFC 7231 standards.
 * 
 * RFC 7231 Status Code Categories:
 * - 1xx: Informational
 * - 2xx: Success
 * - 3xx: Redirection
 * - 4xx: Client Error
 * - 5xx: Server Error
 */
class ApplicationLayer private constructor() {
    
    private val client: OkHttpClient
    private val gson = Gson()
    
    companion object {
        @Volatile
        private var INSTANCE: ApplicationLayer? = null
        
        fun getInstance(): ApplicationLayer {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: ApplicationLayer().also { INSTANCE = it }
            }
        }
    }
    
    init {
        client = OkHttpClient.Builder()
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .build()
    }
    
    /**
     * Configure the HTTP client with custom settings
     */
    fun configureClient(builder: OkHttpClient.Builder.() -> Unit) {
        val newBuilder = client.newBuilder()
        builder(newBuilder)
        // Note: In a real implementation, you'd need to recreate the instance
        // This is a simplified version
    }
    
    /**
     * Execute HTTP request with RFC 7231 status code handling
     */
    suspend fun executeRequest(
        request: Request,
        onResponse: (HttpResponse) -> Unit,
        onError: (HttpException) -> Unit
    ) {
        try {
            val response = withContext(Dispatchers.IO) {
                client.newCall(request).execute()
            }
            val httpResponse = parseResponse(response)
            
            when {
                // 1xx: Informational (RFC 7231 Section 6.2)
                httpResponse.statusCode in 100..199 -> {
                    onResponse(httpResponse)
                }
                // 2xx: Success (RFC 7231 Section 6.3)
                httpResponse.statusCode in 200..299 -> {
                    onResponse(httpResponse)
                }
                // 3xx: Redirection (RFC 7231 Section 6.4)
                httpResponse.statusCode in 300..399 -> {
                    handleRedirection(httpResponse, onResponse, onError)
                }
                // 4xx: Client Error (RFC 7231 Section 6.5)
                httpResponse.statusCode in 400..499 -> {
                    onError(HttpException.ClientError(
                        httpResponse.statusCode,
                        httpResponse.body,
                        httpResponse.message
                    ))
                }
                // 5xx: Server Error (RFC 7231 Section 6.6)
                httpResponse.statusCode in 500..599 -> {
                    onError(HttpException.ServerError(
                        httpResponse.statusCode,
                        httpResponse.body,
                        httpResponse.message
                    ))
                }
                else -> {
                    onError(HttpException.UnknownError(
                        "Unexpected status code: ${httpResponse.statusCode}",
                        httpResponse.statusCode
                    ))
                }
            }
        } catch (e: IOException) {
            onError(HttpException.NetworkError("Network error: ${e.message}", e))
        } catch (e: Exception) {
            onError(HttpException.UnknownError("Unexpected error: ${e.message}", null))
        }
    }
    
    /**
     * Parse HTTP response according to RFC 7231
     */
    private fun parseResponse(response: Response): HttpResponse {
        val body = response.body?.string() ?: ""
        val headers = response.headers.toMultimap()
        
        return HttpResponse(
            statusCode = response.code,
            message = response.message,
            body = body,
            headers = headers,
            isSuccessful = response.isSuccessful,
            isRedirect = response.isRedirect
        )
    }
    
    /**
     * Handle HTTP redirections (RFC 7231 Section 6.4)
     */
    private suspend fun handleRedirection(
        response: HttpResponse,
        onResponse: (HttpResponse) -> Unit,
        onError: (HttpException) -> Unit
    ) {
        // Common redirect status codes:
        // 301: Moved Permanently
        // 302: Found (Temporary Redirect)
        // 303: See Other
        // 307: Temporary Redirect
        // 308: Permanent Redirect
        
        when (response.statusCode) {
            301, 308 -> {
                // Permanent redirect - should update URI
                onError(HttpException.RedirectError(
                    response.statusCode,
                    "Permanent redirect detected",
                    response.headers["Location"]?.firstOrNull()
                ))
            }
            302, 303, 307 -> {
                // Temporary redirect - can follow or report
                onError(HttpException.RedirectError(
                    response.statusCode,
                    "Temporary redirect detected",
                    response.headers["Location"]?.firstOrNull()
                ))
            }
            else -> {
                onResponse(response)
            }
        }
    }
    
    /**
     * Create GET request
     */
    fun createGetRequest(url: String, headers: Map<String, String> = emptyMap()): Request {
        val builder = Request.Builder().url(url)
        headers.forEach { (key, value) ->
            builder.addHeader(key, value)
        }
        return builder.get().build()
    }
    
    /**
     * Create POST request
     */
    fun createPostRequest(
        url: String,
        body: Any?,
        headers: Map<String, String> = emptyMap()
    ): Request {
        val builder = Request.Builder().url(url)
        
        headers.forEach { (key, value) ->
            builder.addHeader(key, value)
        }
        
        val requestBody = if (body != null) {
            val json = gson.toJson(body)
            json.toRequestBody("application/json".toMediaType())
        } else {
            "".toRequestBody(null)
        }
        
        return builder.post(requestBody).build()
    }
    
    /**
     * Create PUT request
     */
    fun createPutRequest(
        url: String,
        body: Any?,
        headers: Map<String, String> = emptyMap()
    ): Request {
        val builder = Request.Builder().url(url)
        
        headers.forEach { (key, value) ->
            builder.addHeader(key, value)
        }
        
        val requestBody = if (body != null) {
            val json = gson.toJson(body)
            json.toRequestBody("application/json".toMediaType())
        } else {
            "".toRequestBody(null)
        }
        
        return builder.put(requestBody).build()
    }
    
    /**
     * Create DELETE request
     */
    fun createDeleteRequest(url: String, headers: Map<String, String> = emptyMap()): Request {
        val builder = Request.Builder().url(url)
        headers.forEach { (key, value) ->
            builder.addHeader(key, value)
        }
        return builder.delete().build()
    }
}

/**
 * HTTP Response data class
 */
data class HttpResponse(
    val statusCode: Int,
    val message: String,
    val body: String,
    val headers: Map<String, List<String>>,
    val isSuccessful: Boolean,
    val isRedirect: Boolean
)

/**
 * HTTP Exception hierarchy following RFC 7231 error categories
 */
sealed class HttpException(message: String, val statusCode: Int? = null) : Exception(message) {
    /**
     * 4xx: Client Error
     */
    data class ClientError(
        val code: Int,
        val body: String?,
        val message: String
    ) : HttpException("Client Error $code: $message", code)
    
    /**
     * 5xx: Server Error
     */
    data class ServerError(
        val code: Int,
        val body: String?,
        val message: String
    ) : HttpException("Server Error $code: $message", code)
    
    /**
     * 3xx: Redirection
     */
    data class RedirectError(
        val code: Int,
        val message: String,
        val location: String?
    ) : HttpException("Redirect $code: $message", code)
    
    /**
     * Network-level errors (connection failures, timeouts)
     */
    data class NetworkError(
        val message: String,
        val cause: Throwable? = null
    ) : HttpException(message)
    
    /**
     * Unknown or unexpected errors
     */
    data class UnknownError(
        val message: String,
        val code: Int?
    ) : HttpException(message, code)
}

