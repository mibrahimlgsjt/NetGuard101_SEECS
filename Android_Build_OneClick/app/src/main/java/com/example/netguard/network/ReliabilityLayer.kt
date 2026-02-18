package com.example.netguard.network

import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * Reliability Layer
 * 
 * Implements two key networking reliability patterns:
 * 1. Circuit Breaker Pattern - Prevents cascading failures
 * 2. Exponential Backoff - Handles retries with increasing delays
 * 
 * These patterns are essential for handling:
 * - 5xx server errors
 * - Network packet loss
 * - Temporary service unavailability
 */

/**
 * Circuit Breaker Pattern
 * 
 * States:
 * - CLOSED: Normal operation, requests pass through
 * - OPEN: Too many failures, requests are blocked
 * - HALF_OPEN: Testing if service recovered, limited requests allowed
 */
class CircuitBreaker(
    private val failureThreshold: Int = 5,
    private val timeoutMillis: Long = 60000, // 1 minute
    private val halfOpenMaxCalls: Int = 3
) {
    
    enum class State {
        CLOSED,    // Normal operation
        OPEN,      // Circuit is open, blocking requests
        HALF_OPEN  // Testing recovery
    }
    
    private val _state = MutableStateFlow<State>(State.CLOSED)
    val state: StateFlow<State> = _state.asStateFlow()
    
    private val failureCount = AtomicInteger(0)
    private val successCount = AtomicInteger(0)
    private val lastFailureTime = AtomicLong(0)
    private val halfOpenCalls = AtomicInteger(0)
    
    /**
     * Execute operation with circuit breaker protection
     */
    suspend fun <T> execute(operation: suspend () -> Result<T>): Result<T> {
        return when (_state.value) {
            State.CLOSED -> {
                executeWithMonitoring(operation)
            }
            State.OPEN -> {
                if (shouldAttemptReset()) {
                    _state.value = State.HALF_OPEN
                    halfOpenCalls.set(0)
                    successCount.set(0)
                    executeWithMonitoring(operation)
                } else {
                    Result.failure(CircuitBreakerException("Circuit breaker is OPEN"))
                }
            }
            State.HALF_OPEN -> {
                if (halfOpenCalls.get() >= halfOpenMaxCalls) {
                    // Too many calls in half-open, close circuit again
                    _state.value = State.OPEN
                    lastFailureTime.set(System.currentTimeMillis())
                    Result.failure(CircuitBreakerException("Circuit breaker exceeded half-open call limit"))
                } else {
                    halfOpenCalls.incrementAndGet()
                    val result = executeWithMonitoring(operation)
                    if (result.isSuccess) {
                        successCount.incrementAndGet()
                        if (successCount.get() >= halfOpenMaxCalls) {
                            // Successfully recovered
                            reset()
                        }
                    }
                    result
                }
            }
        }
    }
    
    private suspend fun <T> executeWithMonitoring(operation: suspend () -> Result<T>): Result<T> {
        val result = operation()
        
        if (result.isFailure) {
            recordFailure()
        } else {
            recordSuccess()
        }
        
        return result
    }
    
    private fun recordFailure() {
        lastFailureTime.set(System.currentTimeMillis())
        val failures = failureCount.incrementAndGet()
        
        if (failures >= failureThreshold && _state.value == State.CLOSED) {
            _state.value = State.OPEN
        }
    }
    
    private fun recordSuccess() {
        failureCount.set(0)
        if (_state.value == State.HALF_OPEN) {
            successCount.incrementAndGet()
        }
    }
    
    private fun shouldAttemptReset(): Boolean {
        val timeSinceLastFailure = System.currentTimeMillis() - lastFailureTime.get()
        return timeSinceLastFailure >= timeoutMillis
    }
    
    fun reset() {
        failureCount.set(0)
        successCount.set(0)
        halfOpenCalls.set(0)
        lastFailureTime.set(0)
        _state.value = State.CLOSED
    }
    
    fun getFailureCount(): Int = failureCount.get()
    fun getSuccessCount(): Int = successCount.get()
}

/**
 * Circuit Breaker Exception
 */
class CircuitBreakerException(message: String) : Exception(message)

/**
 * Exponential Backoff Strategy
 * 
 * Implements exponential backoff algorithm for retrying failed requests.
 * 
 * Formula: delay = baseDelay * (2 ^ attemptNumber) + jitter
 * 
 * This is a classic networking concept taught in Computer Networking courses.
 */
class ExponentialBackoff(
    private val baseDelayMillis: Long = 1000,      // Initial delay: 1 second
    private val maxDelayMillis: Long = 60000,      // Maximum delay: 60 seconds
    private val maxRetries: Int = 5,                // Maximum number of retries
    private val jitterEnabled: Boolean = true,      // Add randomness to prevent thundering herd
    private val backoffMultiplier: Double = 2.0     // Exponential multiplier
) {
    
    /**
     * Retry configuration
     */
    data class RetryConfig(
        val shouldRetry: (Throwable) -> Boolean,
        val onRetry: ((Int, Long) -> Unit)? = null,
        val onMaxRetriesExceeded: ((Throwable) -> Unit)? = null
    )
    
    /**
     * Execute operation with exponential backoff retry logic
     */
    suspend fun <T> executeWithRetry(
        operation: suspend () -> Result<T>,
        config: RetryConfig
    ): Result<T> {
        var lastException: Throwable? = null
        
        for (attempt in 0..maxRetries) {
            val result = operation()
            
            if (result.isSuccess) {
                return result
            }
            
            val exception = result.exceptionOrNull() ?: return result
            
            // Check if we should retry this exception
            if (!config.shouldRetry(exception)) {
                return result
            }
            
            lastException = exception
            
            // Don't delay after the last attempt
            if (attempt < maxRetries) {
                val delay = calculateDelay(attempt)
                config.onRetry?.invoke(attempt + 1, delay)
                delay(delay)
            }
        }
        
        // Max retries exceeded
        config.onMaxRetriesExceeded?.invoke(lastException ?: Exception("Unknown error"))
        return Result.failure(
            lastException ?: Exception("Max retries exceeded")
        )
    }
    
    /**
     * Calculate delay using exponential backoff formula
     * delay = baseDelay * (multiplier ^ attempt) + jitter
     */
    private fun calculateDelay(attempt: Int): Long {
        // Exponential backoff: baseDelay * (2 ^ attempt)
        val exponentialDelay = (baseDelayMillis * Math.pow(backoffMultiplier, attempt.toDouble())).toLong()
        
        // Cap at maximum delay
        val cappedDelay = minOf(exponentialDelay, maxDelayMillis)
        
        // Add jitter (randomness) to prevent thundering herd problem
        val jitter = if (jitterEnabled) {
            // Random jitter between 0% and 25% of the delay
            (Math.random() * cappedDelay * 0.25).toLong()
        } else {
            0L
        }
        
        return cappedDelay + jitter
    }
    
    /**
     * Default retry condition: retry on 5xx errors and network errors
     */
    fun defaultRetryCondition(exception: Throwable): Boolean {
        return when (exception) {
            is HttpException.ServerError -> {
                // Retry on 5xx server errors
                exception.code in 500..599
            }
            is HttpException.NetworkError -> {
                // Retry on network errors (timeouts, connection failures)
                true
            }
            is CircuitBreakerException -> {
                // Don't retry if circuit breaker is open
                false
            }
            else -> {
                // Don't retry on client errors (4xx)
                false
            }
        }
    }
}

/**
 * Combined Reliability Manager
 * 
 * Combines Circuit Breaker and Exponential Backoff for comprehensive
 * reliability handling.
 */
class ReliabilityManager(
    circuitBreaker: CircuitBreaker = CircuitBreaker(),
    exponentialBackoff: ExponentialBackoff = ExponentialBackoff()
) {
    private val circuitBreaker = circuitBreaker
    private val exponentialBackoff = exponentialBackoff
    
    /**
     * Execute operation with both circuit breaker and exponential backoff
     */
    suspend fun <T> executeWithReliability(
        operation: suspend () -> Result<T>,
        retryConfig: ExponentialBackoff.RetryConfig? = null
    ): Result<T> {
        val config = retryConfig ?: ExponentialBackoff.RetryConfig(
            shouldRetry = exponentialBackoff.defaultRetryCondition
        )
        
        return circuitBreaker.execute {
            exponentialBackoff.executeWithRetry(operation, config)
        }
    }
    
    fun getCircuitBreakerState(): CircuitBreaker.State = circuitBreaker.state.value
    fun resetCircuitBreaker() = circuitBreaker.reset()
}

