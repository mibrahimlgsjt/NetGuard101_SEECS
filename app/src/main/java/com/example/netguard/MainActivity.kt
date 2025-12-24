package com.example.netguard

import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.example.netguard.network.ApplicationLayer
import com.example.netguard.network.CommunicationManager
import com.example.netguard.network.HttpException
import com.example.netguard.network.HttpResponse
import com.example.netguard.network.SessionLayer
import com.example.netguard.network.TransportLayerSecurity
import kotlinx.coroutines.launch

class MainActivity : AppCompatActivity() {
    
    private lateinit var communicationManager: CommunicationManager
    private lateinit var sessionStatusText: TextView
    private lateinit var circuitBreakerStatusText: TextView
    private lateinit var responseText: TextView
    private lateinit var testGetButton: Button
    private lateinit var testPostButton: Button
    private lateinit var networkStatusText: TextView
    private lateinit var threatLevelText: TextView
    private lateinit var packetsCountText: TextView
    private lateinit var alertsText: TextView
    
    private var packetsAnalyzed = 0
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        
        // Initialize UI components
        initializeViews()
        
        // Initialize Communication Manager
        initializeNetworking()
        
        // Set up button listeners
        setupButtonListeners()
        
        // Monitor session state
        monitorSessionState()
        
        // Update circuit breaker status
        updateCircuitBreakerStatus()
    }
    
    private fun initializeViews() {
        sessionStatusText = findViewById(R.id.sessionStatusText)
        circuitBreakerStatusText = findViewById(R.id.circuitBreakerStatusText)
        responseText = findViewById(R.id.responseText)
        testGetButton = findViewById(R.id.testGetButton)
        testPostButton = findViewById(R.id.testPostButton)
        networkStatusText = findViewById(R.id.networkStatusText)
        threatLevelText = findViewById(R.id.threatLevelText)
        packetsCountText = findViewById(R.id.packetsCountText)
        alertsText = findViewById(R.id.alertsText)
        
        // Initialize IDPS monitoring UI
        initializeIDPSMonitoring()
    }
    
    private fun initializeIDPSMonitoring() {
        // Set initial monitoring status
        networkStatusText.text = "Active"
        networkStatusText.setTextColor(getColor(android.R.color.holo_green_dark))
        
        threatLevelText.text = "LOW"
        threatLevelText.setTextColor(getColor(android.R.color.holo_green_dark))
        
        packetsCountText.text = "0"
        alertsText.text = "No threats detected. System operating normally."
    }
    
    private fun initializeNetworking() {
        // Get Communication Manager instance
        communicationManager = CommunicationManager.getInstance(this)
        
        // Initialize SSL pinning (optional - for demo we'll skip pinning for httpbin.org)
        // For production, configure with your server's certificate pins:
        /*
        val pinConfigs = listOf(
            TransportLayerSecurity.PinConfig(
                hostname = "api.yourserver.com",
                pins = listOf(
                    "sha256/YOUR_PRIMARY_CERTIFICATE_PIN",
                    "sha256/YOUR_BACKUP_CERTIFICATE_PIN"
                )
            )
        )
        communicationManager.initializeWithSslPinning(pinConfigs)
        */
        
        // For demo purposes, we'll use httpbin.org which doesn't require pinning
        // In production, always use SSL pinning for your API endpoints
        updateStatus("Networking module initialized")
    }
    
    private fun setupButtonListeners() {
        testGetButton.setOnClickListener {
            testGetRequest()
        }
        
        testPostButton.setOnClickListener {
            testPostRequest()
        }
    }
    
    private fun testGetRequest() {
        updateResponse("Making GET request to httpbin.org/get...")
        testGetButton.isEnabled = false
        
        lifecycleScope.launch {
            try {
                // Create GET request using Application Layer
                val requestBuilder = ApplicationLayer.getInstance().createGetRequest(
                    url = "https://httpbin.org/get",
                    headers = mapOf(
                        "User-Agent" to "IDPS-Android-App",
                        "Accept" to "application/json"
                    )
                )
                
                // Execute request (without authentication for demo)
                // In production, use executeAuthenticatedRequest()
                communicationManager.executeUnauthenticatedRequest(
                    request = requestBuilder.build(),
                    onSuccess = { response ->
                        runOnUiThread {
                            packetsAnalyzed++
                            updatePacketsCount()
                            updateResponse("✓ GET Request Successful\n\n" +
                                    "Status Code: ${response.statusCode}\n" +
                                    "Response Body:\n${response.body?.take(500)}...")
                            testGetButton.isEnabled = true
                        }
                    },
                    onError = { error ->
                    runOnUiThread {
                        packetsAnalyzed++
                        updatePacketsCount()
                        val errorMsg = when (error) {
                            is HttpException.ClientError -> {
                                // Check for suspicious patterns
                                if (error.code == 401 || error.code == 403) {
                                    addAlert("Unauthorized access attempt detected (${error.code})")
                                }
                                "Client Error ${error.code}: ${error.message}"
                            }
                            is HttpException.ServerError -> 
                                "Server Error ${error.code}: ${error.message}"
                            is HttpException.NetworkError -> {
                                addAlert("Network connectivity issue detected")
                                "Network Error: ${error.message}"
                            }
                            else -> 
                                "Error: ${error.message}"
                        }
                        updateResponse("✗ GET Request Failed\n\n$errorMsg")
                        testGetButton.isEnabled = true
                    }
                    }
                )
            } catch (e: Exception) {
                runOnUiThread {
                    updateResponse("✗ Exception: ${e.message}")
                    testGetButton.isEnabled = true
                }
            }
        }
    }
    
    private fun testPostRequest() {
        updateResponse("Making POST request to httpbin.org/post...")
        testPostButton.isEnabled = false
        
        lifecycleScope.launch {
            try {
                // Create POST request with JSON body
                val requestBody = mapOf(
                    "app_name" to "IDPS",
                    "test" to true,
                    "timestamp" to System.currentTimeMillis()
                )
                
                val requestBuilder = ApplicationLayer.getInstance().createPostRequest(
                    url = "https://httpbin.org/post",
                    body = requestBody,
                    headers = mapOf(
                        "Content-Type" to "application/json",
                        "User-Agent" to "IDPS-Android-App"
                    )
                )
                
                communicationManager.executeUnauthenticatedRequest(
                    request = requestBuilder.build(),
                    onSuccess = { response ->
                        runOnUiThread {
                            packetsAnalyzed++
                            updatePacketsCount()
                            updateResponse("✓ POST Request Successful\n\n" +
                                    "Status Code: ${response.statusCode}\n" +
                                    "Response Body:\n${response.body?.take(500)}...")
                            testPostButton.isEnabled = true
                        }
                    },
                    onError = { error ->
                        runOnUiThread {
                            packetsAnalyzed++
                            updatePacketsCount()
                            val errorMsg = when (error) {
                                is HttpException.ClientError -> {
                                    if (error.code == 401 || error.code == 403) {
                                        addAlert("Unauthorized access attempt detected (${error.code})")
                                    }
                                    "Client Error ${error.code}: ${error.message}"
                                }
                                is HttpException.ServerError -> 
                                    "Server Error ${error.code}: ${error.message}"
                                is HttpException.NetworkError -> {
                                    addAlert("Network connectivity issue detected")
                                    "Network Error: ${error.message}"
                                }
                                else -> 
                                    "Error: ${error.message}"
                            }
                            updateResponse("✗ POST Request Failed\n\n$errorMsg")
                            testPostButton.isEnabled = true
                        }
                    }
                )
            } catch (e: Exception) {
                runOnUiThread {
                    updateResponse("✗ Exception: ${e.message}")
                    testPostButton.isEnabled = true
                }
            }
        }
    }
    
    private fun monitorSessionState() {
        lifecycleScope.launch {
            communicationManager.getSessionState().collect { state ->
                val statusText = when (state) {
                    is SessionLayer.SessionState.UNAUTHENTICATED -> 
                        "Not Authenticated"
                    is SessionLayer.SessionState.AUTHENTICATING -> 
                        "Authenticating..."
                    is SessionLayer.SessionState.AUTHENTICATED -> 
                        "Authenticated ✓"
                    is SessionLayer.SessionState.REFRESHING -> 
                        "Refreshing Token..."
                    is SessionLayer.SessionState.EXPIRED -> 
                        "Session Expired - Re-login Required"
                }
                sessionStatusText.text = "Status: $statusText"
            }
        }
    }
    
    private fun updateCircuitBreakerStatus() {
        lifecycleScope.launch {
            val state = communicationManager.getCircuitBreakerState()
            val statusText = when (state) {
                com.example.netguard.network.CircuitBreaker.State.CLOSED -> 
                    "Circuit Breaker: CLOSED (Normal Operation)"
                com.example.netguard.network.CircuitBreaker.State.OPEN -> 
                    "Circuit Breaker: OPEN (Too Many Failures)"
                com.example.netguard.network.CircuitBreaker.State.HALF_OPEN -> 
                    "Circuit Breaker: HALF_OPEN (Testing Recovery)"
            }
            circuitBreakerStatusText.text = statusText
        }
    }
    
    private fun updateStatus(message: String) {
        sessionStatusText.text = message
    }
    
    private fun updateResponse(message: String) {
        responseText.text = message
    }
    
    private fun updatePacketsCount() {
        packetsCountText.text = packetsAnalyzed.toString()
        
        // Update threat level based on activity
        when {
            packetsAnalyzed > 100 -> {
                threatLevelText.text = "MEDIUM"
                threatLevelText.setTextColor(getColor(android.R.color.holo_orange_dark))
            }
            packetsAnalyzed > 500 -> {
                threatLevelText.text = "HIGH"
                threatLevelText.setTextColor(getColor(android.R.color.holo_red_dark))
            }
            else -> {
                threatLevelText.text = "LOW"
                threatLevelText.setTextColor(getColor(android.R.color.holo_green_dark))
            }
        }
    }
    
    private fun addAlert(alert: String) {
        val timestamp = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault())
            .format(java.util.Date())
        val currentAlerts = alertsText.text.toString()
        val newAlert = "[$timestamp] $alert\n"
        
        // Keep only last 5 alerts
        val alerts = (currentAlerts + newAlert).lines().takeLast(5)
        alertsText.text = alerts.joinToString("\n")
        
        // Update threat level to MEDIUM if alerts are present
        if (alerts.size > 0) {
            threatLevelText.text = "MEDIUM"
            threatLevelText.setTextColor(getColor(android.R.color.holo_orange_dark))
        }
    }
}

