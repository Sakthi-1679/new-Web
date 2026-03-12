package com.vkmflowers.ui

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.google.firebase.messaging.FirebaseMessaging
import com.vkmflowers.data.models.FcmTokenRequest
import com.vkmflowers.data.network.ApiClient
import com.vkmflowers.ui.auth.LoginActivity
import com.vkmflowers.ui.main.MainActivity
import com.vkmflowers.utils.SessionManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class SplashActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val session = SessionManager(this)
        // Wire token and CSRF providers for Retrofit interceptors
        ApiClient.tokenProvider = { session.getToken() }
        ApiClient.csrfTokenProvider = { session.getCsrfToken() }

        // Request notification permission on Android 13+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), 100)
            }
        }

        // Register FCM token if user is logged in
        if (session.isLoggedIn()) {
            registerFcmToken()
            // Fetch CSRF token if not already stored (e.g. existing sessions before CSRF was added)
            if (session.getCsrfToken() == null) {
                CoroutineScope(Dispatchers.IO).launch {
                    try {
                        val response = ApiClient.service.refreshCsrfToken()
                        session.saveSession(session.getSession()!!.copy(csrfToken = response.csrfToken))
                    } catch (_: Exception) { }
                }
            }
        }

        Handler(Looper.getMainLooper()).postDelayed({
            if (session.isLoggedIn()) {
                startActivity(Intent(this, MainActivity::class.java))
            } else {
                startActivity(Intent(this, LoginActivity::class.java))
            }
            finish()
        }, 1000)
    }

    private fun registerFcmToken() {
        FirebaseMessaging.getInstance().token.addOnSuccessListener { token ->
            CoroutineScope(Dispatchers.IO).launch {
                try {
                    ApiClient.service.saveFcmToken(FcmTokenRequest(token))
                } catch (_: Exception) { }
            }
        }
    }
}
