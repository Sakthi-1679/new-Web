package com.vkmflowers.ui

import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import androidx.appcompat.app.AppCompatActivity
import com.vkmflowers.data.network.ApiClient
import com.vkmflowers.ui.auth.LoginActivity
import com.vkmflowers.ui.main.MainActivity
import com.vkmflowers.utils.SessionManager

class SplashActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val session = SessionManager(this)
        // Wire token provider for Retrofit interceptor
        ApiClient.tokenProvider = { session.getToken() }

        Handler(Looper.getMainLooper()).postDelayed({
            if (session.isLoggedIn()) {
                startActivity(Intent(this, MainActivity::class.java))
            } else {
                startActivity(Intent(this, LoginActivity::class.java))
            }
            finish()
        }, 1000)
    }
}
