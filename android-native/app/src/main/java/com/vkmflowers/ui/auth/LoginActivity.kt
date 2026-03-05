package com.vkmflowers.ui.auth

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.vkmflowers.data.models.LoginRequest
import com.vkmflowers.data.network.ApiClient
import com.vkmflowers.databinding.ActivityLoginBinding
import com.vkmflowers.ui.main.MainActivity
import com.vkmflowers.utils.SessionManager
import com.vkmflowers.utils.snack
import kotlinx.coroutines.launch

class LoginActivity : AppCompatActivity() {

    private lateinit var binding: ActivityLoginBinding
    private lateinit var session: SessionManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityLoginBinding.inflate(layoutInflater)
        setContentView(binding.root)

        session = SessionManager(this)
        ApiClient.tokenProvider = { session.getToken() }

        binding.btnLogin.setOnClickListener { handleLogin() }
        binding.tvSignup.setOnClickListener {
            startActivity(Intent(this, SignupActivity::class.java))
        }
    }

    private fun handleLogin() {
        val email = binding.etEmail.text?.toString()?.trim()?.lowercase() ?: ""
        val password = binding.etPassword.text?.toString() ?: ""

        if (email.isEmpty() || password.isEmpty()) {
            binding.root.snack("Please enter email and password", isError = true)
            return
        }

        setLoading(true)
        lifecycleScope.launch {
            try {
                val data = ApiClient.service.login(LoginRequest(email, password))
                session.saveSession(data)
                startActivity(Intent(this@LoginActivity, MainActivity::class.java))
                finish()
            } catch (e: Exception) {
                binding.root.snack(e.message ?: "Login failed", isError = true)
            } finally {
                setLoading(false)
            }
        }
    }

    private fun setLoading(loading: Boolean) {
        binding.btnLogin.isEnabled = !loading
        binding.progressBar.visibility = if (loading) View.VISIBLE else View.GONE
        binding.btnLoginText.visibility = if (loading) View.GONE else View.VISIBLE
    }
}
