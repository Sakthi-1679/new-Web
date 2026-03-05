package com.vkmflowers.ui.auth

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.vkmflowers.data.models.RegisterRequest
import com.vkmflowers.data.network.ApiClient
import com.vkmflowers.databinding.ActivitySignupBinding
import com.vkmflowers.ui.main.MainActivity
import com.vkmflowers.utils.SessionManager
import com.vkmflowers.utils.snack
import kotlinx.coroutines.launch

class SignupActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySignupBinding
    private lateinit var session: SessionManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySignupBinding.inflate(layoutInflater)
        setContentView(binding.root)

        session = SessionManager(this)
        ApiClient.tokenProvider = { session.getToken() }

        binding.btnSignup.setOnClickListener { handleSignup() }
        binding.tvLogin.setOnClickListener { finish() }
    }

    private fun handleSignup() {
        val name = binding.etName.text?.toString()?.trim() ?: ""
        val email = binding.etEmail.text?.toString()?.trim()?.lowercase() ?: ""
        val phone = binding.etPhone.text?.toString()?.trim() ?: ""
        val area = binding.etArea.text?.toString()?.trim() ?: ""
        val password = binding.etPassword.text?.toString() ?: ""

        if (name.isEmpty() || email.isEmpty() || phone.isEmpty() || area.isEmpty() || password.isEmpty()) {
            binding.root.snack("Please fill all fields", isError = true)
            return
        }

        setLoading(true)
        lifecycleScope.launch {
            try {
                val data = ApiClient.service.register(
                    RegisterRequest(
                        name = name,
                        email = email,
                        password = password,
                        phone = phone,
                        city = "Kanchipuram",
                        area = area
                    )
                )
                session.saveSession(data)
                startActivity(Intent(this@SignupActivity, MainActivity::class.java).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                })
            } catch (e: Exception) {
                binding.root.snack(e.message ?: "Registration failed", isError = true)
            } finally {
                setLoading(false)
            }
        }
    }

    private fun setLoading(loading: Boolean) {
        binding.btnSignup.isEnabled = !loading
        binding.progressBar.visibility = if (loading) View.VISIBLE else View.GONE
        binding.btnSignupText.visibility = if (loading) View.GONE else View.VISIBLE
    }
}
