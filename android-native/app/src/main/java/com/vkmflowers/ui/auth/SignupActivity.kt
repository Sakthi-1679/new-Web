package com.vkmflowers.ui.auth

import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.google.android.gms.auth.api.signin.GoogleSignIn
import com.google.android.gms.auth.api.signin.GoogleSignInClient
import com.google.android.gms.auth.api.signin.GoogleSignInOptions
import com.google.android.gms.common.api.ApiException
import com.vkmflowers.R
import com.vkmflowers.data.models.GoogleLoginRequest
import com.vkmflowers.data.models.RegisterRequest
import com.vkmflowers.data.models.FcmTokenRequest
import com.vkmflowers.data.network.ApiClient
import com.vkmflowers.databinding.ActivitySignupBinding
import com.vkmflowers.ui.main.MainActivity
import com.vkmflowers.utils.SessionManager
import com.vkmflowers.utils.snack
import com.google.firebase.messaging.FirebaseMessaging
import kotlinx.coroutines.launch

class SignupActivity : AppCompatActivity() {

    private lateinit var binding: ActivitySignupBinding
    private lateinit var session: SessionManager
    private lateinit var googleSignInClient: GoogleSignInClient

    private val googleSignInLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        val task = GoogleSignIn.getSignedInAccountFromIntent(result.data)
        try {
            val account = task.getResult(ApiException::class.java)
            account.idToken?.let { handleGoogleLogin(it) }
                ?: binding.root.snack("Google Sign-In failed: no token", isError = true)
        } catch (e: ApiException) {
            binding.root.snack("Google Sign-In failed: ${e.statusCode}", isError = true)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivitySignupBinding.inflate(layoutInflater)
        setContentView(binding.root)

        session = SessionManager(this)
        ApiClient.tokenProvider = { session.getToken() }
        ApiClient.csrfTokenProvider = { session.getCsrfToken() }

        // Google Sign-In setup
        val gso = GoogleSignInOptions.Builder(GoogleSignInOptions.DEFAULT_SIGN_IN)
            .requestIdToken(getString(R.string.web_client_id))
            .requestEmail()
            .build()
        googleSignInClient = GoogleSignIn.getClient(this, gso)

        binding.btnSignup.setOnClickListener { handleSignup() }
        binding.btnGoogleSignIn.setOnClickListener {
            googleSignInClient.signOut().addOnCompleteListener {
                googleSignInLauncher.launch(googleSignInClient.signInIntent)
            }
        }
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
                registerFcmToken()
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
        binding.btnGoogleSignIn.isEnabled = !loading
        binding.progressBar.visibility = if (loading) View.VISIBLE else View.GONE
        binding.btnSignupText.visibility = if (loading) View.GONE else View.VISIBLE
    }

    private fun handleGoogleLogin(idToken: String) {
        setLoading(true)
        lifecycleScope.launch {
            try {
                val data = ApiClient.service.googleLogin(GoogleLoginRequest(idToken))
                session.saveSession(data)
                registerFcmToken()
                startActivity(Intent(this@SignupActivity, MainActivity::class.java).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                })
            } catch (e: Exception) {
                binding.root.snack(e.message ?: "Google login failed", isError = true)
            } finally {
                setLoading(false)
            }
        }
    }

    private fun registerFcmToken() {
        FirebaseMessaging.getInstance().token.addOnSuccessListener { token ->
            lifecycleScope.launch {
                try {
                    ApiClient.service.saveFcmToken(FcmTokenRequest(token))
                } catch (_: Exception) { }
            }
        }
    }
}
