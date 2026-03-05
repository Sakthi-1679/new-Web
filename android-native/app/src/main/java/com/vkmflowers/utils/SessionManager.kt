package com.vkmflowers.utils

import android.content.Context
import android.content.SharedPreferences
import com.google.gson.Gson
import com.vkmflowers.data.models.AuthResponse
import com.vkmflowers.data.models.User

class SessionManager(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("vkm_session", Context.MODE_PRIVATE)
    private val gson = Gson()

    companion object {
        private const val KEY_SESSION = "auth_session"
    }

    fun saveSession(data: AuthResponse) {
        prefs.edit().putString(KEY_SESSION, gson.toJson(data)).apply()
    }

    fun getSession(): AuthResponse? {
        val json = prefs.getString(KEY_SESSION, null) ?: return null
        return try {
            gson.fromJson(json, AuthResponse::class.java)
        } catch (e: Exception) {
            null
        }
    }

    fun getToken(): String? = getSession()?.token

    fun getUser(): User? = getSession()?.user

    fun isLoggedIn(): Boolean = getSession() != null

    fun isAdmin(): Boolean = getUser()?.role?.name?.uppercase() == "ADMIN"

    fun clearSession() {
        prefs.edit().remove(KEY_SESSION).apply()
    }
}
