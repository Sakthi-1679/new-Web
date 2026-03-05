package com.vkmflowers.data.network

import com.google.gson.GsonBuilder
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.gson.GsonConverterFactory
import java.io.IOException
import java.util.concurrent.TimeUnit

object ApiClient {

    private const val BASE_URL = "https://new-ke1aq1mbd-sakthivel-rs-projects-22b1ea94.vercel.app/api/"

    // Token provider - set this after SessionManager is initialized
    var tokenProvider: (() -> String?)? = null

    /** Adds Authorization + Content-Type headers to every request. */
    private val authInterceptor = Interceptor { chain ->
        val token = tokenProvider?.invoke()
        val request = chain.request().newBuilder()
            .apply {
                addHeader("Content-Type", "application/json")
                addHeader("Accept", "application/json")
                if (token != null) addHeader("Authorization", "Bearer $token")
            }
            .build()
        chain.proceed(request)
    }

    /**
     * Reads error response body and throws a human-readable IOException
     * so catch blocks in fragments show the server's actual error message.
     */
    private val errorInterceptor = Interceptor { chain ->
        val response = chain.proceed(chain.request())
        if (!response.isSuccessful) {
            val rawBody = response.peekBody(4096).string()
            val msg = try {
                val obj = com.google.gson.JsonParser.parseString(rawBody).asJsonObject
                obj.get("error")?.asString
                    ?: obj.get("message")?.asString
                    ?: "Server error (${response.code})"
            } catch (_: Exception) {
                "Server error (${response.code})"
            }
            throw IOException(msg)
        }
        response
    }

    private val loggingInterceptor = HttpLoggingInterceptor().apply {
        level = HttpLoggingInterceptor.Level.BODY
    }

    private val okHttpClient = OkHttpClient.Builder()
        .addInterceptor(authInterceptor)
        .addInterceptor(errorInterceptor)   // parse errors before Gson sees them
        .addInterceptor(loggingInterceptor)
        .connectTimeout(60, TimeUnit.SECONDS)  // Render free tier can take ~60s to wake
        .readTimeout(60, TimeUnit.SECONDS)
        .writeTimeout(60, TimeUnit.SECONDS)
        .retryOnConnectionFailure(true)
        .build()

    private val gson = GsonBuilder()
        .setLenient()
        .serializeNulls()
        .create()

    private val retrofit = Retrofit.Builder()
        .baseUrl(BASE_URL)
        .client(okHttpClient)
        .addConverterFactory(GsonConverterFactory.create(gson))
        .build()

    val service: ApiService = retrofit.create(ApiService::class.java)
}
