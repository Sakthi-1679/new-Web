package com.vkmflowers.data.network

import com.vkmflowers.data.models.*
import retrofit2.http.*

interface ApiService {

    // ─── CSRF ────────────────────────────────────────────────
    @GET("csrf-token")
    suspend fun refreshCsrfToken(): com.vkmflowers.data.models.CsrfResponse

    // ─── Auth ────────────────────────────────────────────────
    @POST("login")
    suspend fun login(@Body body: LoginRequest): AuthResponse

    @POST("register")
    suspend fun register(@Body body: RegisterRequest): AuthResponse

    @POST("google-login")
    suspend fun googleLogin(@Body body: GoogleLoginRequest): AuthResponse

    // ─── Push Token ──────────────────────────────────────────
    @POST("push-token")
    suspend fun savePushToken(@Body body: PushTokenRequest)

    @POST("push-token")
    suspend fun saveFcmToken(@Body body: FcmTokenRequest)

    // ─── Admin Contact ───────────────────────────────────────
    @GET("settings/contact")
    suspend fun getAdminContact(): ContactResponse

    @PUT("settings/contact")
    suspend fun updateAdminContact(@Body body: ContactRequest): SuccessResponse

    // ─── Products ───────────────────────────────────────────
    @GET("products")
    suspend fun getProducts(): List<Product>

    @POST("products")
    suspend fun addProduct(@Body body: ProductRequest): Product

    @PUT("products/{id}")
    suspend fun updateProduct(@Path("id") id: String, @Body body: ProductRequest): Product

    @DELETE("products/{id}")
    suspend fun deleteProduct(@Path("id") id: String)

    // ─── Orders ─────────────────────────────────────────────
    @GET("orders")
    suspend fun getAllOrders(): List<Order>

    @POST("orders")
    suspend fun placeOrder(@Body body: PlaceOrderRequest): Order

    @PUT("orders/{id}/status")
    suspend fun updateOrderStatus(@Path("id") id: String, @Body body: UpdateStatusRequest): SuccessResponse

    @DELETE("orders/{id}")
    suspend fun deleteOrder(@Path("id") id: String)

    // ─── Custom Orders ───────────────────────────────────────
    @GET("custom-orders")
    suspend fun getAllCustomOrders(): List<CustomOrder>

    @POST("custom-orders")
    suspend fun placeCustomOrder(@Body body: PlaceCustomOrderRequest): CustomOrder

    @PUT("custom-orders/{id}/status")
    suspend fun updateCustomOrderStatus(@Path("id") id: String, @Body body: UpdateStatusRequest): SuccessResponse

    @DELETE("custom-orders/{id}")
    suspend fun deleteCustomOrder(@Path("id") id: String)
}
