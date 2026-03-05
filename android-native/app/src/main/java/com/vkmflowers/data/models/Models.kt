package com.vkmflowers.data.models

import com.google.gson.annotations.SerializedName

// ─── Enums ────────────────────────────────────────────────────
enum class UserRole { ADMIN, USER }

enum class OrderStatus { PENDING, CONFIRMED, COMPLETED, CANCELLED }

// ─── User ────────────────────────────────────────────────────
data class User(
    val id: String,
    val name: String,
    val email: String,
    val phone: String,
    val city: String,
    val area: String,
    val role: UserRole
)

// ─── Product ─────────────────────────────────────────────────
data class Product(
    val id: String,
    val title: String,
    val description: String,
    val price: Double,
    val durationHours: Int,
    val images: List<String> = emptyList()
)

// ─── Order ───────────────────────────────────────────────────
data class Order(
    val id: String,
    val billId: String?,
    val userId: String,
    val productId: String,
    val productTitle: String,
    val productImage: String,
    val quantity: Int,
    val totalPrice: Double,
    val description: String?,
    val status: OrderStatus,
    val createdAt: String,
    val expectedDeliveryAt: String?,     // null until order is CONFIRMED
    val userName: String? = null,        // from server JOIN
    val userPhone: String? = null        // from server JOIN
)

// ─── Custom Order ────────────────────────────────────────────
data class CustomOrder(
    val id: String,
    val userId: String,
    val description: String,
    val requestedDate: String?,
    val requestedTime: String?,
    val contactName: String?,
    val contactPhone: String?,
    val images: List<String> = emptyList(),
    val status: OrderStatus,
    val createdAt: String,
    val deadlineAt: String?
)

// ─── Auth Response ───────────────────────────────────────────
data class AuthResponse(
    val user: User,
    val token: String
)

// ─── Request Bodies ──────────────────────────────────────────
data class LoginRequest(
    val email: String,
    val password: String
)

data class RegisterRequest(
    val name: String,
    val email: String,
    val password: String,
    val phone: String,
    val city: String,
    val area: String
)

data class PlaceOrderRequest(
    val userId: String,
    val productId: String,
    val quantity: Int,
    val description: String? = null
)

data class PlaceCustomOrderRequest(
    val userId: String,
    val description: String,
    val requestedDate: String,
    val requestedTime: String,
    val contactName: String,
    val contactPhone: String,
    val images: List<String> = emptyList()
)

data class UpdateStatusRequest(
    val status: String
)

data class ProductRequest(
    val title: String,
    val description: String,
    val price: Double,
    val durationHours: Int,
    val images: List<String> = emptyList()
)

data class ContactRequest(
    val phone: String
)

data class ContactResponse(
    val phone: String?
)

/** Generic response for endpoints that return { "success": true } */
data class SuccessResponse(
    val success: Boolean = false
)

data class PushTokenRequest(
    val token: String
)
