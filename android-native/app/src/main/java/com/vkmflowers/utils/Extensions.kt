package com.vkmflowers.utils

import android.app.Activity
import android.content.Context
import android.view.Gravity
import android.widget.Toast
import com.google.android.material.snackbar.Snackbar
import android.view.View

fun Context.toast(msg: String) {
    Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
}

fun View.snack(msg: String, isError: Boolean = false) {
    val sb = Snackbar.make(this, msg, Snackbar.LENGTH_LONG)
    if (isError) {
        sb.setBackgroundTint(0xFFEF4444.toInt())
    } else {
        sb.setBackgroundTint(0xFF22C55E.toInt())
    }
    sb.setTextColor(0xFFFFFFFF.toInt())
    sb.show()
}

fun Activity.showToast(msg: String) {
    Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
}

fun formatPrice(price: Double): String {
    return "₹${price.toInt()}"
}

fun formatDate(isoDate: String): String {
    return try {
        val sdf = java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", java.util.Locale.getDefault())
        val date = sdf.parse(isoDate)
        val out = java.text.SimpleDateFormat("dd MMM yyyy", java.util.Locale.getDefault())
        out.format(date!!)
    } catch (e: Exception) {
        isoDate.take(10)
    }
}

fun getStatusColor(status: String): Int {
    return when (status.uppercase()) {
        "PENDING"   -> 0xFFF59E0B.toInt()
        "CONFIRMED" -> 0xFF6366F1.toInt()
        "COMPLETED" -> 0xFF22C55E.toInt()
        "CANCELLED" -> 0xFFEF4444.toInt()
        else        -> 0xFF9CA3AF.toInt()
    }
}
