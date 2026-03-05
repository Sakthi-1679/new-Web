package com.vkmflowers.ui.home

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.text.Editable
import android.text.TextWatcher
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.GridLayoutManager
import com.bumptech.glide.Glide
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.vkmflowers.R
import com.vkmflowers.data.models.PlaceOrderRequest
import com.vkmflowers.data.models.Product
import com.vkmflowers.data.models.UserRole
import com.vkmflowers.data.network.ApiClient
import com.vkmflowers.databinding.FragmentHomeBinding
import com.vkmflowers.databinding.DialogOrderBinding
import com.vkmflowers.utils.SessionManager
import com.vkmflowers.utils.snack
import com.vkmflowers.utils.formatPrice
import kotlinx.coroutines.launch
import java.net.URLEncoder

class HomeFragment : Fragment() {

    private var _binding: FragmentHomeBinding? = null
    private val binding get() = _binding!!
    private lateinit var session: SessionManager
    private lateinit var adapter: ProductAdapter
    private var allProducts: List<Product> = emptyList()

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentHomeBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        session = SessionManager(requireContext())

        val user = session.getUser()
        binding.tvGreeting.text = "Hello, ${user?.name?.split(" ")?.firstOrNull() ?: "there"} 👋"

        adapter = ProductAdapter { product -> showOrderDialog(product) }
        binding.rvProducts.layoutManager = GridLayoutManager(requireContext(), 2)
        binding.rvProducts.adapter = adapter

        binding.swipeRefresh.setOnRefreshListener { loadProducts() }

        binding.etSearch.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                filterProducts(s?.toString() ?: "")
            }
            override fun afterTextChanged(s: Editable?) {}
        })

        loadProducts()
    }

    private fun loadProducts() {
        binding.progressBar.visibility = View.VISIBLE
        binding.rvProducts.visibility = View.GONE
        viewLifecycleOwner.lifecycleScope.launch {
            try {
                allProducts = ApiClient.service.getProducts()
                if (_binding == null) return@launch
                filterProducts(binding.etSearch.text?.toString() ?: "")
                binding.rvProducts.visibility = View.VISIBLE
            } catch (e: Exception) {
                if (_binding == null) return@launch
                binding.root.snack("Failed to load products", isError = true)
            } finally {
                if (_binding != null) {
                    binding.progressBar.visibility = View.GONE
                    binding.swipeRefresh.isRefreshing = false
                }
            }
        }
    }

    private fun filterProducts(query: String) {
        val filtered = if (query.isEmpty()) allProducts
        else allProducts.filter { it.title.contains(query, ignoreCase = true) }
        adapter.submitList(filtered)

        if (filtered.isEmpty()) {
            binding.tvEmpty.visibility = View.VISIBLE
            binding.rvProducts.visibility = View.GONE
        } else {
            binding.tvEmpty.visibility = View.GONE
            binding.rvProducts.visibility = View.VISIBLE
        }
    }

    private fun showOrderDialog(product: Product) {
        val user = session.getUser() ?: return
        if (user.role == UserRole.ADMIN) {
            Toast.makeText(requireContext(), "Admins cannot place orders", Toast.LENGTH_SHORT).show()
            return
        }

        val dialog = BottomSheetDialog(requireContext(), R.style.Theme_VKMFlowers)
        val db = DialogOrderBinding.inflate(layoutInflater)
        dialog.setContentView(db.root)

        db.tvProductTitle.text = product.title
        db.tvProductPrice.text = formatPrice(product.price)
        db.tvProductDesc.text = product.description

        if (product.images.isNotEmpty()) {
            Glide.with(this).load(product.images[0])
                .placeholder(R.drawable.ic_flower).centerCrop().into(db.ivProduct)
        }

        var qty = 1
        db.tvQty.text = qty.toString()
        db.tvTotal.text = "Total: ${formatPrice(product.price * qty)}"

        db.btnMinus.setOnClickListener {
            if (qty > 1) {
                qty--
                db.tvQty.text = qty.toString()
                db.tvTotal.text = "Total: ${formatPrice(product.price * qty)}"
            }
        }
        db.btnPlus.setOnClickListener {
            qty++
            db.tvQty.text = qty.toString()
            db.tvTotal.text = "Total: ${formatPrice(product.price * qty)}"
        }

        db.btnPlaceOrder.setOnClickListener {
            val note = db.etNote.text?.toString() ?: ""
            db.btnPlaceOrder.isEnabled = false
            viewLifecycleOwner.lifecycleScope.launch {
                try {
                    ApiClient.service.placeOrder(
                        PlaceOrderRequest(userId = user.id, productId = product.id,
                            quantity = qty, description = note.ifEmpty { null })
                    )
                    val adminPhone = try { ApiClient.service.getAdminContact().phone ?: "9999999999" }
                    catch (e: Exception) { "9999999999" }
                    val total = product.price * qty
                    val now = java.text.SimpleDateFormat("dd MMM yyyy, hh:mm a", java.util.Locale.getDefault())
                        .format(java.util.Date())
                    val msg = buildString {
                        appendLine("🌸 *New Order – VKM Flowers*"); appendLine()
                        appendLine("👤 Customer: ${user.name}")
                        appendLine("📞 Phone: ${user.phone}")
                        appendLine("📦 Product: ${product.title}")
                        appendLine("🔢 Quantity: $qty")
                        if (note.isNotEmpty()) appendLine("📝 Note: $note")
                        appendLine("💰 Amount: ₹${total.toInt()}")
                        appendLine("📅 Date: $now")
                    }
                    val encoded = URLEncoder.encode(msg, "UTF-8")
                    startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://wa.me/91$adminPhone?text=$encoded")))
                    dialog.dismiss()
                    if (_binding != null) binding.root.snack("Order placed! WhatsApp opened to notify admin.")
                } catch (e: Exception) {
                    if (_binding != null) {
                        binding.root.snack(e.message ?: "Failed to place order", isError = true)
                        db.btnPlaceOrder.isEnabled = true
                    }
                }
            }
        }

        dialog.show()
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
