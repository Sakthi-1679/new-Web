package com.vkmflowers.ui.admin

import android.os.Bundle
import android.util.Base64
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.LinearLayout
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.vkmflowers.R
import com.vkmflowers.data.models.*
import com.vkmflowers.data.network.ApiClient
import com.vkmflowers.databinding.*
import com.vkmflowers.utils.formatDate
import com.vkmflowers.utils.formatPrice
import com.vkmflowers.utils.getStatusColor
import com.vkmflowers.utils.snack
import kotlinx.coroutines.launch
import androidx.activity.result.contract.ActivityResultContracts

class AdminDashboardFragment : Fragment() {

    private var _binding: FragmentAdminDashboardBinding? = null
    private val binding get() = _binding!!

    private var allOrders: List<Order> = emptyList()
    private var allCustomOrders: List<CustomOrder> = emptyList()
    private var allProducts: List<Product> = emptyList()
    private var adminPhone: String = ""

    // Image picker for products
    private val selectedProductImages = mutableListOf<String>()
    private var productDialog: BottomSheetDialog? = null
    private var productDialogBinding: DialogProductBinding? = null

    private val pickImages = registerForActivityResult(ActivityResultContracts.GetMultipleContents()) { uris ->
        for (uri in uris.take(5 - selectedProductImages.size)) {
            try {
                val stream = requireContext().contentResolver.openInputStream(uri) ?: continue
                val bytes = stream.readBytes()
                val b64 = Base64.encodeToString(bytes, Base64.DEFAULT)
                selectedProductImages.add("data:image/jpeg;base64,$b64")
            } catch (e: Exception) { /* skip */ }
        }
        productDialogBinding?.tvImageCount?.text = "${selectedProductImages.size} image(s) selected"
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentAdminDashboardBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        binding.btnOrders.setOnClickListener { showTab("orders") }
        binding.btnCustom.setOnClickListener { showTab("custom") }
        binding.btnProducts.setOnClickListener { showTab("products") }
        binding.btnSettings.setOnClickListener { showTab("settings") }

        binding.swipeRefresh.setOnRefreshListener { loadData() }
        loadData()
    }

    private var currentTab = "orders"

    private fun loadData() {
        binding.progressBar.visibility = View.VISIBLE
        viewLifecycleOwner.lifecycleScope.launch {
            try {
                allOrders = ApiClient.service.getAllOrders()
                allCustomOrders = ApiClient.service.getAllCustomOrders()
                allProducts = ApiClient.service.getProducts()
                adminPhone = try { ApiClient.service.getAdminContact().phone ?: "" } catch (e: Exception) { "" }
                if (_binding == null) return@launch
                updateBadges()
                showTab(currentTab)
            } catch (e: Exception) {
                if (_binding == null) return@launch
                binding.root.snack("Failed to load data", isError = true)
            } finally {
                if (_binding != null) {
                    binding.progressBar.visibility = View.GONE
                    binding.swipeRefresh.isRefreshing = false
                }
            }
        }
    }

    private fun updateBadges() {
        val pendingOrders = allOrders.count { it.status == OrderStatus.PENDING }
        val pendingCustom = allCustomOrders.count { it.status == OrderStatus.PENDING }
        binding.btnOrders.text = if (pendingOrders > 0) "Orders ($pendingOrders)" else "Orders"
        binding.btnCustom.text = if (pendingCustom > 0) "Custom ($pendingCustom)" else "Custom"
        binding.tvStats.text = buildString {
            if (pendingOrders > 0) append("$pendingOrders pending orders  ")
            if (pendingCustom > 0) append("$pendingCustom custom pending")
        }
    }

    private fun showTab(tab: String) {
        currentTab = tab
        val primaryColor = requireContext().getColor(R.color.primary)
        val surfaceColor = requireContext().getColor(R.color.surface)
        val hintColor = requireContext().getColor(R.color.text_secondary)

        listOf(binding.btnOrders, binding.btnCustom, binding.btnProducts, binding.btnSettings).forEach {
            it.setTextColor(hintColor); it.setBackgroundColor(android.graphics.Color.TRANSPARENT)
        }
        val activeBtn = when (tab) {
            "orders" -> binding.btnOrders
            "custom" -> binding.btnCustom
            "products" -> binding.btnProducts
            else -> binding.btnSettings
        }
        activeBtn.setTextColor(primaryColor)
        activeBtn.setBackgroundColor(surfaceColor)

        binding.rvList.visibility = View.GONE
        binding.settingsLayout.visibility = View.GONE
        binding.btnAddProduct.visibility = View.GONE

        when (tab) {
            "orders" -> {
                binding.rvList.visibility = View.VISIBLE
                binding.rvList.layoutManager = LinearLayoutManager(requireContext())
                binding.rvList.adapter = OrderAdapter(allOrders)
            }
            "custom" -> {
                binding.rvList.visibility = View.VISIBLE
                binding.rvList.layoutManager = LinearLayoutManager(requireContext())
                binding.rvList.adapter = CustomOrderAdapter(allCustomOrders)
            }
            "products" -> {
                binding.rvList.visibility = View.VISIBLE
                binding.btnAddProduct.visibility = View.VISIBLE
                binding.rvList.layoutManager = LinearLayoutManager(requireContext())
                binding.rvList.adapter = ProductAdminAdapter(allProducts)
                binding.btnAddProduct.setOnClickListener { openProductDialog(null) }
            }
            "settings" -> {
                binding.settingsLayout.visibility = View.VISIBLE
                binding.etAdminPhone.setText(adminPhone)
                binding.btnSetPhone.setOnClickListener {
                    val phone = binding.etAdminPhone.text?.toString()?.trim() ?: ""
                    if (phone.isEmpty()) return@setOnClickListener
                    viewLifecycleOwner.lifecycleScope.launch {
                        try {
                            ApiClient.service.updateAdminContact(ContactRequest(phone))
                            adminPhone = phone
                            if (_binding != null) binding.root.snack("WhatsApp number updated!")
                        } catch (e: Exception) {
                            if (_binding != null) binding.root.snack("Update failed", isError = true)
                        }
                    }
                }
            }
        }
    }

    // ─── Order Adapter ────────────────────────────────────────
    inner class OrderAdapter(private val items: List<Order>) : RecyclerView.Adapter<OrderAdapter.VH>() {
        inner class VH(val b: ItemAdminOrderBinding) : RecyclerView.ViewHolder(b.root)
        override fun onCreateViewHolder(parent: ViewGroup, vt: Int) =
            VH(ItemAdminOrderBinding.inflate(LayoutInflater.from(parent.context), parent, false))
        override fun getItemCount() = items.size
        override fun onBindViewHolder(holder: VH, position: Int) {
            val o = items[position]
            with(holder.b) {
                // Product image
                com.bumptech.glide.Glide.with(root.context)
                    .load(o.productImage)
                    .placeholder(R.drawable.ic_flower)
                    .error(R.drawable.ic_flower)
                    .centerCrop()
                    .into(ivProduct)

                // Bill ID
                tvBillId.text = o.billId ?: ""
                tvBillId.visibility = if (o.billId != null) View.VISIBLE else View.GONE

                // Product title
                tvTitle.text = o.productTitle

                // Customer name
                if (!o.userName.isNullOrEmpty()) {
                    tvCustomerName.text = "👤 ${o.userName}"
                    tvCustomerName.visibility = View.VISIBLE
                } else { tvCustomerName.visibility = View.GONE }

                // Customer phone
                if (!o.userPhone.isNullOrEmpty()) {
                    tvCustomerPhone.text = "📞 ${o.userPhone}"
                    tvCustomerPhone.visibility = View.VISIBLE
                } else { tvCustomerPhone.visibility = View.GONE }

                // Qty · Price · Date
                tvMeta.text = "Qty: ${o.quantity}  •  ${formatPrice(o.totalPrice)}  •  ${formatDate(o.createdAt)}"

                // Note
                if (!o.description.isNullOrEmpty()) {
                    tvNote.text = "📝 ${o.description}"
                    tvNote.visibility = View.VISIBLE
                } else { tvNote.visibility = View.GONE }

                btnDelete.setOnClickListener { confirmDelete { deleteOrder(o.id) } }

                statusChips.removeAllViews()
                OrderStatus.values().forEach { status ->
                    val chip = layoutInflater.inflate(R.layout.item_status_chip, statusChips, false)
                    val tv = chip.findViewById<android.widget.TextView>(R.id.tvChip)
                    tv.text = status.name
                    val color = getStatusColor(status.name)
                    if (o.status == status) {
                        tv.setBackgroundColor(color)
                        tv.setTextColor(0xFFFFFFFF.toInt())
                    } else {
                        tv.setBackgroundColor(color and 0x00FFFFFF or (0x20 shl 24))
                        tv.setTextColor(color)
                    }
                    tv.setOnClickListener {
                        viewLifecycleOwner.lifecycleScope.launch {
                            try {
                                ApiClient.service.updateOrderStatus(o.id, UpdateStatusRequest(status.name))
                                loadData()
                            } catch (e: Exception) { if (_binding != null) binding.root.snack("Update failed", isError = true) }
                        }
                    }
                    statusChips.addView(chip)
                }
            }
        }
    }

    // ─── Custom Order Adapter ─────────────────────────────────
    inner class CustomOrderAdapter(private val items: List<CustomOrder>) : RecyclerView.Adapter<CustomOrderAdapter.VH>() {
        inner class VH(val b: ItemAdminCustomOrderBinding) : RecyclerView.ViewHolder(b.root)
        override fun onCreateViewHolder(parent: ViewGroup, vt: Int) =
            VH(ItemAdminCustomOrderBinding.inflate(LayoutInflater.from(parent.context), parent, false))
        override fun getItemCount() = items.size
        override fun onBindViewHolder(holder: VH, position: Int) {
            val o = items[position]
            with(holder.b) {
                tvName.text = o.contactName ?: "—"

                if (!o.contactPhone.isNullOrEmpty()) {
                    tvPhone.text = "📞 ${o.contactPhone}"
                    tvPhone.visibility = View.VISIBLE
                } else { tvPhone.visibility = View.GONE }

                tvDesc.text = o.description
                tvDate.text = "📅 ${o.requestedDate ?: ""} ${o.requestedTime?.take(5) ?: ""}"

                // Image thumbnails
                imageRow.removeAllViews()
                if (o.images.isNotEmpty()) {
                    scrollImages.visibility = View.VISIBLE
                    val sizePx = (80 * root.context.resources.displayMetrics.density).toInt()
                    val marginPx = (6 * root.context.resources.displayMetrics.density).toInt()
                    o.images.forEach { url ->
                        val iv = android.widget.ImageView(root.context).apply {
                            layoutParams = LinearLayout.LayoutParams(sizePx, sizePx).apply { marginEnd = marginPx }
                            scaleType = android.widget.ImageView.ScaleType.CENTER_CROP
                            setBackgroundResource(R.drawable.bg_input)
                        }
                        com.bumptech.glide.Glide.with(root.context)
                            .load(url).centerCrop().placeholder(R.drawable.ic_brush).into(iv)
                        imageRow.addView(iv)
                    }
                } else { scrollImages.visibility = View.GONE }

                btnDelete.setOnClickListener { confirmDelete { deleteCustomOrder(o.id) } }

                statusChips.removeAllViews()
                OrderStatus.values().forEach { status ->
                    val chip = layoutInflater.inflate(R.layout.item_status_chip, statusChips, false)
                    val tv = chip.findViewById<android.widget.TextView>(R.id.tvChip)
                    tv.text = status.name
                    val color = getStatusColor(status.name)
                    if (o.status == status) {
                        tv.setBackgroundColor(color); tv.setTextColor(0xFFFFFFFF.toInt())
                    } else {
                        tv.setBackgroundColor(color and 0x00FFFFFF or (0x20 shl 24)); tv.setTextColor(color)
                    }
                    tv.setOnClickListener {
                        viewLifecycleOwner.lifecycleScope.launch {
                            try {
                                ApiClient.service.updateCustomOrderStatus(o.id, UpdateStatusRequest(status.name))
                                loadData()
                            } catch (e: Exception) { if (_binding != null) binding.root.snack("Update failed", isError = true) }
                        }
                    }
                    statusChips.addView(chip)
                }
            }
        }
    }

    // ─── Product Adapter ──────────────────────────────────────
    inner class ProductAdminAdapter(private val items: List<Product>) : RecyclerView.Adapter<ProductAdminAdapter.VH>() {
        inner class VH(val b: ItemAdminProductBinding) : RecyclerView.ViewHolder(b.root)
        override fun onCreateViewHolder(parent: ViewGroup, vt: Int) =
            VH(ItemAdminProductBinding.inflate(LayoutInflater.from(parent.context), parent, false))
        override fun getItemCount() = items.size
        override fun onBindViewHolder(holder: VH, position: Int) {
            val p = items[position]
            with(holder.b) {
                tvTitle.text = p.title
                tvPrice.text = formatPrice(p.price)
                if (p.images.isNotEmpty()) {
                    com.bumptech.glide.Glide.with(root.context).load(p.images[0])
                        .placeholder(R.drawable.ic_flower).centerCrop().into(ivProduct)
                }
                btnEdit.setOnClickListener { openProductDialog(p) }
                btnDelete.setOnClickListener { confirmDelete { deleteProduct(p.id) } }
            }
        }
    }

    // ─── Product Dialog ───────────────────────────────────────
    private fun openProductDialog(product: Product?) {
        val dialog = BottomSheetDialog(requireContext(), R.style.Theme_VKMFlowers)
        val db = DialogProductBinding.inflate(layoutInflater)
        dialog.setContentView(db.root)
        productDialog = dialog
        productDialogBinding = db
        selectedProductImages.clear()

        db.tvTitle.text = if (product == null) "Add Product" else "Edit Product"
        product?.let {
            db.etTitle.setText(it.title)
            db.etDesc.setText(it.description)
            db.etPrice.setText(it.price.toInt().toString())
            db.etDuration.setText(it.durationHours.toString())
            selectedProductImages.addAll(it.images)
            db.tvImageCount.text = "${it.images.size} image(s) selected"
            db.tvImageCount.visibility = if (it.images.isNotEmpty()) View.VISIBLE else View.GONE
        }

        db.btnAddImages.setOnClickListener {
            if (selectedProductImages.size < 5) pickImages.launch("image/*")
        }

        db.btnSave.setOnClickListener {
            val title = db.etTitle.text?.toString()?.trim() ?: ""
            val desc = db.etDesc.text?.toString()?.trim() ?: ""
            val price = db.etPrice.text?.toString()?.toDoubleOrNull() ?: 0.0
            val duration = db.etDuration.text?.toString()?.toIntOrNull() ?: 24

            if (title.isEmpty() || price <= 0) {
                binding.root.snack("Title and price required", isError = true)
                return@setOnClickListener
            }

            viewLifecycleOwner.lifecycleScope.launch {
                try {
                    val req = ProductRequest(title, desc, price, duration, selectedProductImages.toList())
                    if (product != null) {
                        ApiClient.service.updateProduct(product.id, req)
                    } else {
                        ApiClient.service.addProduct(req)
                    }
                    dialog.dismiss()
                    loadData()
                    if (_binding != null) binding.root.snack("Product saved!")
                } catch (e: Exception) {
                    if (_binding != null) binding.root.snack(e.message ?: "Save failed", isError = true)
                }
            }
        }

        dialog.show()
    }

    // ─── Helpers ──────────────────────────────────────────────
    private fun confirmDelete(action: () -> Unit) {
        AlertDialog.Builder(requireContext())
            .setTitle("Delete")
            .setMessage("Are you sure? This cannot be undone.")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Delete") { _, _ -> action() }
            .show()
    }

    private fun deleteOrder(id: String) {
        viewLifecycleOwner.lifecycleScope.launch {
            try { ApiClient.service.deleteOrder(id); loadData(); if (_binding != null) binding.root.snack("Deleted") }
            catch (e: Exception) { if (_binding != null) binding.root.snack("Delete failed", isError = true) }
        }
    }

    private fun deleteCustomOrder(id: String) {
        viewLifecycleOwner.lifecycleScope.launch {
            try { ApiClient.service.deleteCustomOrder(id); loadData(); if (_binding != null) binding.root.snack("Deleted") }
            catch (e: Exception) { if (_binding != null) binding.root.snack("Delete failed", isError = true) }
        }
    }

    private fun deleteProduct(id: String) {
        viewLifecycleOwner.lifecycleScope.launch {
            try { ApiClient.service.deleteProduct(id); loadData(); if (_binding != null) binding.root.snack("Deleted") }
            catch (e: Exception) { if (_binding != null) binding.root.snack("Delete failed", isError = true) }
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
