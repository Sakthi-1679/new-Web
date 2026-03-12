package com.vkmflowers.ui.orders

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.Color
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.vkmflowers.data.models.CustomOrder
import com.vkmflowers.data.models.Order
import com.vkmflowers.data.network.ApiClient
import com.vkmflowers.databinding.FragmentMyOrdersBinding
import com.vkmflowers.databinding.ItemOrderBinding
import com.vkmflowers.databinding.ItemCustomOrderBinding
import com.vkmflowers.utils.formatDate
import com.vkmflowers.utils.formatPrice
import com.vkmflowers.utils.getStatusColor
import com.bumptech.glide.Glide
import com.vkmflowers.fcm.VkmFirebaseMessagingService
import com.vkmflowers.utils.snack
import kotlinx.coroutines.launch

class MyOrdersFragment : Fragment() {

    private var _binding: FragmentMyOrdersBinding? = null
    private val binding get() = _binding!!

    private val orderReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (_binding != null) loadData()
        }
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentMyOrdersBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        LocalBroadcastManager.getInstance(requireContext())
            .registerReceiver(orderReceiver, IntentFilter(VkmFirebaseMessagingService.ACTION_NEW_ORDER))

        binding.btnOrders.setOnClickListener { showTab("orders") }
        binding.btnCustom.setOnClickListener { showTab("custom") }

        binding.swipeRefresh.setOnRefreshListener { loadData() }
        loadData()
    }

    private var currentTab = "orders"
    private var orders: List<Order> = emptyList()
    private var customOrders: List<CustomOrder> = emptyList()

    private fun loadData() {
        binding.progressBar.visibility = View.VISIBLE
        viewLifecycleOwner.lifecycleScope.launch {
            try {
                // Server already returns only the current user's orders (JWT-filtered)
                orders = ApiClient.service.getAllOrders().reversed()
                customOrders = ApiClient.service.getAllCustomOrders().reversed()
                if (_binding == null) return@launch
                updateTabLabels()
                showTab(currentTab)
            } catch (e: Exception) {
                if (_binding == null) return@launch
                binding.root.snack("Failed to load orders", isError = true)
            } finally {
                if (_binding != null) {
                    binding.progressBar.visibility = View.GONE
                    binding.swipeRefresh.isRefreshing = false
                }
            }
        }
    }

    private fun updateTabLabels() {
        binding.btnOrders.text = "ஆர்டர்கள் (${orders.size})"
        binding.btnCustom.text = "தனிப்பட்ட (${customOrders.size})"
    }

    private fun showTab(tab: String) {
        currentTab = tab
        val primaryColor = requireContext().getColor(com.vkmflowers.R.color.primary)
        val surfaceColor = requireContext().getColor(com.vkmflowers.R.color.surface)
        val hintColor = requireContext().getColor(com.vkmflowers.R.color.text_secondary)

        if (tab == "orders") {
            binding.btnOrders.setTextColor(primaryColor)
            binding.btnOrders.setBackgroundColor(surfaceColor)
            binding.btnCustom.setTextColor(hintColor)
            binding.btnCustom.setBackgroundColor(Color.TRANSPARENT)
            showOrdersList()
        } else {
            binding.btnCustom.setTextColor(primaryColor)
            binding.btnCustom.setBackgroundColor(surfaceColor)
            binding.btnOrders.setTextColor(hintColor)
            binding.btnOrders.setBackgroundColor(Color.TRANSPARENT)
            showCustomList()
        }
    }

    private fun showOrdersList() {
        binding.rvList.layoutManager = LinearLayoutManager(requireContext())
        binding.rvList.adapter = OrderAdapter(orders)
        binding.tvEmpty.visibility = if (orders.isEmpty()) View.VISIBLE else View.GONE
    }

    private fun showCustomList() {
        binding.rvList.layoutManager = LinearLayoutManager(requireContext())
        binding.rvList.adapter = CustomOrderAdapter(customOrders)
        binding.tvEmpty.visibility = if (customOrders.isEmpty()) View.VISIBLE else View.GONE
    }

    // ─── Adapters ─────────────────────────────────────────────

    inner class OrderAdapter(private val items: List<Order>) :
        RecyclerView.Adapter<OrderAdapter.VH>() {

        inner class VH(val b: ItemOrderBinding) : RecyclerView.ViewHolder(b.root)

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) =
            VH(ItemOrderBinding.inflate(LayoutInflater.from(parent.context), parent, false))

        override fun getItemCount() = items.size

        override fun onBindViewHolder(holder: VH, position: Int) {
            val o = items[position]
            with(holder.b) {
                Glide.with(root.context)
                    .load(o.productImage)
                    .placeholder(com.vkmflowers.R.drawable.ic_flower)
                    .error(com.vkmflowers.R.drawable.ic_flower)
                    .centerCrop()
                    .into(ivProduct)
                tvTitle.text = o.productTitle
                tvBillId.text = o.billId ?: ""
                tvBillId.visibility = if (o.billId != null) View.VISIBLE else View.GONE
                tvQty.text = "Qty: ${o.quantity}"
                tvPrice.text = formatPrice(o.totalPrice)
                tvDate.text = formatDate(o.createdAt)
                tvNote.text = o.description ?: ""
                tvNote.visibility = if (!o.description.isNullOrEmpty()) View.VISIBLE else View.GONE

                val statusColor = getStatusColor(o.status.name)
                tvStatus.text = o.status.name
                tvStatus.setTextColor(statusColor)
                chipStatus.setBackgroundColor(statusColor and 0x30FFFFFF or (0x20 shl 24))

                if (o.status.name == "CONFIRMED" && !o.expectedDeliveryAt.isNullOrEmpty()) {
                    tvDelivery.visibility = View.VISIBLE
                    tvDelivery.text = "Expected: ${formatDate(o.expectedDeliveryAt)}"
                } else {
                    tvDelivery.visibility = View.GONE
                }
            }
        }
    }

    inner class CustomOrderAdapter(private val items: List<CustomOrder>) :
        RecyclerView.Adapter<CustomOrderAdapter.VH>() {

        inner class VH(val b: ItemCustomOrderBinding) : RecyclerView.ViewHolder(b.root)

        override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) =
            VH(ItemCustomOrderBinding.inflate(LayoutInflater.from(parent.context), parent, false))

        override fun getItemCount() = items.size

        override fun onBindViewHolder(holder: VH, position: Int) {
            val o = items[position]
            with(holder.b) {
                tvTitle.text = "Custom Order"
                tvDesc.text = o.description
                tvDate.text = "Req: ${o.requestedDate ?: ""} ${o.requestedTime?.take(5) ?: ""}"

                val statusColor = getStatusColor(o.status.name)
                tvStatus.text = o.status.name
                tvStatus.setTextColor(statusColor)
            }
        }
    }

    override fun onDestroyView() {
        LocalBroadcastManager.getInstance(requireContext())
            .unregisterReceiver(orderReceiver)
        super.onDestroyView()
        _binding = null
    }
}
