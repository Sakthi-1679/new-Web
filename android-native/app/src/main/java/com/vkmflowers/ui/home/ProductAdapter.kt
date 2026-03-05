package com.vkmflowers.ui.home

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.bumptech.glide.Glide
import com.vkmflowers.R
import com.vkmflowers.data.models.Product
import com.vkmflowers.databinding.ItemProductBinding
import com.vkmflowers.utils.formatPrice

class ProductAdapter(
    private val onOrderClick: (Product) -> Unit
) : ListAdapter<Product, ProductAdapter.ViewHolder>(DIFF) {

    inner class ViewHolder(val binding: ItemProductBinding) : RecyclerView.ViewHolder(binding.root)

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ViewHolder {
        val binding = ItemProductBinding.inflate(LayoutInflater.from(parent.context), parent, false)
        return ViewHolder(binding)
    }

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        val product = getItem(position)
        with(holder.binding) {
            tvTitle.text = product.title
            tvDesc.text = product.description
            tvPrice.text = formatPrice(product.price)

            if (product.images.isNotEmpty()) {
                Glide.with(root.context)
                    .load(product.images[0])
                    .placeholder(R.drawable.ic_flower)
                    .centerCrop()
                    .into(ivProduct)
            } else {
                ivProduct.setImageResource(R.drawable.ic_flower)
            }

            btnOrder.setOnClickListener { onOrderClick(product) }
            root.setOnClickListener { onOrderClick(product) }
        }
    }

    companion object {
        val DIFF = object : DiffUtil.ItemCallback<Product>() {
            override fun areItemsTheSame(a: Product, b: Product) = a.id == b.id
            override fun areContentsTheSame(a: Product, b: Product) = a == b
        }
    }
}
