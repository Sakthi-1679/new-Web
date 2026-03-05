package com.vkmflowers.ui.custom

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.activity.result.contract.ActivityResultContracts
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.vkmflowers.data.models.PlaceCustomOrderRequest
import com.vkmflowers.data.network.ApiClient
import com.vkmflowers.databinding.FragmentCustomOrderBinding
import com.vkmflowers.utils.SessionManager
import com.vkmflowers.utils.snack
import kotlinx.coroutines.launch
import java.net.URLEncoder
import android.util.Base64
import android.graphics.BitmapFactory
import android.graphics.Bitmap
import java.io.ByteArrayOutputStream
import android.provider.MediaStore

class CustomOrderFragment : Fragment() {

    private var _binding: FragmentCustomOrderBinding? = null
    private val binding get() = _binding!!
    private lateinit var session: SessionManager
    private val selectedImages = mutableListOf<String>()

    private val pickImages = registerForActivityResult(ActivityResultContracts.GetMultipleContents()) { uris ->
        for (uri in uris.take(5 - selectedImages.size)) {
            try {
                val stream = requireContext().contentResolver.openInputStream(uri) ?: continue
                val bytes = stream.readBytes()
                val b64 = Base64.encodeToString(bytes, Base64.DEFAULT)
                selectedImages.add("data:image/jpeg;base64,$b64")
            } catch (e: Exception) { /* skip */ }
        }
        updateImageCount()
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentCustomOrderBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        session = SessionManager(requireContext())

        val user = session.getUser()
        binding.etName.setText(user?.name ?: "")
        binding.etPhone.setText(user?.phone ?: "")

        binding.btnAddPhotos.setOnClickListener {
            if (selectedImages.size < 5) pickImages.launch("image/*")
            else binding.root.snack("Maximum 5 photos", isError = true)
        }

        binding.btnSubmit.setOnClickListener { submitOrder() }
    }

    private fun updateImageCount() {
        binding.tvPhotoCount.text = "${selectedImages.size}/5 photos selected"
        binding.tvPhotoCount.visibility = if (selectedImages.isNotEmpty()) View.VISIBLE else View.GONE
    }

    private fun submitOrder() {
        val desc = binding.etDesc.text?.toString()?.trim() ?: ""
        val date = binding.etDate.text?.toString()?.trim() ?: ""
        val time = binding.etTime.text?.toString()?.trim() ?: ""
        val name = binding.etName.text?.toString()?.trim() ?: ""
        val phone = binding.etPhone.text?.toString()?.trim() ?: ""

        if (desc.isEmpty() || date.isEmpty() || time.isEmpty() || name.isEmpty() || phone.isEmpty()) {
            binding.root.snack("Please fill all required fields", isError = true)
            return
        }

        val userId = session.getUser()?.id ?: return
        setLoading(true)

        viewLifecycleOwner.lifecycleScope.launch {
            try {
                ApiClient.service.placeCustomOrder(
                    PlaceCustomOrderRequest(
                        userId = userId,
                        description = desc,
                        requestedDate = date,
                        requestedTime = time,
                        contactName = name,
                        contactPhone = phone,
                        images = selectedImages.toList()
                    )
                )
                val adminPhone = try { ApiClient.service.getAdminContact().phone ?: "9999999999" } catch (e: Exception) { "9999999999" }
                val msg = buildString {
                    appendLine("🎨 *Custom Order – VKM Flowers*")
                    appendLine()
                    appendLine("👤 Name: $name")
                    appendLine("📞 Phone: $phone")
                    appendLine("📝 Description: $desc")
                    appendLine("📅 Date: $date at $time")
                    if (selectedImages.isNotEmpty()) appendLine("📷 Photos: ${selectedImages.size} image(s) — check app")
                }
                val encoded = URLEncoder.encode(msg, "UTF-8")
                val intent = Intent(Intent.ACTION_VIEW, Uri.parse("https://wa.me/91$adminPhone?text=$encoded"))
                startActivity(intent)

                if (_binding == null) return@launch
                // Reset form
                binding.etDesc.setText("")
                binding.etDate.setText("")
                binding.etTime.setText("")
                selectedImages.clear()
                updateImageCount()
                binding.root.snack("Custom order placed! WhatsApp opened.")
            } catch (e: Exception) {
                if (_binding == null) return@launch
                binding.root.snack(e.message ?: "Failed to place order", isError = true)
            } finally {
                if (_binding != null) setLoading(false)
            }
        }
    }

    private fun setLoading(loading: Boolean) {
        binding.btnSubmit.isEnabled = !loading
        binding.progressBar.visibility = if (loading) View.VISIBLE else View.GONE
        binding.btnSubmitText.visibility = if (loading) View.GONE else View.VISIBLE
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
