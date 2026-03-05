package com.vkmflowers.ui.profile

import android.content.Intent
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.appcompat.app.AlertDialog
import androidx.fragment.app.Fragment
import com.vkmflowers.databinding.FragmentProfileBinding
import com.vkmflowers.ui.auth.LoginActivity
import com.vkmflowers.utils.SessionManager

class ProfileFragment : Fragment() {

    private var _binding: FragmentProfileBinding? = null
    private val binding get() = _binding!!
    private lateinit var session: SessionManager

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View {
        _binding = FragmentProfileBinding.inflate(inflater, container, false)
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        session = SessionManager(requireContext())

        val user = session.getUser()
        val isAdmin = session.isAdmin()

        binding.tvName.text = user?.name ?: "—"
        binding.tvEmail.text = user?.email ?: "—"
        binding.tvPhone.text = user?.phone ?: "—"
        binding.tvArea.text = user?.area ?: "—"
        binding.tvCity.text = user?.city ?: "—"

        if (isAdmin) {
            binding.tvRole.text = "⚡ Admin"
            binding.tvRole.setTextColor(requireContext().getColor(com.vkmflowers.R.color.admin_text))
            binding.cardRole.setCardBackgroundColor(requireContext().getColor(com.vkmflowers.R.color.admin_badge))
            binding.ivAvatar.setImageResource(com.vkmflowers.R.drawable.ic_grid)
        } else {
            binding.tvRole.text = "👤 Customer"
            binding.tvRole.setTextColor(requireContext().getColor(com.vkmflowers.R.color.primary))
            binding.cardRole.setCardBackgroundColor(requireContext().getColor(com.vkmflowers.R.color.primary_light))
            binding.ivAvatar.setImageResource(com.vkmflowers.R.drawable.ic_person)
        }

        binding.btnLogout.setOnClickListener {
            AlertDialog.Builder(requireContext())
                .setTitle("Sign Out")
                .setMessage("Are you sure you want to sign out?")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Sign Out") { _, _ ->
                    session.clearSession()
                    startActivity(Intent(requireContext(), LoginActivity::class.java).apply {
                        flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
                    })
                }
                .show()
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        _binding = null
    }
}
