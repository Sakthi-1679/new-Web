package com.vkmflowers.ui.main

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import com.google.android.material.bottomnavigation.BottomNavigationView
import com.vkmflowers.R
import com.vkmflowers.databinding.ActivityMainBinding
import com.vkmflowers.ui.admin.AdminDashboardFragment
import com.vkmflowers.ui.custom.CustomOrderFragment
import com.vkmflowers.ui.home.HomeFragment
import com.vkmflowers.ui.orders.MyOrdersFragment
import com.vkmflowers.ui.profile.ProfileFragment
import com.vkmflowers.utils.SessionManager

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var session: SessionManager

    // Cache fragment instances so coroutines/state survive tab switches
    private val homeFragment     by lazy { HomeFragment() }
    private val ordersFragment   by lazy { MyOrdersFragment() }
    private val customFragment   by lazy { CustomOrderFragment() }
    private val profileFragment  by lazy { ProfileFragment() }
    private val adminFragment    by lazy { AdminDashboardFragment() }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        session = SessionManager(this)
        val isAdmin = session.isAdmin()

        val navView: BottomNavigationView = binding.bottomNav
        if (isAdmin) {
            navView.menu.clear()
            navView.inflateMenu(R.menu.bottom_nav_admin)
            loadFragment(adminFragment)
        } else {
            navView.menu.clear()
            navView.inflateMenu(R.menu.bottom_nav_user)
            loadFragment(homeFragment)
        }

        navView.setOnItemSelectedListener { item ->
            when (item.itemId) {
                R.id.nav_home       -> { loadFragment(homeFragment);    true }
                R.id.nav_orders     -> { loadFragment(ordersFragment);  true }
                R.id.nav_custom     -> { loadFragment(customFragment);  true }
                R.id.nav_profile    -> { loadFragment(profileFragment); true }
                R.id.nav_dashboard  -> { loadFragment(adminFragment);   true }
                else -> false
            }
        }
    }

    private fun loadFragment(fragment: Fragment) {
        // "show/hide" approach keeps fragment views alive, preventing binding NPE
        val tx = supportFragmentManager.beginTransaction()
        supportFragmentManager.fragments.forEach { tx.hide(it) }
        if (!fragment.isAdded) {
            tx.add(R.id.fragmentContainer, fragment)
        } else {
            tx.show(fragment)
        }
        tx.commit()
    }
}
