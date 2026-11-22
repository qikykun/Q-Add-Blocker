package com.qikykun.qaddblocker

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat

class MainActivity : AppCompatActivity() {

    companion object {
        private const val VPN_REQUEST_CODE = 100
        private const val NOTIFICATION_PERMISSION_CODE = 101
    }

    private lateinit var toggleButton: Button
    private lateinit var statusText: TextView
    private lateinit var blockedCountText: TextView
    private lateinit var subtitleText: TextView

    private val handler = Handler(Looper.getMainLooper())
    private val updateRunnable = object : Runnable {
        override fun run() {
            updateUI()
            handler.postDelayed(this, 1000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        toggleButton = findViewById(R.id.toggleButton)
        statusText = findViewById(R.id.statusText)
        blockedCountText = findViewById(R.id.blockedCountText)
        subtitleText = findViewById(R.id.subtitleText)

        toggleButton.setOnClickListener {
            if (AdBlockVpnService.isRunning.get()) {
                stopAdBlocking()
            } else {
                startAdBlocking()
            }
        }

        // Request notification permission on Android 13+
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                ActivityCompat.requestPermissions(
                    this,
                    arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                    NOTIFICATION_PERMISSION_CODE
                )
            }
        }

        updateUI()
    }

    override fun onResume() {
        super.onResume()
        handler.post(updateRunnable)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(updateRunnable)
    }

    private fun startAdBlocking() {
        val vpnIntent = VpnService.prepare(this)
        if (vpnIntent != null) {
            startActivityForResult(vpnIntent, VPN_REQUEST_CODE)
        } else {
            launchVpnService()
        }
    }

    private fun stopAdBlocking() {
        AdBlockVpnService.instance?.stopVpn()
        updateUI()
    }

    private fun launchVpnService() {
        val intent = Intent(this, AdBlockVpnService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
        // Give service time to start
        handler.postDelayed({ updateUI() }, 500)
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            launchVpnService()
        }
    }

    private fun updateUI() {
        val running = AdBlockVpnService.isRunning.get()

        if (running) {
            toggleButton.text = "ON"
            toggleButton.setBackgroundResource(R.drawable.bg_button_on)
            toggleButton.setTextColor(ContextCompat.getColor(this, android.R.color.white))
            statusText.text = "Perlindungan Aktif"
            statusText.setTextColor(ContextCompat.getColor(this, R.color.green_500))
            subtitleText.text = "Iklan sedang diblokir"

            val count = AdBlockVpnService.instance?.blockedCount ?: 0
            blockedCountText.text = "$count iklan diblokir"
        } else {
            toggleButton.text = "OFF"
            toggleButton.setBackgroundResource(R.drawable.bg_button_off)
            toggleButton.setTextColor(ContextCompat.getColor(this, R.color.gray_600))
            statusText.text = "Tidak Aktif"
            statusText.setTextColor(ContextCompat.getColor(this, R.color.gray_600))
            subtitleText.text = "Tekan tombol untuk mulai"
            blockedCountText.text = ""
        }
    }
}
