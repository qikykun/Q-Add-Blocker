package com.qikykun.qaddblocker

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class AdBlockVpnService : VpnService() {

    companion object {
        const val TAG = "QAddBlocker"
        const val CHANNEL_ID = "q_add_blocker_channel"
        const val NOTIFICATION_ID = 1
        const val ACTION_STOP = "com.qikykun.qaddblocker.STOP"

        // Our fake DNS server IP on the VPN interface
        private val VPN_ADDRESS = "10.0.0.2"
        private val VPN_DNS = "10.0.0.1"
        private val UPSTREAM_DNS = "8.8.8.8"
        private val UPSTREAM_DNS_ALT = "1.1.1.1"

        var isRunning = AtomicBoolean(false)
            private set

        var instance: AdBlockVpnService? = null
            private set
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var readThread: Thread? = null
    private val dnsHandler = DnsHandler()
    private lateinit var executor: ExecutorService

    val blockedCount: Int get() = dnsHandler.blockedCount

    override fun onCreate() {
        super.onCreate()
        instance = this
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopVpn()
            return START_NOT_STICKY
        }

        startVpn()
        return START_STICKY
    }

    override fun onDestroy() {
        stopVpn()
        instance = null
        super.onDestroy()
    }

    private fun startVpn() {
        if (isRunning.get()) return

        try {
            val builder = Builder()
            builder.setSession("Q Add Blocker")
            builder.addAddress(VPN_ADDRESS, 32)
            builder.addDnsServer(VPN_DNS)
            builder.addRoute(VPN_DNS, 32)

            // Don't intercept traffic to our upstream DNS servers
            // (they go through protect()'d sockets)

            // Allow apps to bypass VPN if needed
            builder.setBlocking(true)

            vpnInterface = builder.establish()

            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface")
                stopSelf()
                return
            }

            isRunning.set(true)
            executor = Executors.newCachedThreadPool()

            // Start foreground notification
            startForeground(NOTIFICATION_ID, createNotification())

            // Start reading packets
            readThread = Thread({ packetLoop() }, "VPN-PacketLoop")
            readThread?.start()

            Log.i(TAG, "VPN started successfully")

        } catch (e: Exception) {
            Log.e(TAG, "Failed to start VPN", e)
            stopVpn()
        }
    }

    fun stopVpn() {
        isRunning.set(false)

        readThread?.interrupt()
        readThread = null

        if (::executor.isInitialized) {
            executor.shutdownNow()
        }

        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error closing VPN interface", e)
        }
        vpnInterface = null

        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()

        Log.i(TAG, "VPN stopped")
    }

    /**
     * Main loop: read IP packets from TUN, process DNS queries.
     */
    private fun packetLoop() {
        val fd = vpnInterface?.fileDescriptor ?: return
        val input = FileInputStream(fd)
        val output = FileOutputStream(fd)
        val packet = ByteArray(32767)

        while (isRunning.get()) {
            try {
                val length = input.read(packet)
                if (length <= 0) continue

                val packetCopy = packet.copyOf(length)
                processPacket(packetCopy, length, output)

            } catch (e: InterruptedException) {
                break
            } catch (e: Exception) {
                if (isRunning.get()) {
                    Log.e(TAG, "Error reading packet", e)
                }
                break
            }
        }
    }

    /**
     * Process a single IP packet.
     */
    private fun processPacket(packet: ByteArray, length: Int, output: FileOutputStream) {
        if (length < 20) return

        // Check IPv4
        val version = (packet[0].toInt() and 0xF0) shr 4
        if (version != 4) return

        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (length < ihl) return

        // Check UDP (protocol 17)
        val protocol = packet[9].toInt() and 0xFF
        if (protocol != 17) return

        if (length < ihl + 8) return

        // Parse UDP header
        val buf = ByteBuffer.wrap(packet)
        val srcPort = buf.getShort(ihl).toInt() and 0xFFFF
        val dstPort = buf.getShort(ihl + 2).toInt() and 0xFFFF

        // Only handle DNS (port 53)
        if (dstPort != 53) return

        // Extract IPs
        val srcIp = ByteArray(4)
        val dstIp = ByteArray(4)
        System.arraycopy(packet, 12, srcIp, 0, 4)
        System.arraycopy(packet, 16, dstIp, 0, 4)

        // Extract DNS payload
        val dnsOffset = ihl + 8
        val dnsLength = length - dnsOffset
        if (dnsLength < 12) return

        val dnsPayload = ByteArray(dnsLength)
        System.arraycopy(packet, dnsOffset, dnsPayload, 0, dnsLength)

        // Parse domain name
        val domain = dnsHandler.extractDomain(dnsPayload) ?: return

        if (dnsHandler.isBlocked(domain)) {
            // Create blocked response (0.0.0.0)
            Log.d(TAG, "BLOCKED: $domain")
            val dnsResponse = dnsHandler.createBlockedResponse(dnsPayload)
            val responsePacket = dnsHandler.wrapInIpUdp(
                dnsResponse, dstIp, srcIp, 53, srcPort
            )
            synchronized(output) {
                output.write(responsePacket)
                output.flush()
            }
        } else {
            // Forward to real DNS server
            executor.execute {
                forwardDnsQuery(dnsPayload, srcIp, dstIp, srcPort, output)
            }
        }
    }

    /**
     * Forward DNS query to upstream DNS server and relay response back.
     */
    private fun forwardDnsQuery(
        dnsPayload: ByteArray,
        clientIp: ByteArray,
        fakeServerIp: ByteArray,
        clientPort: Int,
        output: FileOutputStream
    ) {
        var socket: DatagramSocket? = null
        try {
            socket = DatagramSocket()
            protect(socket) // Prevent loop through VPN

            // Send to upstream DNS
            val upstreamAddr = InetAddress.getByName(UPSTREAM_DNS)
            val sendPacket = DatagramPacket(dnsPayload, dnsPayload.size, upstreamAddr, 53)
            socket.soTimeout = 5000
            socket.send(sendPacket)

            // Receive response
            val responseBuffer = ByteArray(4096)
            val receivePacket = DatagramPacket(responseBuffer, responseBuffer.size)
            socket.receive(receivePacket)

            val dnsResponse = ByteArray(receivePacket.length)
            System.arraycopy(responseBuffer, 0, dnsResponse, 0, receivePacket.length)

            // Wrap in IP+UDP and write to TUN
            val ipPacket = dnsHandler.wrapInIpUdp(
                dnsResponse, fakeServerIp, clientIp, 53, clientPort
            )
            synchronized(output) {
                output.write(ipPacket)
                output.flush()
            }

        } catch (e: Exception) {
            Log.e(TAG, "DNS forward failed", e)
            // Try alternate DNS
            tryAlternateDns(dnsPayload, clientIp, fakeServerIp, clientPort, output)
        } finally {
            socket?.close()
        }
    }

    /**
     * Try alternate DNS server if primary fails.
     */
    private fun tryAlternateDns(
        dnsPayload: ByteArray,
        clientIp: ByteArray,
        fakeServerIp: ByteArray,
        clientPort: Int,
        output: FileOutputStream
    ) {
        var socket: DatagramSocket? = null
        try {
            socket = DatagramSocket()
            protect(socket)

            val altAddr = InetAddress.getByName(UPSTREAM_DNS_ALT)
            val sendPacket = DatagramPacket(dnsPayload, dnsPayload.size, altAddr, 53)
            socket.soTimeout = 5000
            socket.send(sendPacket)

            val responseBuffer = ByteArray(4096)
            val receivePacket = DatagramPacket(responseBuffer, responseBuffer.size)
            socket.receive(receivePacket)

            val dnsResponse = ByteArray(receivePacket.length)
            System.arraycopy(responseBuffer, 0, dnsResponse, 0, receivePacket.length)

            val ipPacket = dnsHandler.wrapInIpUdp(
                dnsResponse, fakeServerIp, clientIp, 53, clientPort
            )
            synchronized(output) {
                output.write(ipPacket)
                output.flush()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Alt DNS also failed", e)
        } finally {
            socket?.close()
        }
    }

    // === Notification ===

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Q Add Blocker",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Ad blocking status"
                setShowBadge(false)
            }
            val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            manager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        val openIntent = Intent(this, MainActivity::class.java)
        val pendingOpen = PendingIntent.getActivity(
            this, 0, openIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val stopIntent = Intent(this, AdBlockVpnService::class.java).apply {
            action = ACTION_STOP
        }
        val pendingStop = PendingIntent.getService(
            this, 1, stopIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Q Add Blocker")
            .setContentText("Ad blocking aktif — iklan sedang diblokir")
            .setSmallIcon(R.drawable.ic_shield)
            .setOngoing(true)
            .setContentIntent(pendingOpen)
            .addAction(R.drawable.ic_shield, "Matikan", pendingStop)
            .build()
    }
}
