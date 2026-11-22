package com.qikykun.qaddblocker

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer

/**
 * Handles DNS packet parsing, domain blocking, and response crafting.
 */
class DnsHandler {

    // Blocked ad/tracking domains
    private val blockedDomains = setOf(
        // Google Ads
        "googleads.g.doubleclick.net",
        "pagead2.googlesyndication.com",
        "adservice.google.com",
        "googleadservices.com",
        "googlesyndication.com",
        "doubleclick.net",
        "tpc.googlesyndication.com",
        "googletagservices.com",
        "adclick.g.doubleclick.net",
        "ad.doubleclick.net",
        "static.doubleclick.net",
        "cm.g.doubleclick.net",
        "s0.2mdn.net",
        "z2cdn.net",
        "stats.g.doubleclick.net",
        "ade.googlesyndication.com",
        "www.googletagservices.com",
        "www.googleadservices.com",

        // Facebook / Meta Ads
        "an.facebook.com",
        "ads.facebook.com",
        "pixel.facebook.com",
        "www.facebook.com/tr",

        // Amazon Ads
        "ads.amazon-adsystem.com",
        "aax-us-east.amazon-adsystem.com",
        "amazon-adsystem.com",

        // Ad Networks
        "ads.pubmatic.com",
        "image2.pubmatic.com",
        "cdn.taboola.com",
        "trc.taboola.com",
        "api.taboola.com",
        "server.outbrain.com",
        "odb.outbrain.com",
        "log.outbrain.com",
        "cdn.mgid.com",
        "cm.mgid.com",
        "ads.mgid.com",
        "hb.openx.net",
        "us-u.openx.net",
        "ads.openx.net",
        "ib.adnxs.com",
        "secure.adnxs.com",
        "sdk.criteo.com",
        "gum.criteo.com",
        "bidder.criteo.com",
        "ads.revcontent.com",
        "cdn.sharethrough.com",
        "ads.rubiconproject.com",
        "fastlane.rubiconproject.com",
        "static.media.net",
        "contextual.media.net",
        "display.media.net",
        "d.turn.com",
        "ad.turn.com",
        "ads.teads.tv",
        "t.teads.tv",
        "match.adsrvr.org",
        "match.prod.bidr.io",

        // Mobile Ad SDKs
        "ads.mopub.com",
        "ads.inmobi.com",
        "ads.unity3d.com",
        "unityads.unity3d.com",
        "ads.admob.com",

        // Tracking / Attribution
        "app.adjust.com",
        "sdk.adjust.com",
        "tracking.adjust.com",
        "app.appsflyer.com",
        "launches.appsflyer.com",
        "sdk.iad-01.braze.com",
        "sb.scorecardresearch.com",
        "pixel.quantserve.com",
        "cdn.quantserve.com",
        "pixel.adsafeprotected.com",
        "static.adsafeprotected.com",
        "fw.adsafeprotected.com",
        "pixel.tapad.com",
        "nr-data.net",

        // Social Media Ads
        "ads.tiktok.com",
        "analytics-sg.tiktok.com",
        "ads.twitter.com",
        "ads-api.twitter.com",
        "ads.linkedin.com",
        "ads.pinterest.com",
        "ads.reddit.com",
        "ads.snapchat.com",

        // Pop-ups & Low-quality ads
        "syndication.realsrv.com",
        "cdn.popcash.net",
        "go.onclasrv.com",
        "cdn.onthe.io",
        "ads.betweendigital.com",
        "bttrack.com",
        "e.serverbid.com",
        "ad.lgappstv.com",
        "ads.serving.tv",
        "samsungads.com",
        "config.samsungads.com",

        // Additional common ad domains
        "adcolony.com",
        "ads.yahoo.com",
        "advertising.com",
        "chartboost.com",
        "flurry.com",
        "startappservice.com",
        "supersonicads.com",
        "vungle.com",
        "moatads.com"
    )

    var blockedCount = 0
        private set

    /**
     * Check if a domain should be blocked.
     * Also checks parent domains (e.g. x.doubleclick.net matches doubleclick.net).
     */
    fun isBlocked(domain: String): Boolean {
        val lowerDomain = domain.lowercase().trimEnd('.')
        var d = lowerDomain
        while (d.contains('.')) {
            if (blockedDomains.contains(d)) {
                blockedCount++
                return true
            }
            d = d.substringAfter('.')
        }
        if (blockedDomains.contains(d)) {
            blockedCount++
            return true
        }
        return false
    }

    /**
     * Parse domain name from DNS query payload.
     * Returns the domain name and the offset after the name.
     */
    fun parseDomainName(data: ByteArray, startOffset: Int): Pair<String, Int> {
        val parts = mutableListOf<String>()
        var offset = startOffset

        while (offset < data.size) {
            val labelLen = data[offset].toInt() and 0xFF
            if (labelLen == 0) {
                offset++
                break
            }
            // Handle DNS compression pointers
            if (labelLen and 0xC0 == 0xC0) {
                val pointerOffset = ((labelLen and 0x3F) shl 8) or (data[offset + 1].toInt() and 0xFF)
                val (pointed, _) = parseDomainName(data, pointerOffset)
                parts.add(pointed)
                offset += 2
                return Pair(parts.joinToString("."), offset)
            }
            offset++
            if (offset + labelLen > data.size) break
            parts.add(String(data, offset, labelLen))
            offset += labelLen
        }

        return Pair(parts.joinToString("."), offset)
    }

    /**
     * Extract domain name from a DNS query payload (starting after IP+UDP headers).
     * DNS header is 12 bytes, then the question section starts.
     */
    fun extractDomain(dnsPayload: ByteArray): String? {
        if (dnsPayload.size < 12) return null
        // Question starts at offset 12
        val (domain, _) = parseDomainName(dnsPayload, 12)
        return domain.ifEmpty { null }
    }

    /**
     * Create a DNS response that returns 0.0.0.0 for a blocked domain.
     */
    fun createBlockedResponse(queryPayload: ByteArray): ByteArray {
        if (queryPayload.size < 12) return queryPayload

        val output = ByteArrayOutputStream()

        // DNS Header (12 bytes)
        // Copy Transaction ID (2 bytes)
        output.write(queryPayload, 0, 2)

        // Flags: standard response, no error
        output.write(0x81) // QR=1, Opcode=0, AA=0, TC=0, RD=1
        output.write(0x80) // RA=1, Z=0, RCODE=0

        // Questions: 1
        output.write(0x00)
        output.write(0x01)

        // Answers: 1
        output.write(0x00)
        output.write(0x01)

        // Authority RRs: 0
        output.write(0x00)
        output.write(0x00)

        // Additional RRs: 0
        output.write(0x00)
        output.write(0x00)

        // Copy Question section from query
        var offset = 12
        while (offset < queryPayload.size) {
            val labelLen = queryPayload[offset].toInt() and 0xFF
            if (labelLen == 0) {
                output.write(0x00)
                offset++
                break
            }
            output.write(queryPayload, offset, labelLen + 1)
            offset += labelLen + 1
        }

        // Question Type and Class (4 bytes)
        if (offset + 4 <= queryPayload.size) {
            output.write(queryPayload, offset, 4)
            offset += 4
        } else {
            // Default: Type A, Class IN
            output.write(byteArrayOf(0x00, 0x01, 0x00, 0x01))
        }

        // Answer section
        // Name pointer to question (0xC00C = pointer to offset 12)
        output.write(0xC0)
        output.write(0x0C)

        // Type A (1)
        output.write(0x00)
        output.write(0x01)

        // Class IN (1)
        output.write(0x00)
        output.write(0x01)

        // TTL: 300 seconds
        output.write(0x00)
        output.write(0x00)
        output.write(0x01)
        output.write(0x2C)

        // RDLENGTH: 4 (IPv4 address)
        output.write(0x00)
        output.write(0x04)

        // RDATA: 0.0.0.0
        output.write(0x00)
        output.write(0x00)
        output.write(0x00)
        output.write(0x00)

        return output.toByteArray()
    }

    /**
     * Wrap a DNS response in UDP + IPv4 headers.
     */
    fun wrapInIpUdp(
        dnsResponse: ByteArray,
        srcIp: ByteArray,
        dstIp: ByteArray,
        srcPort: Int,
        dstPort: Int
    ): ByteArray {
        val udpLen = 8 + dnsResponse.size
        val totalLen = 20 + udpLen

        val packet = ByteArray(totalLen)
        val buf = ByteBuffer.wrap(packet)

        // === IPv4 Header (20 bytes) ===
        buf.put((0x45).toByte())       // Version 4, IHL 5
        buf.put(0x00.toByte())          // DSCP/ECN
        buf.putShort(totalLen.toShort()) // Total Length
        buf.putShort(0x0000.toShort())  // Identification
        buf.putShort(0x4000.toShort())  // Flags: Don't Fragment
        buf.put(64.toByte())            // TTL
        buf.put(17.toByte())            // Protocol: UDP
        buf.putShort(0x0000.toShort())  // Checksum (calculated below)
        buf.put(srcIp)                  // Source IP
        buf.put(dstIp)                  // Destination IP

        // Calculate IPv4 header checksum
        val checksum = calculateIpChecksum(packet, 0, 20)
        packet[10] = (checksum shr 8).toByte()
        packet[11] = (checksum and 0xFF).toByte()

        // === UDP Header (8 bytes) ===
        buf.position(20)
        buf.putShort(srcPort.toShort())  // Source Port
        buf.putShort(dstPort.toShort())  // Destination Port
        buf.putShort(udpLen.toShort())   // UDP Length
        buf.putShort(0x0000.toShort())   // UDP Checksum (optional for IPv4)

        // === DNS Payload ===
        buf.put(dnsResponse)

        return packet
    }

    /**
     * Calculate IPv4 header checksum.
     */
    fun calculateIpChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        var remaining = length

        while (remaining > 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
            remaining -= 2
        }

        if (remaining == 1) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }

        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }

        return (sum.inv() and 0xFFFF).toInt()
    }
}
