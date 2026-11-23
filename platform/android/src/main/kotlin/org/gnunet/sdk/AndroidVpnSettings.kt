package org.gnunet.sdk

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.util.Collections

/** A numeric address assigned by Android to the tunnel interface. */
internal data class AndroidVpnAddress(val address: InetAddress, val prefixLength: Int) {
    init {
        validatePrefix(address, prefixLength)
    }
}

/** An exact canonical IPv4 or IPv6 destination network, including explicit /0 routes. */
internal data class AndroidVpnRoute(val network: InetAddress, val prefixLength: Int) {
    init {
        validatePrefix(network, prefixLength)
        require(network !is Inet6Address || network.scopeId == 0) { "VPN routes use unscoped networks" }
        val bytes = network.address
        val networkBytes = prefixLength / 8
        for (index in networkBytes until bytes.size) {
            val hostBits = if (index == networkBytes) 8 - prefixLength % 8 else 8
            val hostMask = (1 shl hostBits) - 1
            require((bytes[index].toInt() and hostMask) == 0) { "VPN route has nonzero host bits" }
        }
    }
}

/** The interface addresses, exact routed prefixes and MTU installed by Android. */
internal class AndroidVpnSettings(addresses: List<AndroidVpnAddress>, routes: List<AndroidVpnRoute>, val mtu: Int) {
    val addresses: List<AndroidVpnAddress> = Collections.unmodifiableList(addresses.toList())
    val routes: List<AndroidVpnRoute> = Collections.unmodifiableList(routes.toList())

    init {
        require(this.addresses.isNotEmpty()) { "VPN requires an interface address" }
        val ipv6 = this.addresses.any { it.address is Inet6Address } ||
            this.routes.any { it.network is Inet6Address }
        val minimumMtu = if (ipv6) 1280 else 68
        require(mtu in minimumMtu..65535) { "VPN MTU does not fit the selected IP families" }
    }
}

private fun validatePrefix(address: InetAddress, prefixLength: Int) {
    val width = when (address) {
        is Inet4Address -> 32
        is Inet6Address -> 128
        else -> throw IllegalArgumentException("VPN requires an IPv4 or IPv6 address")
    }
    require(prefixLength in 0..width) { "VPN prefix is out of range" }
}
