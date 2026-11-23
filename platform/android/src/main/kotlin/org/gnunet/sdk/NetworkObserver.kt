package org.gnunet.sdk

import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.ParcelFileDescriptor
import java.io.Closeable
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/** One selected non-VPN network and the original socket policy for its lifetime. */
internal class PhysicalNetwork(
    val network: Network,
    connectivity: ConnectivityManager,
) {
    private val live = AtomicBoolean(true)

    init {
        require(eligible(connectivity.getNetworkCapabilities(network))) {
            "GNUnet requires an accessible non-VPN Internet network"
        }
    }

    fun isLive(): Boolean = live.get()

    fun matches(candidate: Network): Boolean = isLive() && network == candidate

    fun retire(candidate: Network): Boolean =
        network == candidate && live.getAndSet(false)

    fun bind(fd: Int): Boolean {
        if (!isLive()) return false
        // Only the duplicate is closed. Android binds the original open socket
        // description to this network; protect is applied afterward.
        ParcelFileDescriptor.fromFd(fd).use { network.bindSocket(it.fileDescriptor) }
        return isLive()
    }

    companion object {
        fun eligible(capabilities: NetworkCapabilities?): Boolean =
            capabilities != null &&
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN) &&
                !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
    }
}

/** One original callback registration. DNS metadata never crosses network identities. */
internal class NetworkObserver(
    private val connectivity: ConnectivityManager,
    private val owner: GnunetNode,
    private val source: Source,
) : ConnectivityManager.NetworkCallback(), Closeable {
    sealed interface Source {
        data object ApplicationDefault : Source
        data object PhysicalHints : Source
        class Pinned(val original: PhysicalNetwork) : Source
    }

    private val lock = Any()
    private var network: Network? = null
    private var token = Any()
    private var closed = false
    private var registered = false
    private val pinned = (source as? Source.Pinned)?.original
    private val hintsOnly = source == Source.PhysicalHints
    private val fallback = if (!hintsOnly && Build.VERSION.SDK_INT < 26) {
        Executors.newSingleThreadExecutor { work -> Thread(work, "gnunet-default-network") }
    } else {
        null
    }
    private data class Read(val network: Network, val token: Any)
    private var nextRead: Read? = null
    private var reading = false

    fun start() {
        synchronized(lock) {
            check(!closed && !registered)
            if (source == Source.ApplicationDefault) {
                connectivity.registerDefaultNetworkCallback(this)
            } else {
                connectivity.registerNetworkCallback(
                    NetworkRequest.Builder()
                        .removeCapability(NetworkCapabilities.NET_CAPABILITY_TRUSTED)
                        .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED)
                        .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                        .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                        .build(),
                    this,
                )
            }
            registered = true
        }
    }

    fun isCurrent(original: Any): Boolean = synchronized(lock) { !closed && token === original }

    override fun onAvailable(network: Network) {
        if (hintsOnly) {
            rescan()
            return
        }
        val original = synchronized(lock) {
            if (closed || pinned?.matches(network) == false) return
            this.network = network
            token = Any()
            token
        }
        publish(original, emptyList())
        // API26 guarantees a subsequent LinkProperties callback. API24–25
        // require a separate read, outside NetworkCallback, with its own token.
        if (fallback != null) {
            try {
                synchronized(lock) {
                    if (closed || token !== original) return
                    nextRead = Read(network, original)
                    if (!reading) {
                        reading = true
                        fallback.execute { readLatest() }
                    }
                }
            } catch (error: Exception) {
                owner.networkFailed(this, error, original)
            }
        }
    }

    override fun onLinkPropertiesChanged(network: Network, linkProperties: LinkProperties) {
        if (hintsOnly) {
            rescan()
            return
        }
        val original = synchronized(lock) {
            if (closed || this.network != network || pinned?.matches(network) == false) return
            token = Any()
            nextRead = null
            token
        }
        try {
            publish(original, AndroidNodeOptions.dnsServers(linkProperties))
        } catch (error: Exception) {
            owner.networkFailed(this, error, original)
        }
    }

    override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
        if (hintsOnly) {
            rescan()
        } else if (pinned != null && !PhysicalNetwork.eligible(capabilities)) {
            onLost(network)
        }
    }

    override fun onLost(network: Network) {
        if (hintsOnly) {
            rescan()
            return
        }
        val original = synchronized(lock) {
            if (closed) return
            if (pinned != null) {
                if (!pinned.retire(network)) return
            } else if (this.network != network) {
                return
            }
            this.network = null
            token = Any()
            nextRead = null
            token
        }
        publish(original, emptyList())
    }

    private fun publish(original: Any, servers: List<String>) {
        try {
            owner.networkDns(this, original, servers)
        } catch (error: Exception) {
            owner.networkFailed(this, error, original)
        }
    }

    private fun rescan() {
        try {
            owner.networkRescan(this)
        } catch (error: Exception) {
            owner.networkFailed(this, error)
        }
    }

    private fun stillOnNetwork(network: Network): Boolean =
        if (pinned == null) connectivity.activeNetwork == network else pinned.matches(network)

    private fun readLatest() {
        while (true) {
            val original = synchronized(lock) {
                val next = nextRead
                nextRead = null
                if (closed || next == null) {
                    reading = false
                    return
                }
                next
            }
            try {
                if (!stillOnNetwork(original.network)) continue
                val properties = connectivity.getLinkProperties(original.network)
                if (!stillOnNetwork(original.network)) continue
                publish(original.token, properties?.let(AndroidNodeOptions::dnsServers) ?: emptyList())
            } catch (error: Exception) {
                owner.networkFailed(this, error, original.token)
            }
        }
    }

    override fun close() {
        val unregister = synchronized(lock) {
            if (closed) return
            closed = true
            if (pinned != null) pinned.retire(pinned.network)
            network = null
            nextRead = null
            val original = registered
            registered = false
            original
        }
        try {
            if (unregister) connectivity.unregisterNetworkCallback(this)
        } finally {
            fallback?.shutdownNow()
        }
    }
}
