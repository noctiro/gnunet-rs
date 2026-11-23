package org.gnunet.sdk

import android.content.Context
import android.net.ConnectivityManager
import android.os.Looper
import java.io.Closeable
import java.io.File
import java.io.IOException
import java.util.concurrent.CountDownLatch

/** Owns one Rust node. Call [close] on a background thread to join it. */
class GnunetNode private constructor(
    private var handle: Long,
    private val networkSource: NetworkObserver.Source,
) : Closeable {
    private val lock = Any()
    private val destroyed = CountDownLatch(1)
    private var closeFailure: Throwable? = null
    private var vpn: AndroidVpnProvider? = null
    private var network: NetworkObserver? = null
    private var stopping = false
    private var networkError: String? = null

    /** Paths must refer to existing app-private directories. Bind addresses are numeric. */
    data class Options(
        val stateDirectory: File,
        val ipcDirectory: File,
        val configFile: File? = null,
        val tcpBind: String = "127.0.0.1:0",
        val udp4Bind: String = "127.0.0.1:0",
        val udp6Bind: String? = null,
        val dnsServers: List<String> = emptyList(),
        val startupTimeoutMs: Int = 30_000,
        val drainTimeoutMs: Int = 5_000,
        val bootstrapDataDirectory: File? = null,
    )

    enum class Phase { STARTING, READY, STOPPING, STOPPED, FAILED }

    /** The verified peer and the original bound ports captured at readiness. */
    class Ready internal constructor(
        val peer: ByteArray,
        val tcpPort: Int,
        val udp4Port: Int,
        val udp6Port: Int?,
        val quicPort: Int?,
        val http3Port: Int?,
        val unixMtu: Int?,
    )

    /** A local lifecycle observation, with a diagnostic on terminal failure. */
    data class Snapshot(
        val phase: Phase,
        val ready: Ready?,
        val error: String?,
        /** A network observation/update failure which requested node shutdown. */
        val networkError: String? = null,
    )

    /** Rejected synchronous SDK operation. Asynchronous failure appears in [snapshot]. */
    class NativeFailure internal constructor(operation: String, val status: Int) :
        IOException("GNUnet $operation failed (SDK status $status)")

    /** Ask the original node to stop. Retain this owner to observe shutdown or failure. */
    fun requestStop() {
        val observer = synchronized(lock) {
            if (handle != 0L) checkStatus("stop", NativeNode.stop(handle))
            stopping = true
            network.also { network = null }
        }
        observer?.close()
    }

    internal fun startVpnRoutes() {
        synchronized(lock) {
            check(handle != 0L) { "GNUnet node owner is closed" }
            checkNotNull(vpn).start()
        }
    }

    internal fun revokeVpn() {
        val provider = synchronized(lock) { vpn }
        try {
            provider?.fence()
        } finally {
            requestStop()
        }
    }

    /** Ask the node to rescan its local addresses after a host network change. */
    fun notifyNetworkChange() {
        synchronized(lock) {
            if (handle != 0L) checkStatus("network change", NativeNode.notifyNetworkChange(handle))
        }
    }

    /** Replace a non-VPN node's numeric DNS endpoints. An empty list clears them. */
    fun setDnsServers(servers: List<String>) {
        val bytes = dnsBytes(servers)
        synchronized(lock) {
            if (handle == 0L) return
            check(networkSource == NetworkObserver.Source.ApplicationDefault) {
                "Android network policy supplies DNS for the VPN node"
            }
            checkStatus("DNS update", NativeNode.setDnsServers(handle, bytes))
        }
    }

    internal fun followNetwork(connectivity: ConnectivityManager) {
        val observer = NetworkObserver(connectivity, this, networkSource)
        synchronized(lock) {
            check(handle != 0L && !stopping && network == null) { "GNUnet network observation is unavailable" }
            network = observer
        }
        observer.start()
    }

    internal fun networkDns(observer: NetworkObserver, token: Any, servers: List<String>) {
        synchronized(lock) {
            if (handle == 0L || network !== observer || !observer.isCurrent(token)) return
            val bytes = dnsBytes(servers)
            checkStatus("DNS update", NativeNode.setDnsServers(handle, bytes))
        }
    }

    internal fun networkRescan(observer: NetworkObserver) {
        synchronized(lock) {
            if (handle == 0L || network !== observer) return
            checkStatus("network change", NativeNode.notifyNetworkChange(handle))
        }
    }

    internal fun networkFailed(observer: NetworkObserver, error: Exception, token: Any? = null) {
        synchronized(lock) {
            if (network !== observer || (token != null && !observer.isCurrent(token))) return
            network = null
            stopping = true
            networkError = error.message ?: error.javaClass.simpleName
            if (handle != 0L) NativeNode.stop(handle)
        }
        try {
            observer.close()
        } catch (cleanup: Exception) {
            synchronized(lock) { networkError += "; unregister: ${cleanup.message}" }
        }
    }

    /** Read the original node while this owner remains open. */
    fun snapshot(): Snapshot = synchronized(lock) {
        check(handle != 0L) { "GNUnet node owner is closed" }
        val fields = IntArray(8)
        val peer = ByteArray(32)
        checkStatus("snapshot", NativeNode.snapshot(handle, fields, peer))
        val phase = when (fields[0]) {
            0 -> Phase.STARTING
            1 -> Phase.READY
            2 -> Phase.STOPPING
            3 -> Phase.STOPPED
            4 -> Phase.FAILED
            else -> error("Unknown GNUnet node phase ${fields[0]}")
        }
        val ready = if (fields[1] != 0) {
            Ready(
                peer,
                fields[2],
                fields[3],
                fields[4].takeIf { it != 0 },
                fields[5].takeIf { it != 0 },
                fields[6].takeIf { it != 0 },
                fields[7].takeIf { it != 0 },
            )
        } else {
            null
        }
        val diagnostic = if (phase == Phase.FAILED) NativeNode.error(handle).decodeToString() else null
        Snapshot(phase, ready, diagnostic, networkError)
    }

    /** Consume the native owner and join its worker. Concurrent closes wait for the same join. */
    override fun close() {
        requireWorkerThread()
        val (retired, observer, provider) = synchronized(lock) {
            val current = handle
            handle = 0L
            val observer = network
            network = null
            Triple(current, observer, vpn)
        }
        if (retired == 0L) {
            destroyed.await()
            closeFailure?.let { throw it }
            return
        }
        try {
            try {
                observer?.close()
            } finally {
                try {
                    // The VPN router remains available while Rust requests
                    // teardown of its original route installation.
                    NativeNode.destroy(retired)
                } finally {
                    provider?.close()
                }
            }
        } catch (error: Throwable) {
            closeFailure = error
            throw error
        } finally {
            synchronized(lock) { vpn = null }
            destroyed.countDown()
        }
    }

    companion object {
        /** Start with an owned default-network DNS observer; stop/close unregisters it. */
        fun start(context: Context, configFile: File? = null): GnunetNode =
            start(context, configFile, bootstrapDataDirectory = null)

        /** Start with default-network observation and an optional installed bootstrap data directory. */
        fun start(context: Context, configFile: File? = null, bootstrapDataDirectory: File?): GnunetNode {
            requireWorkerThread()
            val connectivity = context.getSystemService(ConnectivityManager::class.java)
                ?: throw IOException("Android connectivity service is unavailable")
            val options = AndroidNodeOptions.storageOptions(context).copy(
                configFile = configFile,
                bootstrapDataDirectory = bootstrapDataDirectory,
            )
            val owner = start(options)
            try {
                owner.followNetwork(connectivity)
                return owner
            } catch (error: Exception) {
                try {
                    owner.close()
                } catch (cleanup: Exception) {
                    error.addSuppressed(cleanup)
                }
                throw error
            }
        }

        /** Start the native owner on a background thread. Use [snapshot] to observe readiness. */
        fun start(options: Options): GnunetNode {
            return startNative(options, null, NetworkObserver.Source.ApplicationDefault)
        }

        internal fun startVpn(
            options: Options,
            launch: AndroidVpnProvider.Launch,
            networkSource: NetworkObserver.Source,
        ): GnunetNode = startNative(options, launch, networkSource)

        private fun startNative(
            options: Options,
            launch: AndroidVpnProvider.Launch?,
            networkSource: NetworkObserver.Source,
        ): GnunetNode {
            requireWorkerThread()
            val owner = GnunetNode(0L, networkSource)
            val handle = LongArray(if (launch == null) 1 else 2)
            checkStatus(
                "start",
                NativeNode.start(
                    options.stateDirectory.path.encodeToByteArray(),
                    options.ipcDirectory.path.encodeToByteArray(),
                    options.configFile?.path.orEmpty().encodeToByteArray(),
                    options.bootstrapDataDirectory?.path.orEmpty().encodeToByteArray(),
                    options.tcpBind.encodeToByteArray(),
                    options.udp4Bind.encodeToByteArray(),
                    options.udp6Bind.orEmpty().encodeToByteArray(),
                    options.dnsServers.joinToString(" ").encodeToByteArray(),
                    options.startupTimeoutMs,
                    options.drainTimeoutMs,
                    launch?.protection,
                    launch?.maximumPacket ?: 0,
                    handle,
                ),
            )
            check(handle[0] != 0L) { "GNUnet returned no node owner" }
            owner.handle = handle[0]
            if (launch != null) {
                try {
                    check(handle[1] != 0L) { "GNUnet returned no VPN route owner" }
                    owner.vpn = AndroidVpnProvider(handle[1], launch)
                } catch (error: Throwable) {
                    NativeNode.vpnDestroy(handle[1])
                    NativeNode.destroy(handle[0])
                    throw error
                }
            }
            return owner
        }

        private fun checkStatus(operation: String, status: Int) {
            if (status != 0) throw NativeFailure(operation, status)
        }

        private fun dnsBytes(servers: List<String>): ByteArray {
            require(servers.size <= 32) { "At most 32 DNS endpoints are permitted" }
            require(servers.all { value ->
                value.isNotEmpty() && value.length <= 256 &&
                    value.none { it.isWhitespace() || it == '\u0000' }
            }) { "Each DNS endpoint must be one numeric address or IP:port" }
            return servers.joinToString(" ").encodeToByteArray().also {
                require(it.size <= 65535) { "DNS endpoint list is too large" }
            }
        }
    }
}

internal fun requireWorkerThread() {
    check(Looper.myLooper() != Looper.getMainLooper()) {
        "GNUnet node setup and join require a background thread"
    }
}
