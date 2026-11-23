package org.gnunet.sdk

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Runs the GNUnet VPN in an application-declared Android service.
 * The app supplies its consent UI and foreground notification.
 */
abstract class GnunetVpnService : VpnService() {
    /** Android transition which ended this service's original grant. */
    enum class Retirement { PERMISSION_REVOKED, SERVICE_DESTROYED }

    /** Android route policy for the original protected Internet sockets. */
    sealed interface Upstream {
        /** Use Android's system routing for protected sockets. */
        data object SystemDefault : Upstream

        /** Use only this explicitly selected physical Internet network. */
        class Pinned(val network: Network) : Upstream
    }

    private class Grant(val serviceIdentity: Any) {
        val active = AtomicBoolean(true)
        var node: GnunetNode? = null
    }

    private val identity = Any()
    private var retired = false

    companion object {
        private val grantLock = Any()
        private var original: Grant? = null

        /** Obtain the Android consent intent, or null when this app is prepared. */
        @JvmStatic
        fun prepareConsent(context: Context): Intent? = VpnService.prepare(context)
    }

    /**
     * Start one GNUnet node with this service's original consent and protected
     * sockets. Call after consent on a background thread and retain the node to
     * observe readiness and close it. Android route commands use GNUnet's
     * configured prefixes and MTU.
     */
    protected fun startNode(
        options: GnunetNode.Options,
        maximumPacket: Int = 1500,
        upstream: Upstream = Upstream.SystemDefault,
    ): GnunetNode {
        requireWorkerThread()
        require(options.dnsServers.isEmpty()) { "Android network policy supplies DNS for the VPN node" }
        val connectivity = getSystemService(ConnectivityManager::class.java)
            ?: throw IOException("Android connectivity service is unavailable")
        val grant = reserveGrant()
        val node = try {
            if (prepareConsent(this) != null) throw SecurityException("Android VPN consent is required")
            val pinned = when (upstream) {
                Upstream.SystemDefault -> null
                is Upstream.Pinned -> PhysicalNetwork(upstream.network, connectivity)
            }
            val source = if (pinned == null) {
                NetworkObserver.Source.PhysicalHints
            } else {
                NetworkObserver.Source.Pinned(pinned)
            }
            val launch = AndroidVpnProvider.Launch(
                maximumPacket, NativeSocketProtection { fd -> protect(grant, pinned, fd) }, grant.active,
                { settings -> installDescriptor(grant, pinned, settings) },
                { routesAbsent -> release(grant, routesAbsent) },
            )
            GnunetNode.startVpn(options, launch, source)
        } catch (error: Throwable) {
            release(grant, routesAbsent = true)
            throw error
        }
        try {
            synchronized(grantLock) {
                requireActiveGrant(grant)
                grant.node = node
            }
            node.followNetwork(connectivity)
            synchronized(grantLock) {
                requireActiveGrant(grant)
                node.startVpnRoutes()
            }
            return node
        } catch (error: Throwable) {
            try {
                node.close()
            } catch (cleanup: Throwable) {
                if (cleanup !== error) error.addSuppressed(cleanup)
            }
            throw error
        }
    }

    private fun reserveGrant(): Grant = synchronized(grantLock) {
        check(!retired) { "This Android VPN service has retired" }
        check(original == null) { "The process already owns an Android VPN grant" }
        Grant(identity).also { original = it }
    }

    private fun requireActiveGrant(grant: Grant) {
        if (retired || original !== grant || !grant.active.get()) {
            throw SecurityException("Android VPN permission was withdrawn during node startup")
        }
    }

    private fun installDescriptor(
        grant: Grant,
        pinned: PhysicalNetwork?,
        settings: AndroidVpnSettings,
    ): ParcelFileDescriptor {
        if (prepareConsent(this) != null) throw SecurityException("Android VPN consent is required")
        val builder = Builder().setBlocking(false).setMtu(settings.mtu)
        if (pinned != null) {
            check(pinned.isLive()) { "The selected physical network has retired" }
            builder.setUnderlyingNetworks(arrayOf(pinned.network))
        }
        for (address in settings.addresses) builder.addAddress(address.address, address.prefixLength)
        for (route in settings.routes) builder.addRoute(route.network, route.prefixLength)
        check(grant.active.get()) { "Android VPN permission was withdrawn before establishment" }
        return builder.establish()
            ?: throw SecurityException("Android VPN permission was withdrawn during establishment")
    }

    private fun protect(grant: Grant, pinned: PhysicalNetwork?, fd: Int): Boolean =
        fd >= 0 && grant.active.get() && (pinned == null || pinned.bind(fd)) &&
            protect(fd) && grant.active.get() && (pinned == null || pinned.isLive())

    /**
     * Observe retirement after the SDK has fenced the original VPN.
     * Android may call this from a binder thread. App-owned work can finish
     * asynchronously while the SDK retires its own node and descriptor.
     */
    protected open fun onVpnRetiring(reason: Retirement) {}

    final override fun onRevoke() {
        try {
            if (retire()) onVpnRetiring(Retirement.PERMISSION_REVOKED)
        } finally {
            super.onRevoke()
        }
    }

    final override fun onDestroy() {
        try {
            if (retire()) onVpnRetiring(Retirement.SERVICE_DESTROYED)
        } finally {
            super.onDestroy()
        }
    }

    private fun release(grant: Grant, routesAbsent: Boolean) {
        grant.active.set(false)
        synchronized(grantLock) {
            if (original !== grant) return
            grant.node = null
            if (routesAbsent) original = null
        }
    }

    private fun retire(): Boolean {
        val node = synchronized(grantLock) {
            if (retired) return false
            retired = true
            val grant = original?.takeIf { it.serviceIdentity === identity }
            grant?.active?.set(false)
            grant?.node
        }
        if (node != null) {
            try {
                node.revokeVpn()
            } catch (error: IOException) {
                Log.e("GnunetVpnService", "Stopping the original GNUnet VPN node failed", error)
            }
            Thread({
                try {
                    node.close()
                } catch (error: Exception) {
                    Log.e("GnunetVpnService", "Joining the original GNUnet VPN node failed", error)
                }
            }, "gnunet-vpn-retire").start()
        }
        return true
    }
}
