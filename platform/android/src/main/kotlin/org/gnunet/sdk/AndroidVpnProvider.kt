package org.gnunet.sdk

import android.os.ParcelFileDescriptor
import java.net.Inet6Address
import java.net.InetAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.atomic.AtomicBoolean

/** Owns one descriptor-mode command source, with a single route reader. */
internal class AndroidVpnProvider(
    private val handle: Long,
    private val launch: Launch,
) {
    class Launch(
        val maximumPacket: Int,
        val protection: NativeSocketProtection,
        val active: AtomicBoolean,
        val establish: (AndroidVpnSettings) -> ParcelFileDescriptor,
        val released: (Boolean) -> Unit,
    ) {
        init {
            require(maximumPacket in 68..65535) { "Invalid Android VPN packet capacity" }
        }
    }

    private data class Token(val epoch: Long, val revision: Long)

    private val control = Any()
    private var liveHandle = handle
    private val finished = CountDownLatch(1)
    private val worker = Thread(::run, "gnunet-vpn-routes")
    private var started = false
    private var descriptor: ParcelFileDescriptor? = null
    private var absent = true
    private var failure: Throwable? = null

    /** The node starts and retires this worker under its lifecycle ownership. */
    fun start() {
        worker.start()
        started = true
    }

    /** Fence original packet I/O while the controller is still live. */
    fun fence() {
        synchronized(control) {
            if (liveHandle != 0L) checkStatus("fence VPN packets", NativeNode.vpnFence(liveHandle))
        }
    }

    /** Call after requesting native shutdown. Keep JNI ownership until the reader exits. */
    fun close() {
        var interrupted = false
        while (started) {
            try {
                finished.await()
                break
            } catch (_: InterruptedException) {
                interrupted = true
            }
        }
        try {
            val retired = synchronized(control) { liveHandle.also { liveHandle = 0L } }
            if (retired != 0L) {
                NativeNode.vpnDestroy(retired)
                launch.released(absent)
            }
        } finally {
            if (interrupted) Thread.currentThread().interrupt()
        }
        failure?.let { throw it }
    }

    private fun run() {
        var closed = false
        try {
            val id = LongArray(2)
            val fields = IntArray(6)
            val addresses = ByteArray(64)
            while (true) {
                val status = NativeNode.vpnNext(handle, id, fields, addresses)
                if (status == WAIT) continue
                checkStatus("wait for VPN routes", status)
                if (fields[0] == CLOSED) {
                    closed = true
                    break
                }
                val token = Token(id[0], id[1])
                when (fields[0]) {
                    INSTALL -> install(token, fields, addresses)
                    REMOVE -> remove(token)
                    else -> error("Unexpected GNUnet descriptor-mode operation ${fields[0]}")
                }
            }
        } catch (error: Throwable) {
            record(error)
        } finally {
            try {
                closeOriginal()
                if (!closed || !absent) checkStatus("revoke VPN", NativeNode.vpnRevoke(handle, absent))
            } catch (error: Throwable) {
                record(error)
            } finally {
                finished.countDown()
            }
        }
    }

    private fun install(token: Token, fields: IntArray, addresses: ByteArray) {
        try {
            check(absent && descriptor == null) { "The original Android VPN routes must retire before installation" }
            val settings = settings(fields, addresses)
            val original = launch.establish(settings)
            descriptor = original
            absent = false
            check(launch.active.get()) { "Android VPN consent was withdrawn before descriptor handoff" }
            checkStatus("install VPN descriptor", NativeNode.vpnInstalled(handle, token.epoch, token.revision, original.fd))
        } catch (error: Exception) {
            record(error)
            closeOriginal()
            complete(token, if (absent) FAILED_ABSENT else FAILED, error)
        }
    }

    private fun remove(token: Token) {
        val error = closeOriginal()
        complete(token, if (absent) REMOVED else FAILED, error)
    }

    /** A failed physical close never becomes an affirmative later receipt. */
    private fun closeOriginal(): Exception? {
        val original = descriptor ?: return null
        descriptor = null
        return try {
            original.close()
            absent = true
            null
        } catch (error: Exception) {
            record(error)
            error
        }
    }

    private fun complete(token: Token, outcome: Int, failure: Exception?) {
        val diagnostic = failure?.message?.take(1024)?.replace('\u0000', ' ')?.encodeToByteArray()
        checkStatus("complete VPN routes",
            NativeNode.vpnComplete(handle, token.epoch, token.revision, outcome, diagnostic))
    }

    private fun record(error: Throwable) {
        val original = failure
        if (original == null) failure = error else if (original !== error) original.addSuppressed(error)
    }

    private fun settings(fields: IntArray, packed: ByteArray): AndroidVpnSettings {
        val addresses = ArrayList<AndroidVpnAddress>(2)
        val routes = ArrayList<AndroidVpnRoute>(2)
        for (index in 0..1) {
            val family = fields[2 + 2 * index]
            if (family == 0) continue
            check(family == if (index == 0) 4 else 6) { "Invalid GNUnet VPN prefix family" }
            val bits = fields[3 + 2 * index]
            val offset = 32 * index
            routes.add(AndroidVpnRoute(address(family, packed, offset), bits))
            addresses.add(AndroidVpnAddress(address(family, packed, offset + 16), bits))
        }
        return AndroidVpnSettings(addresses, routes, fields[1])
    }

    private fun address(family: Int, bytes: ByteArray, offset: Int): InetAddress =
        if (family == 4) InetAddress.getByAddress(bytes.copyOfRange(offset, offset + 4))
        else Inet6Address.getByAddress(null, bytes.copyOfRange(offset, offset + 16), 0)

    private fun checkStatus(operation: String, status: Int) {
        if (status != 0) throw GnunetNode.NativeFailure(operation, status)
    }

    private companion object {
        const val WAIT = 3
        const val INSTALL = 1
        const val REMOVE = 2
        const val CLOSED = 4
        const val REMOVED = 2
        const val FAILED = 3
        const val FAILED_ABSENT = 4
    }
}
