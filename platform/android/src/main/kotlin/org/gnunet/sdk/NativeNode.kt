package org.gnunet.sdk

internal fun interface NativeSocketProtection {
    fun protect(socketFd: Int): Boolean
}

internal object NativeNode {
    init {
        System.loadLibrary("gnunet_node_android")
    }

    external fun start(
        stateDir: ByteArray,
        ipcDir: ByteArray,
        configFile: ByteArray,
        bootstrapDataDirectory: ByteArray,
        tcpBind: ByteArray,
        udp4Bind: ByteArray,
        udp6Bind: ByteArray,
        dnsServers: ByteArray,
        startupTimeoutMs: Int,
        drainTimeoutMs: Int,
        protector: NativeSocketProtection?,
        maximumPacket: Int,
        handleOut: LongArray,
    ): Int

    external fun stop(handle: Long): Int
    external fun notifyNetworkChange(handle: Long): Int
    external fun setDnsServers(handle: Long, servers: ByteArray): Int
    external fun snapshot(handle: Long, values: IntArray, peer: ByteArray): Int
    external fun error(handle: Long): ByteArray
    external fun destroy(handle: Long)
    external fun vpnNext(handle: Long, token: LongArray, fields: IntArray, addresses: ByteArray): Int
    external fun vpnInstalled(handle: Long, epoch: Long, revision: Long, fd: Int): Int
    external fun vpnComplete(handle: Long, epoch: Long, revision: Long, outcome: Int, diagnostic: ByteArray?): Int
    external fun vpnFence(handle: Long): Int
    external fun vpnRevoke(handle: Long, routesAbsent: Boolean): Int
    external fun vpnDestroy(handle: Long)
}
