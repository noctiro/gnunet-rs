package org.gnunet.sdk

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.os.Build
import android.os.Process
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import java.io.File
import java.io.IOException
import java.net.Inet6Address
import java.net.NetworkInterface
import java.net.SocketException

/** Android application storage and the default network's DNS addresses at startup. */
object AndroidNodeOptions {
    /** Prepare private directories and take one network snapshot on a background thread. */
    fun fromContext(context: Context): GnunetNode.Options =
        storageOptions(context).copy(dnsServers = defaultLinkDns(context))

    /** Prepare private VPN storage without inheriting the application's default DNS. */
    fun forVpn(context: Context): GnunetNode.Options = storageOptions(context)

    /** Install the app's packaged bootstrap HELLOs on a background thread. */
    fun installIncludedHellos(context: Context): File {
        requireWorkerThread()
        return BootstrapHellos.install(context.assets, context.noBackupFilesDir.canonicalFile)
    }

    internal fun storageOptions(context: Context): GnunetNode.Options {
        requireWorkerThread()
        val root = context.noBackupFilesDir.canonicalFile
        return GnunetNode.Options(
            stateDirectory = privateDirectory(root, "gnunet-state"),
            ipcDirectory = privateDirectory(root, "gnunet-ipc"),
        )
    }

    internal fun privateDirectory(parent: File, name: String): File {
        val directory = File(parent, name)
        try {
            Os.mkdir(directory.path, OsConstants.S_IRWXU)
        } catch (error: ErrnoException) {
            if (error.errno != OsConstants.EEXIST) throw IOException("Cannot create $directory", error)
        }
        return requirePrivateDirectory(directory)
    }

    internal fun requirePrivateDirectory(directory: File): File {
        val stat = try {
            Os.lstat(directory.path)
        } catch (error: ErrnoException) {
            throw IOException("Cannot inspect $directory", error)
        }
        val shared = OsConstants.S_IRWXG or OsConstants.S_IRWXO
        if (!OsConstants.S_ISDIR(stat.st_mode) || stat.st_uid != Process.myUid() ||
            (stat.st_mode and shared) != 0
        ) {
            throw IOException("GNUnet directory must be private to this application: $directory")
        }
        return directory
    }

    private fun defaultLinkDns(context: Context): List<String> {
        val connectivity = context.getSystemService(ConnectivityManager::class.java) ?: return emptyList()
        val network = connectivity.activeNetwork ?: return emptyList()
        val link = connectivity.getLinkProperties(network) ?: return emptyList()
        if (connectivity.activeNetwork != network) return emptyList()
        return dnsServers(link)
    }

    internal fun dnsServers(link: LinkProperties): List<String> {
        if (Build.VERSION.SDK_INT >= 28 &&
            (link.isPrivateDnsActive || link.privateDnsServerName != null)
        ) return emptyList()

        val interfaceIndex by lazy {
            val name = link.interfaceName ?: return@lazy 0
            try {
                NetworkInterface.getByName(name)?.index?.takeIf { it > 0 } ?: 0
            } catch (_: SocketException) {
                0
            }
        }
        return link.dnsServers.take(32).mapNotNull { address ->
            val host = address.hostAddress ?: return@mapNotNull null
            if (address is Inet6Address) {
                val scope = when {
                    address.scopeId > 0 -> address.scopeId
                    address.isLinkLocalAddress -> interfaceIndex
                    else -> 0
                }
                if (address.isLinkLocalAddress && scope == 0) return@mapNotNull null
                val suffix = if (scope == 0) "" else "%$scope"
                "[${host.substringBefore('%')}$suffix]:53"
            } else {
                "$host:53"
            }
        }
    }
}
