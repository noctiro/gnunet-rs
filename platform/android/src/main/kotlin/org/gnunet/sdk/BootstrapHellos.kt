package org.gnunet.sdk

import android.content.res.AssetManager
import android.os.Process
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest
import java.util.UUID

/** Install a bounded immutable generation of the signed application's assets. */
internal object BootstrapHellos {
    private const val SUBDIRECTORY = "hellos"
    private const val ASSETS = "gnunet"
    private const val RECORD_SIZE = 11
    private const val MAX_FILES = 1024
    private const val MAX_FILE_BYTES = 65535
    private const val MAX_TOTAL_BYTES = 4 * 1024 * 1024

    fun install(assets: AssetManager, appRoot: File): File {
        val index = ByteArrayOutputStream()
        assets.open("$ASSETS/hellos.list", AssetManager.ACCESS_STREAMING).use { input ->
            copyBounded(input, MAX_FILES * RECORD_SIZE) { bytes, count -> index.write(bytes, 0, count) }
        }
        val listing = index.toByteArray()
        val count = listing.size / RECORD_SIZE
        if (count == 0 || listing.size % RECORD_SIZE != 0) {
            throw IOException("Invalid packaged GNUnet HELLO list")
        }
        val names = List(count) { number -> number.toString().padStart(4, '0') + ".hello" }
        if (listing.decodeToString() != names.joinToString("\n", postfix = "\n")) {
            throw IOException("The packaged GNUnet HELLO list must contain consecutive names")
        }

        val root = AndroidNodeOptions.privateDirectory(appRoot, "gnunet-bootstrap")
        val stage = File(root, ".stage-${UUID.randomUUID()}")
        Os.mkdir(stage.path, OsConstants.S_IRWXU)
        val stagedHellos = File(stage, SUBDIRECTORY)
        var published = false
        var failure: Throwable? = null
        try {
            Os.mkdir(stagedHellos.path, OsConstants.S_IRWXU)
            val version = sha256().apply { update(listing) }
            var remaining = MAX_TOTAL_BYTES
            val receipts = names.map { name ->
                val receipt = copyAsset(assets, name, stagedHellos, minOf(remaining, MAX_FILE_BYTES))
                remaining -= receipt.size
                version.update(receipt.digest)
                receipt
            }
            syncDirectory(stagedHellos)
            syncDirectory(stage)
            val key = version.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }
            val generation = File(root, key)
            try {
                Os.rename(stage.path, generation.path)
                published = true
            } catch (error: ErrnoException) {
                if (error.errno != OsConstants.EEXIST && error.errno != OsConstants.ENOTEMPTY) throw error
                verifyExisting(generation, names, receipts)
            }
            syncDirectory(root)
            return generation
        } catch (error: Throwable) {
            failure = error
            throw error
        } finally {
            if (!published) {
                try {
                    for (name in names) remove(File(stagedHellos, name))
                    remove(stagedHellos)
                    remove(stage)
                } catch (cleanup: ErrnoException) {
                    if (failure == null) throw cleanup
                    failure.addSuppressed(cleanup)
                }
            }
        }
    }

    private data class Receipt(val size: Int, val digest: ByteArray)

    private fun copyAsset(assets: AssetManager, name: String, parent: File, limit: Int): Receipt {
        val digest = sha256()
        val flags = OsConstants.O_WRONLY or OsConstants.O_CREAT or OsConstants.O_EXCL
        val mode = OsConstants.S_IRUSR or OsConstants.S_IWUSR
        val size = withDescriptor(File(parent, name), flags, mode) { fd ->
            // Android leaves a descriptor passed to FileOutputStream owned by the caller.
            FileOutputStream(fd).use { output ->
                assets.open("$ASSETS/$SUBDIRECTORY/$name", AssetManager.ACCESS_STREAMING).use { input ->
                    copyBounded(input, limit) { bytes, count ->
                        output.write(bytes, 0, count)
                        digest.update(bytes, 0, count)
                    }.also { Os.fsync(fd) }
                }
            }
        }
        if (size == 0) throw IOException("Empty packaged GNUnet HELLO asset")
        return Receipt(size, digest.digest())
    }

    private fun verifyExisting(generation: File, names: List<String>, receipts: List<Receipt>) {
        AndroidNodeOptions.requirePrivateDirectory(generation)
        val hellos = AndroidNodeOptions.requirePrivateDirectory(File(generation, SUBDIRECTORY))
        if (hellos.list()?.toSet() != names.toSet()) throw IOException("Incomplete GNUnet HELLO generation")
        for ((index, name) in names.withIndex()) {
            val receipt = receipts[index]
            val digest = sha256()
            withDescriptor(File(hellos, name), OsConstants.O_RDONLY or OsConstants.O_NONBLOCK) { fd ->
                val stat = Os.fstat(fd)
                val shared = OsConstants.S_IRWXG or OsConstants.S_IRWXO
                if (!OsConstants.S_ISREG(stat.st_mode) || stat.st_uid != Process.myUid() ||
                    (stat.st_mode and shared) != 0 || stat.st_nlink != 1L || stat.st_size != receipt.size.toLong()
                ) {
                    throw IOException("Invalid cached GNUnet HELLO asset")
                }
                val size = FileInputStream(fd).use { input ->
                    copyBounded(input, receipt.size) { bytes, count -> digest.update(bytes, 0, count) }
                }
                if (size != receipt.size || !MessageDigest.isEqual(digest.digest(), receipt.digest)) {
                    throw IOException("Cached GNUnet HELLO asset differs from the package")
                }
            }
        }
    }

    private fun sha256(): MessageDigest = MessageDigest.getInstance("SHA-256")

    private fun copyBounded(input: InputStream, limit: Int, consume: (ByteArray, Int) -> Unit): Int {
        val buffer = ByteArray(minOf(8192, limit + 1))
        var total = 0
        while (true) {
            val count = input.read(buffer, 0, minOf(buffer.size, limit - total + 1))
            if (count < 0) return total
            if (count == 0 || count > limit - total) throw IOException("Packaged GNUnet HELLO bounds exceeded")
            consume(buffer, count)
            total += count
        }
    }

    private fun syncDirectory(directory: File) {
        withDescriptor(directory, OsConstants.O_RDONLY or OsConstants.O_NONBLOCK) { fd ->
            if (!OsConstants.S_ISDIR(Os.fstat(fd).st_mode)) {
                throw IOException("GNUnet HELLO generation path is not a directory")
            }
            Os.fsync(fd)
        }
    }

    private fun remove(file: File) {
        try {
            Os.remove(file.path)
        } catch (error: ErrnoException) {
            if (error.errno != OsConstants.ENOENT) throw error
        }
    }

    private inline fun <T> withDescriptor(
        file: File,
        flags: Int,
        mode: Int = 0,
        action: (FileDescriptor) -> T,
    ): T {
        val fd = Os.open(file.path, flags or OsConstants.O_CLOEXEC or OsConstants.O_NOFOLLOW, mode)
        var failure: Throwable? = null
        try {
            return action(fd)
        } catch (error: Throwable) {
            failure = error
            throw error
        } finally {
            try {
                Os.close(fd)
            } catch (cleanup: ErrnoException) {
                if (failure == null) throw cleanup
                failure.addSuppressed(cleanup)
            }
        }
    }
}
