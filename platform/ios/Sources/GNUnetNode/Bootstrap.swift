import Foundation

public enum GNUnetBootstrapError: Error {
    case resourcesNotPackaged
    case invalidIndex
    case invalidDestination
    case invalidBody(String)
    case cleanup(original: String, cleanup: String)
}

/// Installs explicitly packaged trusted HELLO resources before node startup.
public enum GNUnetBootstrap {
    private static let maximumFiles = 1024
    private static let maximumFileBytes = 65535
    private static let maximumTotalBytes = 4 * 1024 * 1024
    private static let indexRowBytes = 11

    /// Call on the application's file-I/O queue with an existing private parent.
    /// Returns a fresh completed generation containing hellos/. Retain it until
    /// every node using bootstrapDataDirectory has stopped. Later installations
    /// never modify or remove an earlier generation.
    public static func install(in parent: URL) throws -> URL {
        guard parent.isFileURL, parent.path.hasPrefix("/") else {
            throw GNUnetBootstrapError.invalidDestination
        }
        let values = try parent.resourceValues(forKeys: [.isDirectoryKey, .isSymbolicLinkKey])
        guard values.isDirectory == true, values.isSymbolicLink != true else {
            throw GNUnetBootstrapError.invalidDestination
        }
        guard let indexURL = Bundle.module.url(
            forResource: "hellos", withExtension: "list", subdirectory: "Resources/gnunet"
        ) else {
            throw GNUnetBootstrapError.resourcesNotPackaged
        }
        let index = try read(indexURL, maximumBytes: maximumFiles * indexRowBytes)
        let names = try filenames(index)
        let manager = FileManager.default
        let generation = parent.appendingPathComponent("gnunet-hellos-\(UUID().uuidString)", isDirectory: true)
        try manager.createDirectory(
            at: generation, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]
        )
        do {
            let hellos = generation.appendingPathComponent("hellos", isDirectory: true)
            try manager.createDirectory(
                at: hellos, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700]
            )
            var total = 0
            for name in names {
                let source = indexURL.deletingLastPathComponent()
                    .appendingPathComponent("hellos", isDirectory: true).appendingPathComponent(name)
                let body = try read(source, maximumBytes: maximumFileBytes)
                guard !body.isEmpty, total + body.count <= maximumTotalBytes else {
                    throw GNUnetBootstrapError.invalidBody(name)
                }
                total += body.count
                try body.write(to: hellos.appendingPathComponent(name), options: [.withoutOverwriting])
            }
            // No configuration or node can observe this generation before return.
            return generation
        } catch {
            let original = error
            do {
                try manager.removeItem(at: generation)
            } catch {
                throw GNUnetBootstrapError.cleanup(
                    original: String(describing: original), cleanup: String(describing: error)
                )
            }
            throw original
        }
    }

    private static func filenames(_ index: Data) throws -> [String] {
        guard !index.isEmpty, index.count <= maximumFiles * indexRowBytes,
              index.count.isMultiple(of: indexRowBytes)
        else { throw GNUnetBootstrapError.invalidIndex }
        let bytes = [UInt8](index)
        let suffix: [UInt8] = [46, 104, 101, 108, 108, 111, 10]
        var names: [String] = []
        for start in stride(from: 0, to: bytes.count, by: indexRowBytes) {
            guard bytes[start..<(start + 4)].allSatisfy({ (48...57).contains($0) }),
                  bytes[(start + 4)..<(start + indexRowBytes)].elementsEqual(suffix),
                  let name = String(bytes: bytes[start..<(start + 10)], encoding: .ascii)
            else { throw GNUnetBootstrapError.invalidIndex }
            let ordinal = bytes[start..<(start + 4)].reduce(0) { $0 * 10 + Int($1 - 48) }
            guard ordinal == start / indexRowBytes else { throw GNUnetBootstrapError.invalidIndex }
            names.append(name)
        }
        return names
    }

    private static func read(_ url: URL, maximumBytes: Int) throws -> Data {
        // Application bundle resources are caller-selected signed assets; the
        // application excludes replacement while this bounded read is active.
        let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
        guard values.isRegularFile == true, values.isSymbolicLink != true else {
            throw GNUnetBootstrapError.invalidBody(url.lastPathComponent)
        }
        let file = try FileHandle(forReadingFrom: url)
        let result: Result<Data, Error>
        do {
            var data = Data()
            while data.count <= maximumBytes {
                guard let part = try file.read(upToCount: maximumBytes + 1 - data.count), !part.isEmpty else { break }
                data.append(part)
            }
            guard data.count <= maximumBytes else {
                throw GNUnetBootstrapError.invalidBody(url.lastPathComponent)
            }
            result = .success(data)
        } catch {
            result = .failure(error)
        }
        do {
            try file.close()
        } catch {
            if case let .failure(original) = result {
                throw GNUnetBootstrapError.cleanup(
                    original: String(describing: original), cleanup: String(describing: error)
                )
            }
            throw error
        }
        return try result.get()
    }
}
