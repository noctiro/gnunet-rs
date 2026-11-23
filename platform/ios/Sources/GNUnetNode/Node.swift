import Dispatch
import GNUnetNodeNative
import Network

public struct GNUnetNodeOptions: Sendable {
    public var stateDirectory: String
    public var ipcDirectory: String
    public var configurationFile: String?
    /// Optional completed immutable generation installed by GNUnetBootstrap.
    public var bootstrapDataDirectory: String?
    public var tcpBind: String
    public var udp4Bind: String
    public var udp6Bind: String?
    public var dnsServers: [String]
    public var startupTimeoutMilliseconds: UInt32
    public var drainTimeoutMilliseconds: UInt32

    public init(
        stateDirectory: String,
        ipcDirectory: String,
        configurationFile: String? = nil,
        bootstrapDataDirectory: String? = nil,
        tcpBind: String = "127.0.0.1:0",
        udp4Bind: String = "127.0.0.1:0",
        udp6Bind: String? = nil,
        dnsServers: [String] = [],
        startupTimeoutMilliseconds: UInt32 = 15_000,
        drainTimeoutMilliseconds: UInt32 = 2_000
    ) {
        self.stateDirectory = stateDirectory
        self.ipcDirectory = ipcDirectory
        self.configurationFile = configurationFile
        self.bootstrapDataDirectory = bootstrapDataDirectory
        self.tcpBind = tcpBind
        self.udp4Bind = udp4Bind
        self.udp6Bind = udp6Bind
        self.dnsServers = dnsServers
        self.startupTimeoutMilliseconds = startupTimeoutMilliseconds
        self.drainTimeoutMilliseconds = drainTimeoutMilliseconds
    }
}

public enum GNUnetNodePhase: UInt32, Sendable {
    case starting = 0
    case ready = 1
    case stopping = 2
    case stopped = 3
    case failed = 4
}

public struct GNUnetNodeReady: Sendable {
    /// The verified peer identity at initial readiness.
    public let peer: [UInt8]
    public let tcpPort: UInt16
    public let udp4Port: UInt16
    public let udp6Port: UInt16?
    public let quicPort: UInt16?
    public let http3Port: UInt16?
    public let unixMtu: UInt16?
}

public struct GNUnetNodeStatus: Sendable {
    public let phase: GNUnetNodePhase
    public let ready: GNUnetNodeReady?
    public let failure: String?
}

public enum GNUnetNodeError: Error, Sendable {
    case start(Int32)
    case snapshot(Int32)
    case dnsServers(Int32)
    case notRunning
    case invalidPhase(UInt32)
}

/// Owns one app-scoped node. All calls into Rust use one private serial queue.
public final class GNUnetNode: Sendable {
    private let owner: Owner

    public init(options: GNUnetNodeOptions) {
        owner = Owner(options: options)
    }

    deinit {
        enqueueStop {}
    }

    /// Launches the native owner; read `snapshot()` to observe readiness.
    public func start() async throws {
        let result: Result<Void, GNUnetNodeError> = await withCheckedContinuation { continuation in
            enqueueStart { continuation.resume(returning: $0) }
        }
        try result.get()
    }

    public func snapshot() async throws -> GNUnetNodeStatus {
        let result: Result<GNUnetNodeStatus, GNUnetNodeError> = await withCheckedContinuation {
            continuation in
            owner.queue.async { [owner] in continuation.resume(returning: owner.snapshot()) }
        }
        return try result.get()
    }

    /// Enqueues an address rescan on the current node after a path change.
    public func notifyNetworkChange() {
        owner.signalNetworkChange()
    }

    /// Replaces the current network's DNS endpoints and requests an address rescan.
    /// Pass an empty array when the network has no permitted DNS upstreams.
    public func setDnsServers(_ servers: [String]) async throws {
        let snapshot = try NodeDnsSnapshot(servers)
        let result: Result<Void, GNUnetNodeError> = await withCheckedContinuation { continuation in
            owner.queue.async { [owner] in
                continuation.resume(returning: owner.setDnsServers(snapshot))
            }
        }
        try result.get()
    }

    /// Requests shutdown and waits for the native owner to retire off the main thread.
    public func stop() async {
        await withCheckedContinuation { continuation in
            enqueueStop { continuation.resume() }
        }
    }

    func enqueueStart(_ completion: @escaping @Sendable (Result<Void, GNUnetNodeError>) -> Void) {
        owner.queue.async { [owner] in completion(owner.start()) }
    }

    func enqueueStop(_ completion: @escaping @Sendable () -> Void) {
        owner.queue.async { [owner] in
            owner.stop()
            completion()
        }
    }

    // The native handle and current path monitor are accessed only on `queue`.
    private final class Owner: @unchecked Sendable {
        let queue = DispatchQueue(label: "org.gnunet.node.lifecycle", qos: .utility)
        let options: GNUnetNodeOptions
        private let networkChanges: any DispatchSourceUserDataOr
        private var handle: OpaquePointer?
        private var pathMonitor: NWPathMonitor?

        init(options: GNUnetNodeOptions) {
            self.options = options
            networkChanges = DispatchSource.makeUserDataOrSource(queue: queue)
            networkChanges.setEventHandler { [weak self] in self?.applyNetworkChange() }
            networkChanges.activate()
        }

        func start() -> Result<Void, GNUnetNodeError> {
            guard handle == nil else { return .success(()) }
            do {
                return try options.withNativeOptions(bindings: .configured) { input in
                    var started: OpaquePointer?
                    let result = gnunet_node_start(&input, &started)
                    guard result == 0, let started else { return .failure(.start(result)) }
                    handle = started
                    let monitor = NWPathMonitor()
                    monitor.pathUpdateHandler = { [weak self, weak monitor] _ in
                        guard let self, let monitor, self.pathMonitor === monitor else { return }
                        self.applyNetworkChange()
                    }
                    pathMonitor = monitor
                    monitor.start(queue: queue)
                    return .success(())
                }
            } catch { return .failure(error) }
        }

        func setDnsServers(_ snapshot: NodeDnsSnapshot) -> Result<Void, GNUnetNodeError> {
            guard let handle else { return .failure(.notRunning) }
            do { try snapshot.apply(to: handle); return .success(()) }
            catch { return .failure(error) }
        }

        func snapshot() -> Result<GNUnetNodeStatus, GNUnetNodeError> {
            guard let handle else { return .failure(.notRunning) }
            var native = GnNodeSnapshot()
            let result = gnunet_node_snapshot(handle, &native)
            guard result == 0 else { return .failure(.snapshot(result)) }
            guard let phase = GNUnetNodePhase(rawValue: native.phase) else {
                return .failure(.invalidPhase(native.phase))
            }
            let ready = native.has_ready == 0 ? nil : GNUnetNodeReady(
                peer: withUnsafeBytes(of: native.peer) { Array($0) },
                tcpPort: native.tcp_port,
                udp4Port: native.udp4_port,
                udp6Port: native.udp6_port == 0 ? nil : native.udp6_port,
                quicPort: native.quic_port == 0 ? nil : native.quic_port,
                http3Port: native.http3_port == 0 ? nil : native.http3_port,
                unixMtu: native.unix_mtu == 0 ? nil : native.unix_mtu
            )
            return .success(GNUnetNodeStatus(
                phase: phase,
                ready: ready,
                failure: phase == .failed ? failureMessage(handle) : nil
            ))
        }

        func signalNetworkChange() {
            networkChanges.or(data: 1)
        }

        private func applyNetworkChange() {
            if let handle {
                _ = gnunet_node_notify_network_change(handle)
            }
        }

        func stop() {
            guard let original = handle else { return }
            handle = nil
            pathMonitor?.cancel()
            pathMonitor = nil
            gnunet_node_destroy(original)
        }

        private func failureMessage(_ handle: OpaquePointer) -> String? {
            let count = gnunet_node_error(handle, nil, 0)
            guard count > 0 else { return nil }
            var bytes = [UInt8](repeating: 0, count: count)
            let reported = bytes.withUnsafeMutableBufferPointer {
                gnunet_node_error(handle, $0.baseAddress, $0.count)
            }
            return String(decoding: bytes.prefix(min(reported, count)), as: UTF8.self)
        }
    }
}
