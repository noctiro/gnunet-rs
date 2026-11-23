import Foundation
import GNUnetNode
import Network
import NetworkExtension

final class PacketTunnelProvider: NEPacketTunnelProvider, @unchecked Sendable {
    private let session = TunnelSession()

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        do {
            let ticket = try session.reserve()
            defer { session.release(ticket) }
            let deployment = try TunnelDeployment(protocolConfiguration)
            let node = try GNUnetPacketTunnelNode(
                provider: self, options: deployment.options, hostPolicy: deployment.policy
            )
            let starting = try session.start(node, ticket: ticket)
            let completion = NativeCompletion(finish: completionHandler)
            Task { [completion, starting] in
                do {
                    try await starting.value
                    completion.finish(nil)
                } catch {
                    completion.finish(error)
                }
            }
        } catch {
            completionHandler(error)
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        let retiring = session.retire()
        let completion = NativeCompletion<Void>(finish: { _ in completionHandler() })
        Task { [self, completion, retiring] in
            do { try await retiring?.value }
            catch { cancelTunnelWithError(error) }
            completion.finish(())
        }
    }
}

/// The original NetworkExtension callback is invoked once by its submitted task.
private struct NativeCompletion<Value>: @unchecked Sendable {
    let finish: (Value) -> Void
}

private enum TunnelDeploymentError: Error {
    case invalidProfile
    case pathUnavailable
    case occupied
}

/// Reserves a start synchronously before any container or native work. A stop
/// can revoke that reservation before the provider submits the original node.
private final class TunnelSession: @unchecked Sendable {
    private enum State {
        case idle
        case reserved(UUID)
        case active(GNUnetPacketTunnelNode)
        case retiring(GNUnetPacketTunnelNode, Task<Void, Error>)
    }

    private let lock = NSLock()
    private var state = State.idle

    func reserve() throws -> UUID {
        try lock.withLock {
            guard case .idle = state else { throw TunnelDeploymentError.occupied }
            let ticket = UUID()
            state = .reserved(ticket)
            return ticket
        }
    }

    func release(_ ticket: UUID) {
        lock.withLock {
            if case let .reserved(current) = state, current == ticket { state = .idle }
        }
    }

    func start(_ selected: GNUnetPacketTunnelNode, ticket: UUID) throws -> Task<Void, Error> {
        try lock.withLock {
            guard case let .reserved(current) = state, current == ticket else { throw CancellationError() }
            state = .active(selected)
            return Task { try await activate(selected) }
        }
    }

    private func activate(_ original: GNUnetPacketTunnelNode) async throws {
        do {
            try await original.start()
            let isActive = lock.withLock {
                guard case let .active(current) = state else { return false }
                return current === original
            }
            guard isActive else {
                throw CancellationError()
            }
        } catch {
            let failure = error
            do { try await retire(expected: original)?.value }
            catch {
                throw GNUnetPacketTunnelNodeError.cleanup(
                    original: String(describing: failure), removal: String(describing: error)
                )
            }
            throw failure
        }
    }

    func retire(expected: GNUnetPacketTunnelNode? = nil) -> Task<Void, Error>? {
        lock.withLock {
            switch state {
            case .idle:
                return nil
            case .reserved:
                if expected == nil { state = .idle }
                return nil
            case let .active(original):
                guard expected == nil || original === expected else { return nil }
                let retirement = Task {
                    try await original.stopAndWaitForRetirement()
                    lock.withLock { state = .idle }
                }
                state = .retiring(original, retirement)
                return retirement
            case let .retiring(original, retirement):
                return expected == nil || original === expected ? retirement : nil
            }
        }
    }
}

private struct TunnelDeployment {
    let options: GNUnetNodeOptions
    let policy: GNUnetPacketTunnelHostPolicy

    init(_ configuration: NEVPNProtocol) throws {
        guard let tunnel = configuration as? NETunnelProviderProtocol,
              let inputs = tunnel.providerConfiguration,
              let remoteAddress = tunnel.serverAddress,
              !remoteAddress.isEmpty, remoteAddress.utf8.count <= 255, !remoteAddress.utf8.contains(0)
        else { throw TunnelDeploymentError.invalidProfile }
        let interface: NWInterface.InterfaceType
        switch inputs["upstreamInterface"] as? String {
        case "wifi": interface = .wifi
        case "wiredEthernet": interface = .wiredEthernet
        case "cellular": interface = .cellular
        default: throw TunnelDeploymentError.invalidProfile
        }
        let upstreamDns = try Self.strings(inputs["upstreamDnsServers"], limit: 32)
        let tunnelDns = try Self.strings(inputs["tunnelDnsServers"], limit: 32)
        let ipv4 = try Self.prefixes(inputs["ipv4ExcludedRoutes"], family: .ipv4)
        let ipv6 = try Self.prefixes(inputs["ipv6ExcludedRoutes"], family: .ipv6)
        let configurationFile = try Self.absolutePath(inputs["configurationFile"])
        let bootstrap = try Self.absolutePath(inputs["bootstrapDataDirectory"])

        let files = FileManager.default
        let support = try files.url(
            for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true
        )
        let state = support.appendingPathComponent("GNUnet", isDirectory: true)
        let ipc = files.temporaryDirectory.appendingPathComponent("g", isDirectory: true)
        for directory in [state, ipc] {
            try files.createDirectory(
                at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]
            )
        }
        options = GNUnetNodeOptions(
            stateDirectory: state.path,
            ipcDirectory: ipc.path,
            configurationFile: configurationFile,
            bootstrapDataDirectory: bootstrap
        )
        policy = GNUnetPacketTunnelHostPolicy(
            remoteAddress: remoteAddress,
            dnsServers: tunnelDns,
            ipv4ExcludedRoutes: ipv4,
            ipv6ExcludedRoutes: ipv6
        ) { path in
            try Task.checkCancellation()
            guard path.status == .satisfied, path.usesInterfaceType(interface) else {
                throw TunnelDeploymentError.pathUnavailable
            }
            return upstreamDns
        }
    }

    private static func absolutePath(_ value: Any?) throws -> String? {
        guard let value else { return nil }
        guard let path = value as? String, path.hasPrefix("/"),
              path.utf8.count <= 4096, !path.utf8.contains(0)
        else { throw TunnelDeploymentError.invalidProfile }
        return path
    }

    private static func strings(_ value: Any?, limit: Int) throws -> [String] {
        guard let value else { return [] }
        guard let entries = value as? [String], entries.count <= limit,
              entries.allSatisfy({ $0.utf8.count <= 128 && !$0.utf8.contains(0) })
        else { throw TunnelDeploymentError.invalidProfile }
        return entries
    }

    private static func prefixes(_ value: Any?, family: GNUnetPacketVersion) throws -> [GNUnetIPPrefix] {
        try strings(value, limit: 128).map { text in
            let fields = text.split(separator: "/", omittingEmptySubsequences: false)
            guard fields.count == 2, let length = UInt8(fields[1])
            else { throw TunnelDeploymentError.invalidProfile }
            let address = String(fields[0])
            let valid = switch family {
            case .ipv4: length <= 32 && IPv4Address(address) != nil
            case .ipv6: length <= 128 && IPv6Address(address) != nil
            }
            guard valid else { throw TunnelDeploymentError.invalidProfile }
            return GNUnetIPPrefix(address: address, length: length)
        }
    }
}
