import Darwin
import Foundation
import NetworkExtension

public struct GNUnetIPPrefix: Sendable {
    public var address: String
    public var length: UInt8

    public init(address: String, length: UInt8) {
        self.address = address
        self.length = length
    }
}

/// Explicit settings for one original packet-tunnel session.
public struct GNUnetPacketTunnelPlan: Sendable {
    public var remoteAddress: String
    public var ipv4Addresses: [GNUnetIPPrefix]
    public var ipv4Routes: [GNUnetIPPrefix]
    public var ipv4ExcludedRoutes: [GNUnetIPPrefix]
    public var ipv6Addresses: [GNUnetIPPrefix]
    public var ipv6Routes: [GNUnetIPPrefix]
    public var ipv6ExcludedRoutes: [GNUnetIPPrefix]
    public var dnsServers: [String]
    public var mtu: UInt32

    public init(
        remoteAddress: String,
        ipv4Addresses: [GNUnetIPPrefix] = [], ipv4Routes: [GNUnetIPPrefix] = [],
        ipv4ExcludedRoutes: [GNUnetIPPrefix] = [],
        ipv6Addresses: [GNUnetIPPrefix] = [], ipv6Routes: [GNUnetIPPrefix] = [],
        ipv6ExcludedRoutes: [GNUnetIPPrefix] = [],
        dnsServers: [String] = [], mtu: UInt32
    ) {
        self.remoteAddress = remoteAddress
        self.ipv4Addresses = ipv4Addresses
        self.ipv4Routes = ipv4Routes
        self.ipv4ExcludedRoutes = ipv4ExcludedRoutes
        self.ipv6Addresses = ipv6Addresses
        self.ipv6Routes = ipv6Routes
        self.ipv6ExcludedRoutes = ipv6ExcludedRoutes
        self.dnsServers = dnsServers
        self.mtu = mtu
    }
}

public enum GNUnetPacketVersion: UInt8, Sendable {
    case ipv4 = 4
    case ipv6 = 6
}

/// Raw IP, without an utun header. The version is separate platform metadata.
public struct GNUnetTunnelPacket: Sendable {
    public let bytes: Data
    public let version: GNUnetPacketVersion

    public init(bytes: Data, version: GNUnetPacketVersion) {
        self.bytes = bytes
        self.version = version
    }
}

public enum GNUnetPacketWriteOutcome: Sendable {
    /// The original public packet-flow API returned true; no peer delivery is inferred.
    case accepted
    /// False has no documented zero-effect guarantee. Never replay automatically.
    case unknown
}

public enum GNUnetTunnelSettingsOutcome: Sendable {
    case applied
    /// Original settings applied after close began; their removal remains owed.
    case appliedWhileClosing
}

public enum GNUnetTunnelRemoval: Sendable {
    case notConfigured
    /// The original setTunnelNetworkSettings(nil) completion succeeded.
    case cleared
}

public enum GNUnetPacketTunnelResourceError: Error, Sendable {
    case busy
    case stopped
    case providerGone
    case invalidSettings
    case invalidPacket
    case capacity
}

/// Owns one settings operation, one native read and one synchronous packet write.
/// Native APIs are thread safe; the lock protects all mutable admission and
/// completion state. A caller retains this owner through its original close.
/// It does not start a node, manage a VPN manager, or extract a private utun fd.
public final class GNUnetPacketTunnelResources: @unchecked Sendable {
    public typealias ApplyCompletion = @Sendable (Result<GNUnetTunnelSettingsOutcome, Error>) -> Void
    public typealias ReadCompletion = @Sendable (Result<[GNUnetTunnelPacket], Error>) -> Void
    public typealias WriteCompletion = @Sendable (GNUnetPacketWriteOutcome) -> Void
    public typealias CloseCompletion = @Sendable (Result<GNUnetTunnelRemoval, Error>) -> Void

    private enum Phase { case new, applying, active, closing, closed, failed }
    private let lock = NSLock()
    private weak var provider: NEPacketTunnelProvider?
    private let flow: NEPacketTunnelFlow
    private let maximumPacketBytes: Int
    private let maximumBatchPackets: Int
    private var phase: Phase = .new
    private var settingsAttempted = false
    private var applying: ApplyCompletion?
    private var writing = false
    private var deliveries = 0
    private var clearing = false
    private var closing: CloseCompletion?
    private var closed: Result<GNUnetTunnelRemoval, Error>?
    private var readSerial: UInt64 = 0
    private var reading: (UInt64, ReadCompletion)?

    public init(
        provider: NEPacketTunnelProvider,
        maximumPacketBytes: Int = 65575,
        maximumBatchPackets: Int = 64
    ) throws {
        guard (40...65575).contains(maximumPacketBytes), (1...64).contains(maximumBatchPackets) else {
            throw GNUnetPacketTunnelResourceError.capacity
        }
        self.provider = provider
        flow = provider.packetFlow
        self.maximumPacketBytes = maximumPacketBytes
        self.maximumBatchPackets = maximumBatchPackets
    }

    /// One explicit plan per OS tunnel session. Only the native completion may
    /// report applied. The extension calls its original startTunnel completion
    /// after this and its actual shared-SDK readiness barrier have succeeded.
    public func apply(_ plan: GNUnetPacketTunnelPlan, completion: @escaping ApplyCompletion) throws {
        let settings = try Self.settings(plan)
        let original: NEPacketTunnelProvider = try lock.withLock {
            guard phase == .new else { throw GNUnetPacketTunnelResourceError.busy }
            guard let provider else { throw GNUnetPacketTunnelResourceError.providerGone }
            phase = .applying
            settingsAttempted = true
            applying = completion
            return provider
        }
        original.setTunnelNetworkSettings(settings) { [weak self] error in
            self?.applied(error)
        }
    }

    /// Exactly one caller-driven read. A completed batch is bounded before it
    /// is retained or delivered; the caller decides when to request another.
    public func read(completion: @escaping ReadCompletion) throws {
        let serial: UInt64 = try lock.withLock {
            guard phase == .active else { throw GNUnetPacketTunnelResourceError.stopped }
            guard reading == nil else { throw GNUnetPacketTunnelResourceError.busy }
            guard readSerial < UInt64.max else { throw GNUnetPacketTunnelResourceError.capacity }
            readSerial += 1
            reading = (readSerial, completion)
            return readSerial
        }
        // This block owns no user completion or raw Rust handle. A late native
        // read can only look up this original owner's still-current read slot.
        flow.readPackets { [weak self] packets, protocols in
            self?.readCompleted(serial, packets: packets, protocols: protocols)
        }
    }

    /// Submit one immutable packet, preserving one actual Bool outcome. The
    /// caller keeps its original write token; false is an uncertain outcome.
    public func write(_ packet: GNUnetTunnelPacket, completion: @escaping WriteCompletion) throws {
        try validate(packet)
        try lock.withLock {
            guard phase == .active else { throw GNUnetPacketTunnelResourceError.stopped }
            guard !writing else { throw GNUnetPacketTunnelResourceError.busy }
            writing = true
        }
        let family = packet.version == .ipv4 ? AF_INET : AF_INET6
        let accepted = flow.writePackets([packet.bytes], withProtocols: [NSNumber(value: family)])
        completion(accepted ? .accepted : .unknown)
        lock.withLock { writing = false }
        beginRemovalIfReady()
    }

    /// Fence new work and retire the logical read immediately. Apple exposes
    /// no read cancellation receipt; late OS callbacks retain no client handle.
    /// Actual settings removal waits for an admitted apply/write to finish.
    public func close(completion: @escaping CloseCompletion) {
        let admission: (ReadCompletion?, Result<GNUnetTunnelRemoval, Error>?) = lock.withLock {
            if let closed { return (nil, closed) }
            if phase == .closing { return (nil, .failure(GNUnetPacketTunnelResourceError.busy)) }
            phase = .closing
            closing = completion
            let read = reading?.1
            reading = nil
            if read != nil { deliveries += 1 }
            return (read, nil)
        }
        if let result = admission.1 { completion(result); return }
        admission.0?(.failure(GNUnetPacketTunnelResourceError.stopped))
        if admission.0 != nil { deliveryFinished() } else { beginRemovalIfReady() }
    }

    private func applied(_ error: Error?) {
        let work: (ApplyCompletion?, Bool) = lock.withLock {
            let original = applying
            applying = nil
            if original != nil { deliveries += 1 }
            let retiring = phase == .closing
            if !retiring { phase = error == nil ? .active : .failed }
            return (original, retiring)
        }
        if let error {
            work.0?(.failure(error))
        } else {
            work.0?(.success(work.1 ? .appliedWhileClosing : .applied))
        }
        if work.0 != nil { deliveryFinished() } else { beginRemovalIfReady() }
    }

    private func readCompleted(_ serial: UInt64, packets: [Data], protocols: [NSNumber]) {
        guard lock.withLock({ reading?.0 == serial && phase == .active }) else { return }
        let result: Result<[GNUnetTunnelPacket], Error>
        do {
            guard packets.count == protocols.count, packets.count <= maximumBatchPackets else {
                throw GNUnetPacketTunnelResourceError.capacity
            }
            var total = 0
            var batch: [GNUnetTunnelPacket] = []
            batch.reserveCapacity(packets.count)
            for index in packets.indices {
                let family = protocols[index].int32Value
                guard protocols[index].doubleValue == Double(family), family == AF_INET || family == AF_INET6 else {
                    throw GNUnetPacketTunnelResourceError.invalidPacket
                }
                let packet = GNUnetTunnelPacket(bytes: packets[index], version: family == AF_INET ? .ipv4 : .ipv6)
                try validate(packet)
                guard total <= 4 * 1024 * 1024 - packet.bytes.count else {
                    throw GNUnetPacketTunnelResourceError.capacity
                }
                total += packet.bytes.count
                batch.append(packet)
            }
            result = .success(batch)
        } catch {
            result = .failure(error)
        }
        let completion: ReadCompletion? = lock.withLock {
            guard reading?.0 == serial, phase == .active else { return nil }
            let original = reading?.1
            reading = nil
            if original != nil { deliveries += 1 }
            if case .failure = result { phase = .failed }
            return original
        }
        completion?(result)
        if completion != nil { deliveryFinished() }
    }

    private func deliveryFinished() {
        lock.withLock { deliveries -= 1 }
        beginRemovalIfReady()
    }

    private func validate(_ packet: GNUnetTunnelPacket) throws {
        let minimum = packet.version == .ipv4 ? 20 : 40
        guard packet.bytes.count >= minimum, packet.bytes.count <= maximumPacketBytes,
              let first = packet.bytes.first, first >> 4 == packet.version.rawValue
        else { throw GNUnetPacketTunnelResourceError.invalidPacket }
    }

    private enum RemovalStart {
        case none
        case finish(Result<GNUnetTunnelRemoval, Error>)
        case clear(NEPacketTunnelProvider)
    }

    private func beginRemovalIfReady() {
        let start: RemovalStart = lock.withLock {
            guard phase == .closing, applying == nil, !writing, deliveries == 0, !clearing else { return .none }
            clearing = true
            if !settingsAttempted { return .finish(.success(.notConfigured)) }
            guard let provider else { return .finish(.failure(GNUnetPacketTunnelResourceError.providerGone)) }
            return .clear(provider)
        }
        switch start {
        case .none: break
        case let .finish(result): removed(result)
        case let .clear(original):
            original.setTunnelNetworkSettings(nil) { [weak self] error in
                if let error { self?.removed(.failure(error)) }
                else { self?.removed(.success(.cleared)) }
            }
        }
    }

    private func removed(_ result: Result<GNUnetTunnelRemoval, Error>) {
        let completion: CloseCompletion? = lock.withLock {
            closed = result
            if case .success = result { phase = .closed } else { phase = .failed }
            let original = closing
            closing = nil
            return original
        }
        completion?(result)
    }

    private static func settings(_ plan: GNUnetPacketTunnelPlan) throws -> NEPacketTunnelNetworkSettings {
        guard !plan.remoteAddress.isEmpty, plan.remoteAddress.utf8.count <= 256,
              !plan.remoteAddress.utf8.contains(0),
              plan.ipv4Addresses.count + plan.ipv6Addresses.count > 0,
              plan.ipv4Addresses.count + plan.ipv6Addresses.count <= 64,
              plan.ipv4Routes.count + plan.ipv6Routes.count + plan.ipv4ExcludedRoutes.count + plan.ipv6ExcludedRoutes.count <= 128,
              plan.dnsServers.count <= 32, (68...65535).contains(plan.mtu),
              plan.ipv6Addresses.isEmpty || plan.mtu >= 1280
        else { throw GNUnetPacketTunnelResourceError.invalidSettings }
        for value in plan.ipv4Addresses + plan.ipv4Routes + plan.ipv4ExcludedRoutes { try prefix(value, version: .ipv4) }
        for value in plan.ipv6Addresses + plan.ipv6Routes + plan.ipv6ExcludedRoutes { try prefix(value, version: .ipv6) }
        for dns in plan.dnsServers {
            guard validIP(dns, version: .ipv4) || validIP(dns, version: .ipv6) else {
                throw GNUnetPacketTunnelResourceError.invalidSettings
            }
        }
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: plan.remoteAddress)
        if !plan.ipv4Addresses.isEmpty {
            let ipv4 = NEIPv4Settings(
                addresses: plan.ipv4Addresses.map(\.address),
                subnetMasks: plan.ipv4Addresses.map { netmask($0.length) }
            )
            ipv4.includedRoutes = plan.ipv4Routes.map {
                NEIPv4Route(destinationAddress: $0.address, subnetMask: netmask($0.length))
            }
            ipv4.excludedRoutes = plan.ipv4ExcludedRoutes.map {
                NEIPv4Route(destinationAddress: $0.address, subnetMask: netmask($0.length))
            }
            settings.ipv4Settings = ipv4
        } else if !plan.ipv4Routes.isEmpty || !plan.ipv4ExcludedRoutes.isEmpty { throw GNUnetPacketTunnelResourceError.invalidSettings }
        if !plan.ipv6Addresses.isEmpty {
            let ipv6 = NEIPv6Settings(
                addresses: plan.ipv6Addresses.map(\.address),
                networkPrefixLengths: plan.ipv6Addresses.map { NSNumber(value: $0.length) }
            )
            ipv6.includedRoutes = plan.ipv6Routes.map {
                NEIPv6Route(destinationAddress: $0.address, networkPrefixLength: NSNumber(value: $0.length))
            }
            ipv6.excludedRoutes = plan.ipv6ExcludedRoutes.map {
                NEIPv6Route(destinationAddress: $0.address, networkPrefixLength: NSNumber(value: $0.length))
            }
            settings.ipv6Settings = ipv6
        } else if !plan.ipv6Routes.isEmpty || !plan.ipv6ExcludedRoutes.isEmpty { throw GNUnetPacketTunnelResourceError.invalidSettings }
        if !plan.dnsServers.isEmpty { settings.dnsSettings = NEDNSSettings(servers: plan.dnsServers) }
        settings.mtu = NSNumber(value: plan.mtu)
        return settings
    }

    private static func prefix(_ value: GNUnetIPPrefix, version: GNUnetPacketVersion) throws {
        guard value.length <= (version == .ipv4 ? 32 : 128), validIP(value.address, version: version) else {
            throw GNUnetPacketTunnelResourceError.invalidSettings
        }
    }

    private static func validIP(_ value: String, version: GNUnetPacketVersion) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 128, !value.utf8.contains(0) else { return false }
        if version == .ipv4 {
            var address = in_addr()
            return value.withCString { inet_pton(AF_INET, $0, &address) == 1 }
        }
        var address = in6_addr()
        return value.withCString { inet_pton(AF_INET6, $0, &address) == 1 }
    }

    private static func netmask(_ length: UInt8) -> String {
        let mask: UInt32 = length == 0 ? 0 : UInt32.max << (32 - Int(length))
        return [24, 16, 8, 0].map { String((mask >> $0) & 255) }.joined(separator: ".")
    }
}
