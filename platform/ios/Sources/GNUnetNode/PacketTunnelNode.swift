import Darwin
import Dispatch
import Foundation
import GNUnetNodeNative
import Network
import NetworkExtension

/// Application-owned upstream routing for the whole original tunnel lifetime.
/// The application establishes safe upstream routing before any node socket
/// opens and maintains it for the original tunnel lifetime.
public struct GNUnetPacketTunnelHostPolicy: Sendable {
    public var remoteAddress: String
    public var dnsServers: [String]
    public var ipv4ExcludedRoutes: [GNUnetIPPrefix]
    public var ipv6ExcludedRoutes: [GNUnetIPPrefix]
    /// Qualify the observed path and return its permitted numeric Resolver
    /// endpoints. The SDK observes one preparation at a time and may cancel it.
    public let prepareUpstream: @Sendable (NWPath) async throws -> [String]

    public init(
        remoteAddress: String,
        dnsServers: [String] = [],
        ipv4ExcludedRoutes: [GNUnetIPPrefix] = [],
        ipv6ExcludedRoutes: [GNUnetIPPrefix] = [],
        prepareUpstream: @escaping @Sendable (NWPath) async throws -> [String]
    ) {
        self.remoteAddress = remoteAddress
        self.dnsServers = dnsServers
        self.ipv4ExcludedRoutes = ipv4ExcludedRoutes
        self.ipv6ExcludedRoutes = ipv6ExcludedRoutes
        self.prepareUpstream = prepareUpstream
    }
}

public enum GNUnetPacketTunnelNodeError: Error, Sendable {
    case busy
    case stopped
    case invalidOptions
    case invalidCommand
    case native(operation: String, code: Int32)
    case failed(String)
    case startupTimedOut
    case commandExpired
    /// Original cleanup continues; this error is not a native-removal receipt.
    case retirementPending
    case cleanup(original: String, removal: String)
}

/// One outbound TCP GNUnet peer plus its original NetworkExtension resources.
/// Retains its C handles until native callbacks settle and the original worker
/// terminates. One bounded command reader is separate from the serial state and
/// reply queue; destruction waits for that reader to release the original handle.
public final class GNUnetPacketTunnelNode: Sendable {
    private let owner: Owner

    public init(
        provider: NEPacketTunnelProvider,
        options: GNUnetNodeOptions,
        hostPolicy: GNUnetPacketTunnelHostPolicy,
        maximumPacketBytes: UInt16 = 1500,
        ingressPackets: UInt16 = 64
    ) throws {
        guard maximumPacketBytes >= 40, (1...1024).contains(ingressPackets),
              options.startupTimeoutMilliseconds > 0, options.drainTimeoutMilliseconds > 0,
              options.dnsServers.isEmpty
        else { throw GNUnetPacketTunnelNodeError.invalidOptions }
        owner = Owner(
            resources: try GNUnetPacketTunnelResources(
                provider: provider, maximumPacketBytes: Int(maximumPacketBytes), maximumBatchPackets: 64
            ),
            options: options, policy: hostPolicy,
            maximumPacket: maximumPacketBytes, ingressPackets: ingressPackets
        )
    }

    deinit { owner.enqueueStop(nil) }

    /// Services route commands while waiting for actual node readiness. The
    /// provider may then complete its original startTunnel callback.
    public func start() async throws {
        try await withTaskCancellationHandler {
            try Task.checkCancellation()
            try await withCheckedThrowingContinuation { continuation in owner.enqueueStart(continuation) }
        } onCancel: { owner.enqueueStop(nil) }
    }

    public func snapshot() async throws -> GNUnetNodeStatus {
        try await withCheckedThrowingContinuation { continuation in
            owner.queue.async { [owner] in
                do { continuation.resume(returning: try owner.snapshot()) }
                catch { continuation.resume(throwing: error) }
            }
        }
    }

    /// A pending-retirement error leaves original callback/handle owners alive.
    /// Only a successful return is complete node and native-settings retirement.
    public func stop() async throws {
        try await withCheckedThrowingContinuation { continuation in
            owner.enqueueStop(.bounded(continuation))
        }
    }

    /// Requests stop and waits for the original terminal retirement result.
    /// Use this for the NetworkExtension stop callback. The wait stays pending
    /// while original native operations still own resources. A terminal failure
    /// reports cleanup errors rather than acknowledging native settings removal.
    public func stopAndWaitForRetirement() async throws {
        try await withCheckedThrowingContinuation { continuation in
            owner.enqueueStop(.retirement(continuation))
        }
    }

    private final class Owner: @unchecked Sendable {
        struct Token: Equatable, Sendable {
            let epoch: UInt64
            let revision: UInt64
            init(_ value: GnVpnToken) { epoch = value.epoch; revision = value.revision }
            var native: GnVpnToken { GnVpnToken(epoch: epoch, revision: revision) }
        }
        enum Phase { case new, preparing, starting, running, stopping, closed }
        enum StopWait {
            case bounded(CheckedContinuation<Void, Error>)
            case retirement(CheckedContinuation<Void, Error>)
        }
        struct CommandResult: @unchecked Sendable {
            let code: Int32
            let command: GnVpnCommand
            let packet: Data
            let deadline: DispatchTime
        }
        /// Only this serial worker accesses its original handle and buffer.
        /// The owner keeps it alive until its last bounded read has returned.
        final class CommandReader: @unchecked Sendable {
            let queue = DispatchQueue(label: "org.gnunet.packet-tunnel.commands", qos: .utility)
            let handle: OpaquePointer
            var packet: [UInt8]

            init(handle: OpaquePointer, capacity: Int) {
                self.handle = handle
                packet = [UInt8](repeating: 0, count: capacity)
            }
            func next() -> CommandResult {
                var command = GnVpnCommand()
                let code = packet.withUnsafeMutableBufferPointer {
                    gnunet_vpn_next(handle, 25, &command, $0.baseAddress, $0.count)
                }
                let deadline = DispatchTime.now() + .milliseconds(Int(command.remaining_ms))
                let count = code == 0 && Int(command.kind) == GNUNET_VPN_WRITE_PACKET
                    ? min(Int(command.packet_len), packet.count) : 0
                return CommandResult(code: code, command: command, packet: Data(packet.prefix(count)),
                                     deadline: deadline)
            }
        }
        let queue = DispatchQueue(label: "org.gnunet.packet-tunnel", qos: .utility)
        let resources: GNUnetPacketTunnelResources
        let options: GNUnetNodeOptions
        let policy: GNUnetPacketTunnelHostPolicy
        let maximumPacket: UInt16
        let ingressPackets: UInt16
        var phase: Phase = .new
        var node: OpaquePointer?
        var vpn: OpaquePointer?
        var retained: Owner?
        var timer: (any DispatchSourceTimer)?
        lazy var upstream = PacketTunnelUpstream(queue: queue, prepare: policy.prepareUpstream) {
            [weak self] event in self?.upstreamChanged(event)
        }
        var reader: CommandReader?
        var readerActive = false
        var starting: CheckedContinuation<Void, Error>?
        var boundedStop: CheckedContinuation<Void, Error>?
        var retirementStop: CheckedContinuation<Void, Error>?
        var failure: Error?
        var cleanupFailure: Error?
        var lastStatus: GNUnetNodeStatus?
        var startupDeadline = DispatchTime.distantFuture
        var stopAt: UInt64 = 0
        var controllerClosed = false
        var route: Token?
        var writing: Token?
        var reading = false
        var routesReady = false
        var settingsAdmitted = false
        var removalStarted = false
        var removalFinished = false
        var ingress: [GNUnetTunnelPacket] = []
        var ingressIndex = 0

        init(resources: GNUnetPacketTunnelResources, options: GNUnetNodeOptions,
             policy: GNUnetPacketTunnelHostPolicy, maximumPacket: UInt16, ingressPackets: UInt16) {
            self.resources = resources
            self.options = options
            self.policy = policy
            self.maximumPacket = maximumPacket
            self.ingressPackets = ingressPackets
        }

        func enqueueStart(_ result: CheckedContinuation<Void, Error>) {
            queue.async { [self] in
                guard phase == .new else { result.resume(throwing: GNUnetPacketTunnelNodeError.busy); return }
                phase = .preparing
                starting = result
                startupDeadline = .now() + .milliseconds(Int(options.startupTimeoutMilliseconds))
                retained = self
                startTimer()
                upstream.start()
            }
        }

        func upstreamChanged(_ event: PacketTunnelUpstream.Event) {
            switch event {
            case .invalidated:
                if let node {
                    do { try NodeDnsSnapshot([]).apply(to: node) }
                    catch { fail(error) }
                }
            case let .ready(snapshot):
                if phase == .preparing {
                    startNative(snapshot)
                } else if let node {
                    do { try snapshot.apply(to: node) }
                    catch { fail(error) }
                }
            case let .failed(error):
                fail(error)
            case .retired:
                finishIfReady()
            }
        }

        func startNative(_ snapshot: NodeDnsSnapshot) {
            guard DispatchTime.now() < startupDeadline else {
                fail(GNUnetPacketTunnelNodeError.startupTimedOut)
                return
            }
            phase = .starting
            var vpnOptions = GnVpnOptions(
                peer_mode: UInt32(GNUNET_VPN_PEERS_OUTBOUND_TCP),
                packet_source: UInt32(GNUNET_VPN_APPLICATION_PACKETS),
                maximum_packet: maximumPacket, ingress_packets: ingressPackets
            )
            let code: Int32
            do {
                code = try options.withNativeOptions(bindings: .outboundTCP(snapshot)) { input in
                    gnunet_node_start_with_vpn(&input, &vpnOptions, &node, &vpn)
                }
            } catch { fail(error); return }
            guard code == 0, node != nil, let vpn else {
                fail(GNUnetPacketTunnelNodeError.native(operation: "start_with_vpn", code: code))
                return
            }
            reader = CommandReader(handle: vpn, capacity: Int(maximumPacket))
            driveCommands()
        }

        func startTimer() {
            guard timer == nil else { return }
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.setEventHandler { [weak self] in self?.poll() }
            timer.schedule(deadline: .now(), repeating: .milliseconds(10), leeway: .milliseconds(1))
            self.timer = timer
            timer.activate()
        }

        func enqueueStop(_ result: StopWait?) {
            queue.async { [self] in requestStop(result) }
        }
        func requestStop(_ result: StopWait?) {
            if phase == .closed {
                switch result {
                case let .bounded(waiter): waiter.resume(with: stopResult)
                case let .retirement(waiter): waiter.resume(with: retirementResult)
                case nil: break
                }
                return
            }
            switch result {
            case let .bounded(waiter):
                guard boundedStop == nil else {
                    waiter.resume(throwing: GNUnetPacketTunnelNodeError.busy)
                    return
                }
                boundedStop = waiter
            case let .retirement(waiter):
                guard retirementStop == nil else {
                    waiter.resume(throwing: GNUnetPacketTunnelNodeError.busy)
                    return
                }
                retirementStop = waiter
            case nil:
                break
            }
            if phase != .stopping {
                phase = .stopping
                stopAt = DispatchTime.now().uptimeNanoseconds
                upstream.stop()
                starting?.resume(throwing: failure ?? GNUnetPacketTunnelNodeError.stopped)
                starting = nil
                routesReady = false
                ingress.removeAll(keepingCapacity: false)
                ingressIndex = 0
                if let vpn { _ = gnunet_vpn_fence(vpn) }
                if let node { _ = gnunet_node_stop(node) }
                startTimer()
            }
            if vpn == nil {
                controllerClosed = true
                beginRemoval(nil)
            }
        }

        func fail(_ error: Error) {
            if failure == nil { failure = error }
            requestStop(nil)
        }

        func poll() {
            if phase == .preparing || phase == .starting, DispatchTime.now() >= startupDeadline {
                fail(GNUnetPacketTunnelNodeError.startupTimedOut)
            }
            pumpIngress()
            do {
                let status = try snapshot()
                lastStatus = status
                if status.phase == .ready, routesReady, upstream.hasCurrent, phase == .starting {
                    if DispatchTime.now() >= startupDeadline {
                        fail(GNUnetPacketTunnelNodeError.startupTimedOut)
                    } else {
                        phase = .running
                        starting?.resume(); starting = nil
                    }
                } else if status.phase == .failed {
                    fail(GNUnetPacketTunnelNodeError.failed(status.failure ?? "Native node failed"))
                }
            } catch { if node != nil { fail(error) } }
            finishIfReady()
            if phase == .stopping, let result = boundedStop,
               DispatchTime.now().uptimeNanoseconds - stopAt >= UInt64(options.drainTimeoutMilliseconds) * 1_000_000 {
                boundedStop = nil
                result.resume(throwing: failure ?? GNUnetPacketTunnelNodeError.retirementPending)
            }
        }

        func driveCommands() {
            // A pending native operation owns its exact claimed token. Do not
            // let another claim replace it. Waiting blocks only the reader.
            guard let reader, !readerActive, !controllerClosed,
                  route == nil, writing == nil, phase != .closed else { return }
            readerActive = true
            reader.queue.async { [self, reader] in
                let began = DispatchTime.now().uptimeNanoseconds
                let result = reader.next()
                // Even a spurious immediate WAIT or repeated native error
                // yields; successful commands have no timer-imposed delay.
                let deadline = result.code == 0 ? DispatchTime.now()
                    : DispatchTime(uptimeNanoseconds: max(DispatchTime.now().uptimeNanoseconds, began + 25_000_000))
                queue.asyncAfter(deadline: deadline) { [self] in
                    readerActive = false
                    if result.code == 0 { commandReceived(result) }
                    else if result.code != GNUNET_VPN_WAIT {
                        fail(GNUnetPacketTunnelNodeError.native(operation: "vpn_next", code: result.code))
                    }
                    driveCommands()
                    finishIfReady()
                }
            }
        }

        func commandReceived(_ result: CommandResult) {
            let command = result.command
            let token = Token(command.token)
            let expired = DispatchTime.now() >= result.deadline
            switch Int(command.kind) {
            case GNUNET_VPN_APPLY_ROUTES:
                guard !expired, phase == .starting || phase == .running else {
                    completeRoute(token, outcome: settingsAdmitted ? GNUNET_VPN_ROUTES_FAILED : GNUNET_VPN_ROUTES_FAILED_ABSENT,
                                  error: expired ? GNUnetPacketTunnelNodeError.commandExpired :
                                      GNUnetPacketTunnelNodeError.stopped)
                    return
                }
                guard route == nil else { fail(GNUnetPacketTunnelNodeError.invalidCommand); return }
                route = token
                do {
                    let plan = try routePlan(command)
                    try resources.apply(plan) { [weak self] result in
                        self?.queue.async { [weak self] in self?.applied(token, result: result) }
                    }
                    settingsAdmitted = true
                } catch {
                    route = nil
                    completeRoute(token, outcome: settingsAdmitted ? GNUNET_VPN_ROUTES_FAILED : GNUNET_VPN_ROUTES_FAILED_ABSENT,
                                  error: error)
                    fail(error)
                }
            case GNUNET_VPN_REMOVE_ROUTES:
                guard route == nil else { fail(GNUnetPacketTunnelNodeError.invalidCommand); return }
                route = token
                requestStop(nil)
                beginRemoval(token)
            case GNUNET_VPN_WRITE_PACKET:
                guard writing == nil, command.packet_len > 0, Int(command.packet_len) == result.packet.count else {
                    fail(GNUnetPacketTunnelNodeError.invalidCommand); return
                }
                writing = token
                if phase == .stopping || expired {
                    written(token, outcome: GNUNET_VPN_PACKET_UNSENT,
                            error: expired ? GNUnetPacketTunnelNodeError.commandExpired :
                                GNUnetPacketTunnelNodeError.stopped)
                    return
                }
                let bytes = result.packet
                guard let first = bytes.first, let version = GNUnetPacketVersion(rawValue: first >> 4) else {
                    written(token, outcome: GNUNET_VPN_PACKET_UNSENT, error: GNUnetPacketTunnelNodeError.invalidCommand)
                    fail(GNUnetPacketTunnelNodeError.invalidCommand); return
                }
                do {
                    try resources.write(GNUnetTunnelPacket(bytes: bytes, version: version)) { [weak self] outcome in
                        self?.queue.async { [weak self] in
                            self?.written(token, outcome: outcome == .accepted ? GNUNET_VPN_PACKET_WRITTEN : GNUNET_VPN_PACKET_UNKNOWN)
                        }
                    }
                } catch { written(token, outcome: GNUNET_VPN_PACKET_UNSENT, error: error); fail(error) }
            case GNUNET_VPN_CLOSED:
                controllerClosed = true
                routesReady = false
                if phase != .stopping { requestStop(nil) }
                beginRemoval(nil)
            default: fail(GNUnetPacketTunnelNodeError.invalidCommand)
            }
        }

        func applied(_ token: Token, result: Result<GNUnetTunnelSettingsOutcome, Error>) {
            guard route == token else { fail(GNUnetPacketTunnelNodeError.invalidCommand); return }
            route = nil
            switch result {
            case .success:
                completeRoute(token, outcome: GNUNET_VPN_ROUTES_INSTALLED)
                routesReady = phase == .starting || phase == .running
            case let .failure(error):
                completeRoute(token, outcome: GNUNET_VPN_ROUTES_FAILED, error: error)
                fail(error)
            }
            if controllerClosed { beginRemoval(nil) }
            driveCommands()
        }
        func beginRemoval(_ token: Token?) {
            guard !removalStarted else { return }
            removalStarted = true
            routesReady = false
            ingress.removeAll(keepingCapacity: false); ingressIndex = 0
            resources.close { [weak self] result in
                self?.queue.async { [weak self] in self?.removed(token, result: result) }
            }
        }
        func removed(_ token: Token?, result: Result<GNUnetTunnelRemoval, Error>) {
            removalFinished = true
            if let token, route == token { route = nil }
            switch result {
            case .success:
                if let token { completeRoute(token, outcome: GNUNET_VPN_ROUTES_REMOVED) }
                else if let vpn { _ = diagnostic("") { gnunet_vpn_revoke(vpn, 1, $0) } }
            case let .failure(error):
                cleanupFailure = error
                if let token { completeRoute(token, outcome: GNUNET_VPN_ROUTES_FAILED, error: error) }
                fail(error)
            }
            driveCommands()
            finishIfReady()
        }
        func completeRoute(_ token: Token, outcome: Int, error: Error? = nil) {
            guard let vpn else { return }
            let code = diagnostic(error.map { String(describing: $0) } ?? "") {
                gnunet_vpn_route_complete(vpn, token.native, UInt32(outcome), $0)
            }
            if code != 0, !controllerClosed, phase != .stopping {
                fail(GNUnetPacketTunnelNodeError.native(operation: "route_complete", code: code))
            }
        }
        func written(_ token: Token, outcome: Int, error: Error? = nil) {
            guard writing == token, let vpn else { fail(GNUnetPacketTunnelNodeError.invalidCommand); return }
            writing = nil
            let code = diagnostic(error.map { String(describing: $0) } ?? "") {
                gnunet_vpn_write_complete(vpn, token.native, UInt32(outcome), $0)
            }
            if code != 0, !controllerClosed, phase != .stopping {
                fail(GNUnetPacketTunnelNodeError.native(operation: "write_complete", code: code))
            }
            driveCommands()
        }

        func pumpIngress() {
            guard let vpn, routesReady, upstream.hasCurrent, phase == .starting || phase == .running else { return }
            for _ in 0..<8 {
                guard ingressIndex < ingress.count else { break }
                let bytes = ingress[ingressIndex].bytes
                let code = bytes.withUnsafeBytes {
                    gnunet_vpn_receive(vpn, $0.bindMemory(to: UInt8.self).baseAddress, $0.count)
                }
                if code == GNUNET_VPN_WOULD_BLOCK { return }
                guard code == 0 else {
                    fail(GNUnetPacketTunnelNodeError.native(operation: "receive", code: code)); return
                }
                ingressIndex += 1
            }
            guard ingressIndex == ingress.count else {
                // Yield between bounded chunks without limiting a ready batch
                // to the state timer's frequency. WOULD_BLOCK above retains it.
                queue.async { [self] in pumpIngress() }
                return
            }
            ingress.removeAll(keepingCapacity: false); ingressIndex = 0
            guard !reading else { return }
            reading = true
            do {
                try resources.read { [weak self] result in
                    self?.queue.async { [weak self] in
                        guard let self else { return }
                        self.reading = false
                        if !self.removalStarted, self.phase == .starting || self.phase == .running {
                            switch result {
                            case let .success(batch): self.ingress = batch; self.ingressIndex = 0
                            case let .failure(error): self.fail(error)
                            }
                            self.pumpIngress()
                        }
                        self.finishIfReady()
                    }
                }
            } catch { reading = false; fail(error) }
        }

        func finishIfReady() {
            guard phase == .stopping, controllerClosed, removalFinished,
                  route == nil, writing == nil, !reading, !readerActive, upstream.isIdle else { return }
            if let node {
                guard let status = try? snapshot(), status.phase == .stopped || status.phase == .failed else { return }
                lastStatus = status
                gnunet_node_destroy(node)
                self.node = nil
            }
            if let vpn { gnunet_vpn_destroy(vpn); self.vpn = nil }
            reader = nil
            timer?.cancel(); timer = nil
            phase = .closed
            let bounded = boundedStop
            let retirement = retirementStop
            boundedStop = nil
            retirementStop = nil
            retained = nil
            bounded?.resume(with: stopResult)
            retirement?.resume(with: retirementResult)
        }

        var stopResult: Result<Void, Error> {
            terminalFailure().map(Result<Void, Error>.failure) ?? .success(())
        }

        var retirementResult: Result<Void, Error> {
            cleanupFailure.map(Result<Void, Error>.failure) ?? .success(())
        }

        func terminalFailure() -> Error? {
            if let failure, let cleanupFailure {
                return GNUnetPacketTunnelNodeError.cleanup(
                    original: String(describing: failure), removal: String(describing: cleanupFailure)
                )
            }
            return failure ?? cleanupFailure
        }

        func routePlan(_ command: GnVpnCommand) throws -> GNUnetPacketTunnelPlan {
            guard command.mtu <= UInt32(maximumPacket) else { throw GNUnetPacketTunnelNodeError.invalidCommand }
            let v4 = try prefix(command.ipv4, family: 4)
            let v6 = try prefix(command.ipv6, family: 6)
            try rejectOverlappingExclusions(policy.ipv4ExcludedRoutes, original: command.ipv4, family: 4)
            try rejectOverlappingExclusions(policy.ipv6ExcludedRoutes, original: command.ipv6, family: 6)
            return GNUnetPacketTunnelPlan(
                remoteAddress: policy.remoteAddress,
                ipv4Addresses: v4.map { [$0.1] } ?? [], ipv4Routes: v4.map { [$0.0] } ?? [],
                ipv4ExcludedRoutes: policy.ipv4ExcludedRoutes,
                ipv6Addresses: v6.map { [$0.1] } ?? [], ipv6Routes: v6.map { [$0.0] } ?? [],
                ipv6ExcludedRoutes: policy.ipv6ExcludedRoutes,
                dnsServers: policy.dnsServers, mtu: command.mtu
            )
        }
        func rejectOverlappingExclusions(_ exclusions: [GNUnetIPPrefix], original: GnVpnPrefix, family: UInt8) throws {
            guard exclusions.count <= 128 else { throw GNUnetPacketTunnelNodeError.invalidOptions }
            guard original.family != 0 else { return }
            let network = withUnsafeBytes(of: original.network) { Array($0) }
            for exclusion in exclusions {
                guard exclusion.length <= (family == 4 ? 32 : 128),
                      exclusion.address.utf8.count <= 128, !exclusion.address.utf8.contains(0)
                else { throw GNUnetPacketTunnelNodeError.invalidOptions }
                var bytes = [UInt8](repeating: 0, count: 16)
                let valid = exclusion.address.withCString { text in
                    bytes.withUnsafeMutableBytes { inet_pton(family == 4 ? AF_INET : AF_INET6, text, $0.baseAddress) == 1 }
                }
                guard valid else { throw GNUnetPacketTunnelNodeError.invalidOptions }
                let common = min(Int(original.bits), Int(exclusion.length))
                let matches = (0..<((common + 7) / 8)).allSatisfy { index in
                    let bits = min(8, common - index * 8)
                    let mask = UInt8.max << (8 - bits)
                    return bytes[index] & mask == network[index] & mask
                }
                guard !matches else { throw GNUnetPacketTunnelNodeError.invalidOptions }
            }
        }
        func prefix(_ value: GnVpnPrefix, family: UInt8) throws -> (GNUnetIPPrefix, GNUnetIPPrefix)? {
            if value.family == 0 { return nil }
            guard value.family == family, value.bits <= (family == 4 ? 32 : 128) else {
                throw GNUnetPacketTunnelNodeError.invalidCommand
            }
            let network = try address(withUnsafeBytes(of: value.network) { Array($0) }, family: family)
            let interface = try address(withUnsafeBytes(of: value.interface_address) { Array($0) }, family: family)
            return (GNUnetIPPrefix(address: network, length: value.bits), GNUnetIPPrefix(address: interface, length: value.bits))
        }
        func address(_ bytes: [UInt8], family: UInt8) throws -> String {
            var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            let valid = bytes.withUnsafeBufferPointer { input in
                output.withUnsafeMutableBufferPointer {
                    inet_ntop(family == 4 ? AF_INET : AF_INET6, input.baseAddress, $0.baseAddress, socklen_t($0.count)) != nil
                }
            }
            guard valid else { throw GNUnetPacketTunnelNodeError.invalidCommand }
            return String(decoding: output.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
        }

        func snapshot() throws -> GNUnetNodeStatus {
            guard let node else {
                if let lastStatus { return lastStatus }
                throw GNUnetPacketTunnelNodeError.stopped
            }
            var value = GnNodeSnapshot()
            let code = gnunet_node_snapshot(node, &value)
            guard code == 0, let phase = GNUnetNodePhase(rawValue: value.phase) else {
                throw GNUnetPacketTunnelNodeError.native(operation: "snapshot", code: code)
            }
            let ready = value.has_ready == 0 ? nil : GNUnetNodeReady(
                peer: withUnsafeBytes(of: value.peer) { Array($0) },
                tcpPort: value.tcp_port, udp4Port: value.udp4_port,
                udp6Port: value.udp6_port == 0 ? nil : value.udp6_port,
                quicPort: value.quic_port == 0 ? nil : value.quic_port,
                http3Port: value.http3_port == 0 ? nil : value.http3_port,
                unixMtu: value.unix_mtu == 0 ? nil : value.unix_mtu
            )
            var message: String?
            if phase == .failed {
                let size = min(gnunet_node_error(node, nil, 0), 65536)
                var bytes = [UInt8](repeating: 0, count: size)
                let count = bytes.withUnsafeMutableBufferPointer { gnunet_node_error(node, $0.baseAddress, $0.count) }
                message = String(decoding: bytes.prefix(min(count, size)), as: UTF8.self)
            }
            return GNUnetNodeStatus(phase: phase, ready: ready, failure: message)
        }
        func diagnostic(_ message: String, _ body: (GnBytes) -> Int32) -> Int32 {
            // The C boundary admits 4096 UTF-8 bytes. Re-decode a bounded
            // prefix so a multibyte truncation never makes the receipt invalid.
            let text = message.replacingOccurrences(of: "\0", with: "�")
            let bytes = Array(String(decoding: text.utf8.prefix(4093), as: UTF8.self).utf8)
            return bytes.withUnsafeBufferPointer { body(GnBytes(data: $0.baseAddress, len: $0.count)) }
        }
    }
}
