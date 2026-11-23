import Foundation
import GNUnetNodeNative
import NetworkExtension

/// Subclass this provider as the principal class of a DNS proxy app extension.
/// GNUNET_CONFIG selects an absolute filename or a signed bundle resource.
@available(iOS 18.0, *)
open class GNUnetDNSProxyProvider: NEDNSProxyProvider, @unchecked Sendable {
    private let session = DnsProxySession()

    public final override func startProxy(
        options: [String: Any]?, completionHandler: @escaping (Error?) -> Void
    ) {
        do { try session.start(self, options: options, reply: ExtensionReply(completionHandler)) }
        catch { completionHandler(error) }
    }

    public final override func handleNewFlow(_ flow: NEAppProxyFlow) -> Bool {
        // The system's default UDP callback forwards to this entry. Reads and
        // replies use the original per-datagram endpoints inside the host.
        session.accept(self, flow: flow)
    }

    public final override func stopProxy(
        with reason: NEProviderStopReason, completionHandler: @escaping () -> Void
    ) {
        session.stop(self, reason: reason.rawValue, reply: ExtensionReply { _ in completionHandler() })
    }
}

/// Apple owns the original escaping callbacks. The owner invokes each once.
private struct ExtensionReply<Value>: @unchecked Sendable {
    let complete: (Value) -> Void
    init(_ complete: @escaping (Value) -> Void) { self.complete = complete }
}

private enum DnsProxyError: Error {
    case invalidConfiguration
    case occupied
    case nativeStart(Int32)
    case retirement(Int32)
}

@available(iOS 18.0, *)
private final class DnsProxySession: @unchecked Sendable {
    // The owning pointer is borrowed only under admission and consumed once
    // on the worker-join queue after changing the state to retiring.
    private struct Native: @unchecked Sendable {
        let id: UUID
        let handle: OpaquePointer
    }

    private enum End: Sendable { case failedStart, stop(reason: Int) }
    private enum State {
        case idle
        case active(Native)
        case retiring(Task<Bool, Never>)
    }

    private let admission = DispatchQueue(label: "org.gnunet.dns-proxy.admission")
    private let workerJoin = DispatchQueue(label: "org.gnunet.dns-proxy.join")
    private var state = State.idle

    func start(
        _ provider: GNUnetDNSProxyProvider, options: [String: Any]?, reply: ExtensionReply<Error?>
    ) throws {
        try admission.sync {
            guard case .idle = state else { throw DnsProxyError.occupied }
            let bundle = Bundle.main
            guard let selected = options?["GNUNET_CONFIG"] as? String,
                  let filename = configurationFile(selected, in: bundle),
                  let resources = bundle.resourceURL,
                  let executable = bundle.executableURL
            else { throw DnsProxyError.invalidConfiguration }

            let id = UUID()
            var handle: OpaquePointer?
            let status = withBytes(filename) { configuration in
                withBytes(resources.path) { resourcePath in
                    withBytes(executable.deletingLastPathComponent().path) { binaries in
                        var paths = GnDnsProxyPaths(configuration: configuration, resources: resourcePath, binaries: binaries)
                        return gnunet_dns_proxy_start(&paths, Unmanaged.passUnretained(provider).toOpaque(), { error in
                            // Copy the borrowed NSError reference before leaving its native callback.
                            let failure = error.map { Unmanaged<NSError>.fromOpaque($0).takeUnretainedValue() }
                            self.didStart(provider, id: id, failure: failure, reply: reply)
                        }, &handle)
                    }
                }
            }
            guard status == GNUNET_NODE_OK, let handle else { throw DnsProxyError.nativeStart(status) }
            state = .active(Native(id: id, handle: handle))
        }
    }

    func accept(_ provider: GNUnetDNSProxyProvider, flow: NEAppProxyFlow) -> Bool {
        admission.sync {
            guard case let .active(native) = state else { return false }
            return gnunet_dns_proxy_accept(
                native.handle, Unmanaged.passUnretained(provider).toOpaque(), Unmanaged.passUnretained(flow).toOpaque()
            ) != 0
        }
    }

    func stop(_ provider: GNUnetDNSProxyProvider, reason: Int, reply: ExtensionReply<Void>) {
        let retirement: Task<Bool, Never>? = admission.sync {
            switch state {
            case .idle:
                return nil
            case let .retiring(original):
                return original
            case let .active(original):
                return join(provider, original, after: .stop(reason: reason))
            }
        }
        Task {
            if await retirement?.value != false { reply.complete(()) }
        }
    }

    private func didStart(
        _ provider: GNUnetDNSProxyProvider, id: UUID, failure: NSError?, reply: ExtensionReply<Error?>
    ) {
        // The native start block can run during submission. Defer state access
        // until the startup call has installed the original owning pointer.
        admission.async {
            let retirement: Task<Bool, Never>?
            if failure != nil, case let .active(native) = self.state, native.id == id {
                retirement = self.join(provider, native, after: .failedStart)
            } else {
                retirement = nil
            }
            Task {
                _ = await retirement?.value
                reply.complete(failure)
            }
        }
    }

    private func join(_ provider: GNUnetDNSProxyProvider, _ native: Native, after end: End) -> Task<Bool, Never> {
        dispatchPrecondition(condition: .onQueue(admission))
        let retirement = Task {
            let status = await withCheckedContinuation { continuation in
                workerJoin.async {
                    if case let .stop(reason) = end {
                        _ = gnunet_dns_proxy_stop(native.handle, Unmanaged.passUnretained(provider).toOpaque(), reason)
                    }
                    continuation.resume(returning: gnunet_dns_proxy_join(native.handle))
                }
            }
            // A failed start never opened flow admission. A running session
            // requires the original native stop receipt in addition to join.
            if case .stop = end, status != GNUNET_NODE_OK {
                provider.cancelProxyWithError(DnsProxyError.retirement(status))
                return false
            }
            admission.sync { self.state = .idle }
            return true
        }
        state = .retiring(retirement)
        return retirement
    }
}

private func configurationFile(_ selected: String, in bundle: Bundle) -> String? {
    guard !selected.isEmpty, selected.utf8.count <= 4096, !selected.utf8.contains(0) else { return nil }
    if selected.hasPrefix("/") { return selected }
    guard selected != ".", selected != "..", !selected.contains("/"), selected.utf8.count <= 255 else { return nil }
    return bundle.url(forResource: selected, withExtension: nil)?.path
}

private func withBytes<T>(_ text: String, _ body: (GnBytes) -> T) -> T {
    Array(text.utf8).withUnsafeBufferPointer { bytes in
        body(GnBytes(data: bytes.baseAddress, len: bytes.count))
    }
}
