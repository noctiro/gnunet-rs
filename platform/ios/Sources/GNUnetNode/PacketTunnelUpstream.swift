import Dispatch
import Network

/// Serial ownership of the latest path and at most one host preparation.
final class PacketTunnelUpstream: @unchecked Sendable {
    enum Event {
        case invalidated
        case ready(NodeDnsSnapshot)
        case failed(Error)
        case retired
    }

    typealias Prepare = @Sendable (NWPath) async throws -> [String]

    private let queue: DispatchQueue
    private let prepare: Prepare
    private let observe: (Event) -> Void
    private var monitor: NWPathMonitor?
    private var pending: NWPath?
    private var active: Task<Void, Never>?
    private(set) var hasCurrent = false

    init(queue: DispatchQueue, prepare: @escaping Prepare, observe: @escaping (Event) -> Void) {
        self.queue = queue
        self.prepare = prepare
        self.observe = observe
    }

    var isIdle: Bool { active == nil }

    func start() {
        let monitor = NWPathMonitor()
        self.monitor = monitor
        monitor.pathUpdateHandler = { [weak self, weak monitor] path in
            guard let self, let monitor, self.monitor === monitor else { return }
            pending = path
            hasCurrent = false
            active?.cancel()
            observe(.invalidated)
            prepareNext()
        }
        monitor.start(queue: queue)
    }

    func stop() {
        monitor?.cancel()
        monitor = nil
        pending = nil
        hasCurrent = false
        active?.cancel()
    }

    private func prepareNext() {
        guard active == nil, let path = pending, monitor != nil else { return }
        pending = nil
        active = Task { [weak self, prepare] in
            let result: Result<NodeDnsSnapshot, Error>
            do {
                let servers = try await prepare(path)
                try Task.checkCancellation()
                result = .success(try NodeDnsSnapshot(path.status == .satisfied ? servers : []))
            } catch {
                result = .failure(error)
            }
            self?.queue.async { [weak self] in self?.prepared(result) }
        }
    }

    private func prepared(_ result: Result<NodeDnsSnapshot, Error>) {
        active = nil
        guard monitor != nil else { observe(.retired); return }
        if pending != nil {
            prepareNext()
            return
        }
        switch result {
        case let .success(snapshot):
            hasCurrent = true
            observe(.ready(snapshot))
        case let .failure(error):
            observe(.failed(error))
        }
    }
}
