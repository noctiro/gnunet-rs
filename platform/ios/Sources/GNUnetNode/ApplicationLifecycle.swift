import UIKit

/// Connects one application-wide node to its aggregate foreground state.
@available(iOSApplicationExtension, unavailable)
@MainActor
public final class GNUnetApplicationLifecycle {
    public let node: GNUnetNode
    private let onStartError: @MainActor @Sendable (GNUnetNodeError) -> Void

    public init(
        node: GNUnetNode,
        onStartError: @escaping @MainActor @Sendable (GNUnetNodeError) -> Void
    ) {
        self.node = node
        self.onStartError = onStartError
    }

    /// Call when the app first launches in the foreground or returns there.
    public func enterForeground() {
        node.enqueueStart { [onStartError] result in
            if case let .failure(error) = result {
                Task { @MainActor in onStartError(error) }
            }
        }
    }

    /// Call when the last foreground scene leaves. UIKit owns the time allowance.
    public func enterBackground(in application: UIApplication) {
        let task = RetirementTask(application: application)
        task.begin()
        node.enqueueStop {
            Task { @MainActor in task.end() }
        }
    }

    @MainActor
    private final class RetirementTask {
        private let application: UIApplication
        private var identifier: UIBackgroundTaskIdentifier = .invalid

        init(application: UIApplication) {
            self.application = application
        }

        func begin() {
            identifier = application.beginBackgroundTask(withName: "GNUnet shutdown") { [weak self] in
                self?.end()
            }
        }

        func end() {
            guard identifier != .invalid else { return }
            let original = identifier
            identifier = .invalid
            application.endBackgroundTask(original)
        }
    }
}
