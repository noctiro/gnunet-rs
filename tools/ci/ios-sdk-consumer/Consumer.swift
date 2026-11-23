import GNUnetNode

@main
struct Consumer {
    static func main() async throws {
        let arguments = CommandLine.arguments
        guard arguments.count == 3 else { return }
        let node = GNUnetNode(options: GNUnetNodeOptions(
            stateDirectory: arguments[1],
            ipcDirectory: arguments[2]
        ))
        try await node.start()
        do {
            try await node.setDnsServers([])
        } catch {
            await node.stop()
            throw error
        }
        await node.stop()
    }
}
