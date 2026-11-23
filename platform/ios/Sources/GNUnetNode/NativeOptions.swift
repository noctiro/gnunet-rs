import GNUnetNodeNative

/// A bounded logical DNS snapshot; Rust validates numeric endpoint syntax.
struct NodeDnsSnapshot: Sendable {
    let text: String

    init(_ servers: [String]) throws(GNUnetNodeError) {
        guard servers.count <= 32, servers.allSatisfy({ server in
            !server.isEmpty && server.utf8.count <= 256 &&
                !server.utf8.contains(0) && !server.contains(where: { $0.isWhitespace })
        }) else { throw .dnsServers(Int32(GNUNET_NODE_INVALID)) }
        let text = servers.joined(separator: " ")
        guard text.utf8.count <= 4096 else { throw .dnsServers(Int32(GNUNET_NODE_INVALID)) }
        self.text = text
    }

    func apply(to node: OpaquePointer) throws(GNUnetNodeError) {
        let bytes = Array(text.utf8)
        let code = bytes.withUnsafeBufferPointer {
            gnunet_node_set_dns_servers(node, GnBytes(data: $0.baseAddress, len: $0.count))
        }
        guard code == 0 else { throw .dnsServers(code) }
    }
}

enum NodeBindings {
    case configured
    case outboundTCP(NodeDnsSnapshot)
}

extension GNUnetNodeOptions {
    /// Both public owners lend the same copied options through the C call.
    func withNativeOptions<T>(
        bindings: NodeBindings,
        _ body: (inout GnNodeOptions) -> T
    ) throws(GNUnetNodeError) -> T {
        let peers: (tcp: String, udp4: String, udp6: String)
        let dns: NodeDnsSnapshot
        switch bindings {
        case .configured:
            peers = (tcpBind, udp4Bind, udp6Bind ?? "")
            dns = try NodeDnsSnapshot(dnsServers)
        case let .outboundTCP(snapshot):
            peers = ("", "", "")
            dns = snapshot
        }
        let fields = [
            stateDirectory, ipcDirectory, configurationFile ?? "", bootstrapDataDirectory ?? "",
            peers.tcp, peers.udp4, peers.udp6, dns.text,
        ]
        var bytes: [UInt8] = []
        let ranges = fields.map { field -> Range<Int> in
            let start = bytes.count
            bytes.append(contentsOf: field.utf8)
            return start..<bytes.count
        }
        return bytes.withUnsafeBufferPointer { buffer in
            func field(_ index: Int) -> GnBytes {
                let range = ranges[index]
                return GnBytes(
                    data: range.isEmpty ? nil : buffer.baseAddress?.advanced(by: range.lowerBound),
                    len: range.count
                )
            }
            var input = GnNodeOptions(
                state_dir: field(0), ipc_dir: field(1), config_file: field(2), bootstrap_data_dir: field(3),
                tcp_bind: field(4), udp4_bind: field(5), udp6_bind: field(6), dns_servers: field(7),
                startup_timeout_ms: startupTimeoutMilliseconds, drain_timeout_ms: drainTimeoutMilliseconds
            )
            return body(&input)
        }
    }
}
