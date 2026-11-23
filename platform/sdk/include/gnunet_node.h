#ifndef GNUNET_NODE_SDK_H
#define GNUNET_NODE_SDK_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct GnNode GnNode;
typedef struct GnVpn GnVpn;

typedef struct GnBytes {
    const uint8_t *data;
    size_t len;
} GnBytes;

typedef struct GnNodeOptions {
    GnBytes state_dir;
    GnBytes ipc_dir;
    GnBytes config_file;
    GnBytes bootstrap_data_dir;
    GnBytes tcp_bind;
    GnBytes udp4_bind;
    GnBytes udp6_bind;
    GnBytes dns_servers;
    uint32_t startup_timeout_ms;
    uint32_t drain_timeout_ms;
} GnNodeOptions;

typedef struct GnNodeSnapshot {
    uint32_t phase;
    uint32_t has_ready;
    /* The peer identity at initial readiness. */
    uint8_t peer[32];
    uint16_t tcp_port;
    uint16_t udp4_port;
    uint16_t udp6_port;
    uint16_t quic_port;
    uint16_t http3_port;
    uint16_t unix_mtu; /* Zero when the UNIX communicator is disabled. */
} GnNodeSnapshot;

typedef struct GnVpnOptions {
    uint32_t peer_mode;
    uint32_t packet_source;
    uint16_t maximum_packet;
    uint16_t ingress_packets;
} GnVpnOptions;

#if !defined(_WIN32)
typedef struct GnSocketProtection {
    void *context;
    int32_t (*protect)(void *context, int32_t socket_fd);
    void (*release)(void *context);
} GnSocketProtection;
#endif

typedef struct GnVpnToken {
    uint64_t epoch;
    uint64_t revision;
} GnVpnToken;

typedef struct GnVpnPrefix {
    uint8_t family; /* 0 for absent, 4 or 6 for IP. */
    uint8_t bits;
    uint8_t network[16];
    uint8_t interface_address[16];
} GnVpnPrefix;

typedef struct GnVpnCommand {
    uint32_t kind;
    uint32_t mtu;
    GnVpnToken token;
    GnVpnPrefix ipv4;
    GnVpnPrefix ipv6;
    uint32_t packet_len;
    uint32_t remaining_ms;
} GnVpnCommand;

enum {
    GNUNET_NODE_OK = 0,
    GNUNET_NODE_INVALID = 1,
    GNUNET_NODE_SETUP_ERROR = 2,
};

enum {
    GNUNET_VPN_PEERS_LISTENING = 1,
    GNUNET_VPN_PEERS_OUTBOUND_TCP = 2,
    GNUNET_VPN_APPLICATION_PACKETS = 1,
    GNUNET_VPN_UNIX_DESCRIPTOR = 2,
};

enum {
    GNUNET_VPN_APPLY_ROUTES = 1,
    GNUNET_VPN_REMOVE_ROUTES = 2,
    GNUNET_VPN_WRITE_PACKET = 3,
    GNUNET_VPN_CLOSED = 4,
};

enum {
    GNUNET_VPN_ROUTES_INSTALLED = 1,
    GNUNET_VPN_ROUTES_REMOVED = 2,
    GNUNET_VPN_ROUTES_FAILED = 3,
    GNUNET_VPN_ROUTES_FAILED_ABSENT = 4,
    GNUNET_VPN_PACKET_WRITTEN = 1,
    GNUNET_VPN_PACKET_UNSENT = 2,
    GNUNET_VPN_PACKET_UNKNOWN = 3,
    GNUNET_VPN_WAIT = 3,
    GNUNET_VPN_WOULD_BLOCK = 4,
};

enum {
    GNUNET_NODE_STARTING = 0,
    GNUNET_NODE_READY = 1,
    GNUNET_NODE_STOPPING = 2,
    GNUNET_NODE_STOPPED = 3,
    GNUNET_NODE_FAILED = 4,
};

/* All ranges contain UTF-8 without a NUL terminator. Empty optional ranges
 * are permitted and may have a null pointer. Paths are absolute; state_dir
 * and ipc_dir are existing private directories. config_file is an optional
 * GNUnet configuration file. bootstrap_data_dir optionally selects an
 * absolute, stable application resource directory whose hellos child supplies
 * PEERSTORE bootstrap records. Bind strings contain numeric IP:port, with
 * brackets for IPv6. udp4_bind is required and udp6_bind is optional.
 * dns_servers is an optional whitespace-separated list of numeric endpoints
 * or bare numeric IP addresses (port 53). IPv6 interface scopes are numeric.
 * Both timeouts must be positive. All inputs are copied before start returns.
 * On failure, *out is null. A successful start transfers one GnNode owner.
 */
int32_t gnunet_node_start(const GnNodeOptions *options, GnNode **out);

/* The application owns detour routing or socket protection for all upstream
 * traffic throughout the VPN. Establish it before any node sockets open.
 * Outbound TCP requires empty TCP/UDP bind strings. Application packets
 * require a positive ingress_packets. Descriptor mode sets ingress_packets
 * to zero; the kernel owns the receive queue. Supply two distinct writable
 * output slots; on failure both handles are null. The original controller
 * exists while the node is starting, so the provider can service route commands
 * before waiting for node readiness.
 */
int32_t gnunet_node_start_with_vpn(const GnNodeOptions *options, const GnVpnOptions *vpn_options,
                                  GnNode **out, GnVpn **vpn_out);

#if !defined(_WIN32)
/* A live context and both callbacks are required. Valid protection transfers
 * one original context to Rust, including on option or startup failure.
 * protect borrows each original Internet socket before its first native use.
 * Return 1 on success; every other result rejects that socket. The callback
 * never closes the fd or retains it after returning. The callbacks may run
 * on the node worker and the context must remain live until release.
 */
int32_t gnunet_node_start_with_protected_vpn(const GnNodeOptions *options,
                                            const GnVpnOptions *vpn_options,
                                            const GnSocketProtection *protection,
                                            GnNode **out, GnVpn **vpn_out);
#endif

/* One consumer claims complete commands. Application packet mode requires
 * capacity >= maximum_packet on every call. Descriptor mode can pass null/0.
 * timeout_ms is an observation wait, zero polls immediately. WAIT has no
 * command. A copied write carries the original immutable packet and token.
 */
int32_t gnunet_vpn_next(const GnVpn *vpn, uint32_t timeout_ms, GnVpnCommand *command,
                        uint8_t *packet, size_t capacity);

/* Echo the original command token and a settled native outcome. Error details
 * are optional UTF-8 for failed operations. Removal asserts absence of the
 * original routes, including effects from late platform callbacks.
 */
int32_t gnunet_vpn_route_complete(const GnVpn *vpn, GnVpnToken token, uint32_t outcome,
                                 GnBytes diagnostic);
#if !defined(_WIN32)
/* Successful install in descriptor mode. Rust duplicates the original live
 * nonblocking raw IP descriptor during this call. The application owns its
 * original system resource and keeps it through route removal.
 */
int32_t gnunet_vpn_install_descriptor(const GnVpn *vpn, GnVpnToken token, int32_t fd);
#endif
int32_t gnunet_vpn_write_complete(const GnVpn *vpn, GnVpnToken token, uint32_t outcome,
                                 GnBytes diagnostic);
/* Submit one complete raw packet in application mode. WOULD_BLOCK preserves
 * application ownership. Packets are copied only after admission.
 */
int32_t gnunet_vpn_receive(const GnVpn *vpn, const uint8_t *packet, size_t size);
/* Permanently fence new packet I/O on this handle. Idempotent. Original routing
 * commands and claimed writes can still complete. Request node stop separately
 * and continue servicing route commands through native retirement.
 */
int32_t gnunet_vpn_fence(const GnVpn *vpn);
/* Fence the source. Report routes_absent=1 only after actual native removal. */
int32_t gnunet_vpn_revoke(const GnVpn *vpn, uint32_t routes_absent, GnBytes diagnostic);

/* Release this control handle. Exclude destruction from all other calls.
 * For orderly stop, request node stop, service final native route commands,
 * then join/destroy the node and release the original control handle.
 */
void gnunet_vpn_destroy(GnVpn *vpn);

/* Stops are idempotent. The handle remains live while readiness and retirement
 * are observed. Stop, network notification, snapshot and error may run
 * concurrently. Exclude destroy from all other access to the same handle.
 */
int32_t gnunet_node_stop(GnNode *node);

/* Request an address rescan of a starting or running worker. Returns once the
 * notification is accepted. Pending notices may be coalesced. This is a no-op
 * for workers that are stopping or terminal.
 */
int32_t gnunet_node_notify_network_change(const GnNode *node);

/* Supply the current network's DNS endpoints in the same UTF-8 syntax as
 * GnNodeOptions.dns_servers. An empty range revokes upstreams. The worker
 * copies the list and can coalesce updates before applying it. Also requests
 * an address rescan. A stopping or terminal worker discards the snapshot.
 */
int32_t gnunet_node_set_dns_servers(const GnNode *node, GnBytes dns_servers);

/* Ready ports are the original local bindings. Zero marks an absent listener. */
int32_t gnunet_node_snapshot(const GnNode *node, GnNodeSnapshot *out);

/* Returns the total UTF-8 diagnostic length. Copies at most capacity bytes
 * without adding a NUL terminator. Query with a null pointer and zero capacity.
 * Read the complete byte range to decode UTF-8. A terminal failure is immutable.
 */
size_t gnunet_node_error(const GnNode *node, uint8_t *out, size_t capacity);

/* Consumes the handle, requests stop and joins the original worker. Runs on
 * a background queue. A null handle is accepted.
 */
void gnunet_node_destroy(GnNode *node);

#ifdef __cplusplus
}
#endif

#endif
