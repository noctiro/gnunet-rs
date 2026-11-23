#include "gnunet_node.h"
#include "napi/native_api.h"

#include <algorithm>
#include <arpa/inet.h>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <exception>
#include <limits>
#include <memory>
#include <mutex>
#include <net/if.h>
#include <string>

namespace {

constexpr std::size_t max_option_bytes = 65535;
const napi_type_tag node_tag{0x354261E242124997, 0x99DA0B8A04D3FB58};

void destroy_node(GnNode* node)
{
    if (node != nullptr) {
        gnunet_node_destroy(node);
    }
}

using Node = std::unique_ptr<GnNode, decltype(&destroy_node)>;
using Vpn = std::unique_ptr<GnVpn, decltype(&gnunet_vpn_destroy)>;

enum class ProcessVpn { Unreserved, Reserved, Running, Retired };
std::mutex process_mutex;
ProcessVpn process_vpn = ProcessVpn::Unreserved;
std::size_t ordinary_nodes = 0;

struct Owner {
    Node node{nullptr, destroy_node};
    Vpn vpn{nullptr, gnunet_vpn_destroy};
    bool claimed = false;
    bool exclusive = false;

    bool claim(bool wants_vpn)
    {
        std::lock_guard lock(process_mutex);
        if (wants_vpn) {
            if (process_vpn != ProcessVpn::Reserved) return false;
            process_vpn = ProcessVpn::Running;
        } else {
            if (process_vpn != ProcessVpn::Unreserved) return false;
            ++ordinary_nodes;
        }
        exclusive = wants_vpn;
        claimed = true;
        return true;
    }

    void close()
    {
        // When a Worker fails, dropping the controller first fences packets
        // and lets the native owner see uncertainty during its bounded drain.
        vpn.reset();
        node.reset();
        if (claimed) {
            std::lock_guard lock(process_mutex);
            if (exclusive) {
                process_vpn = ProcessVpn::Reserved;
            } else {
                --ordinary_nodes;
            }
            claimed = false;
        }
    }

    ~Owner() { close(); }
};

napi_value fail(napi_env env, const char* error)
{
    napi_throw_error(env, nullptr, error);
    return nullptr;
}

template <napi_callback Callback>
napi_value guarded(napi_env env, napi_callback_info info) noexcept
{
    try {
        return Callback(env, info);
    } catch (const std::exception& error) {
        return fail(env, error.what());
    } catch (...) {
        return fail(env, "GNUnet native binding failed");
    }
}

bool read_string(napi_env env, napi_value value, std::string& out)
{
    napi_valuetype type;
    std::size_t size = 0;
    if (napi_typeof(env, value, &type) != napi_ok || type != napi_string ||
        napi_get_value_string_utf8(env, value, nullptr, 0, &size) != napi_ok ||
        size > max_option_bytes) {
        return false;
    }
    out.resize(size + 1);
    std::size_t used = 0;
    if (napi_get_value_string_utf8(env, value, out.data(), out.size(), &used) != napi_ok ||
        used != size) {
        return false;
    }
    out.resize(used);
    return out.find('\0') == std::string::npos;
}

bool read_text(napi_env env, napi_value options, const char* name, bool optional, std::string& out)
{
    napi_value value;
    napi_valuetype type;
    if (napi_get_named_property(env, options, name, &value) != napi_ok ||
        napi_typeof(env, value, &type) != napi_ok) {
        return false;
    }
    if (optional && type == napi_undefined) {
        return true;
    }
    return read_string(env, value, out) && (optional || !out.empty());
}

bool read_uint(napi_env env, napi_value value, std::uint32_t minimum, std::uint32_t maximum,
               std::uint32_t& out)
{
    double number;
    if (napi_get_value_double(env, value, &number) != napi_ok || !std::isfinite(number) ||
        number < minimum || number > maximum || std::trunc(number) != number) {
        return false;
    }
    out = static_cast<std::uint32_t>(number);
    return true;
}

bool read_timeout(napi_env env, napi_value options, const char* name, std::uint32_t& out)
{
    napi_value value;
    return napi_get_named_property(env, options, name, &value) == napi_ok &&
           read_uint(env, value, 1, std::numeric_limits<std::uint32_t>::max(), out);
}

GnBytes bytes(const std::string& text)
{
    return {text.empty() ? nullptr : reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
}

bool read_options(napi_env env, napi_value value, GnNodeOptions& options, std::string (&text)[8])
{
    if (!read_text(env, value, "stateDir", false, text[0]) ||
        !read_text(env, value, "ipcDir", false, text[1]) ||
        !read_text(env, value, "configFile", true, text[2]) ||
        !read_text(env, value, "tcpBind", false, text[3]) ||
        !read_text(env, value, "udp4Bind", false, text[4]) ||
        !read_text(env, value, "udp6Bind", true, text[5]) ||
        !read_text(env, value, "dnsServers", true, text[6]) ||
        !read_text(env, value, "bootstrapDataDir", true, text[7]) ||
        !read_timeout(env, value, "startupTimeoutMs", options.startup_timeout_ms) ||
        !read_timeout(env, value, "drainTimeoutMs", options.drain_timeout_ms)) {
        return false;
    }
    options.state_dir = bytes(text[0]);
    options.ipc_dir = bytes(text[1]);
    options.config_file = bytes(text[2]);
    options.tcp_bind = bytes(text[3]);
    options.udp4_bind = bytes(text[4]);
    options.udp6_bind = bytes(text[5]);
    options.dns_servers = bytes(text[6]);
    options.bootstrap_data_dir = bytes(text[7]);
    return true;
}

Owner* receiver(napi_env env, napi_callback_info info)
{
    napi_value self;
    bool tagged = false;
    void* value = nullptr;
    if (napi_get_cb_info(env, info, nullptr, nullptr, &self, nullptr) != napi_ok ||
        napi_check_object_type_tag(env, self, &node_tag, &tagged) != napi_ok || !tagged ||
        napi_unwrap(env, self, &value) != napi_ok) {
        fail(env, "Expected an original GNUnet node owner");
        return nullptr;
    }
    return static_cast<Owner*>(value);
}

bool set_number(napi_env env, napi_value object, const char* name, std::uint32_t number)
{
    napi_value value;
    return napi_create_uint32(env, number, &value) == napi_ok &&
           napi_set_named_property(env, object, name, value) == napi_ok;
}

bool set_text(napi_env env, napi_value object, const char* name, const std::string& text)
{
    napi_value value;
    return napi_create_string_utf8(env, text.data(), text.size(), &value) == napi_ok &&
           napi_set_named_property(env, object, name, value) == napi_ok;
}

napi_value undefined(napi_env env)
{
    napi_value value;
    return napi_get_undefined(env, &value) == napi_ok ? value : nullptr;
}

bool set_prefix(napi_env env, napi_value object, const char* name, const GnVpnPrefix& prefix)
{
    if (prefix.family == 0) return true;
    const int family = prefix.family == 4 ? AF_INET : AF_INET6;
    char network[INET6_ADDRSTRLEN];
    char interface_ip[INET6_ADDRSTRLEN];
    napi_value value;
    return inet_ntop(family, prefix.network, network, sizeof(network)) != nullptr &&
           inet_ntop(family, prefix.interface_address, interface_ip, sizeof(interface_ip)) != nullptr &&
           napi_create_object(env, &value) == napi_ok &&
           set_number(env, value, "bits", prefix.bits) &&
           set_text(env, value, "network", network) &&
           set_text(env, value, "interfaceAddress", interface_ip) &&
           napi_set_named_property(env, object, name, value) == napi_ok;
}

bool read_token_word(napi_env env, napi_value object, const char* name, std::uint64_t& word)
{
    std::string digits;
    if (!read_text(env, object, name, false, digits) || digits.size() > 20) return false;
    const auto end = digits.data() + digits.size();
    const auto parsed = std::from_chars(digits.data(), end, word);
    return parsed.ec == std::errc{} && parsed.ptr == end && word != 0;
}

bool read_token(napi_env env, napi_value object, GnVpnToken& token)
{
    return read_token_word(env, object, "epoch", token.epoch) &&
           read_token_word(env, object, "revision", token.revision);
}

napi_value vpn_next(napi_env env, napi_callback_info info)
{
    const auto* owner = receiver(env, info);
    if (owner == nullptr) return nullptr;
    if (!owner->vpn) return fail(env, "GNUnet VPN is closed");
    GnVpnCommand original{};
    // This wait belongs on the dedicated Worker, never the ability event loop.
    const auto result = gnunet_vpn_next(owner->vpn.get(), 100, &original, nullptr, 0);
    if (result == GNUNET_VPN_WAIT) return undefined(env);
    if (result != GNUNET_NODE_OK || (original.kind != GNUNET_VPN_APPLY_ROUTES &&
        original.kind != GNUNET_VPN_REMOVE_ROUTES && original.kind != GNUNET_VPN_CLOSED)) {
        return fail(env, "GNUnet VPN could not claim a descriptor command");
    }
    napi_value object;
    if (napi_create_object(env, &object) != napi_ok ||
        !set_number(env, object, "kind", original.kind) ||
        !set_number(env, object, "mtu", original.mtu) ||
        !set_text(env, object, "epoch", std::to_string(original.token.epoch)) ||
        !set_text(env, object, "revision", std::to_string(original.token.revision)) ||
        !set_prefix(env, object, "ipv4", original.ipv4) ||
        !set_prefix(env, object, "ipv6", original.ipv6)) {
        return fail(env, "GNUnet VPN could not return its original command");
    }
    return object;
}

napi_value vpn_installed(napi_env env, napi_callback_info info)
{
    const auto* owner = receiver(env, info);
    if (owner == nullptr) return nullptr;
    std::size_t argc = 2;
    napi_value argv[2];
    std::uint32_t fd;
    GnVpnToken token{};
    if (!owner->vpn || napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok ||
        argc != 2 || !read_token(env, argv[0], token) ||
        !read_uint(env, argv[1], 0, std::numeric_limits<std::int32_t>::max(), fd) ||
        gnunet_vpn_install_descriptor(owner->vpn.get(), token, static_cast<std::int32_t>(fd)) != GNUNET_NODE_OK) {
        return fail(env, "GNUnet VPN did not accept the original descriptor");
    }
    return undefined(env);
}

napi_value vpn_complete(napi_env env, napi_callback_info info)
{
    const auto* owner = receiver(env, info);
    if (owner == nullptr) return nullptr;
    std::size_t argc = 2;
    napi_value argv[2];
    std::uint32_t outcome;
    GnVpnToken token{};
    if (!owner->vpn || napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok ||
        argc != 2 || !read_token(env, argv[0], token) ||
        !read_uint(env, argv[1], GNUNET_VPN_ROUTES_REMOVED, GNUNET_VPN_ROUTES_FAILED_ABSENT, outcome) ||
        gnunet_vpn_route_complete(owner->vpn.get(), token, outcome, {}) != GNUNET_NODE_OK) {
        return fail(env, "GNUnet VPN did not accept the original route result");
    }
    return undefined(env);
}

napi_value vpn_revoke(napi_env env, napi_callback_info info)
{
    const auto* owner = receiver(env, info);
    if (owner == nullptr) return nullptr;
    std::size_t argc = 1;
    napi_value value;
    bool absent;
    if (!owner->vpn || napi_get_cb_info(env, info, &argc, &value, nullptr, nullptr) != napi_ok ||
        argc != 1 || napi_get_value_bool(env, value, &absent) != napi_ok ||
        gnunet_vpn_revoke(owner->vpn.get(), absent, {}) != GNUNET_NODE_OK) {
        return fail(env, "GNUnet VPN source could not be revoked");
    }
    return undefined(env);
}

napi_value snapshot(napi_env env, napi_callback_info info)
{
    const auto* owner = receiver(env, info);
    if (owner == nullptr) {
        return nullptr;
    }
    GnNodeSnapshot state{};
    if (!owner->node || gnunet_node_snapshot(owner->node.get(), &state) != GNUNET_NODE_OK) {
        return fail(env, "GNUnet node is closed or could not be observed");
    }
    napi_value object;
    napi_value has_ready;
    napi_value peer_buffer;
    napi_value peer;
    void* peer_bytes;
    if (napi_create_object(env, &object) != napi_ok ||
        napi_get_boolean(env, state.has_ready != 0, &has_ready) != napi_ok ||
        napi_set_named_property(env, object, "hasReady", has_ready) != napi_ok ||
        !set_number(env, object, "phase", state.phase) ||
        !set_number(env, object, "tcpPort", state.tcp_port) ||
        !set_number(env, object, "udp4Port", state.udp4_port) ||
        !set_number(env, object, "udp6Port", state.udp6_port) ||
        !set_number(env, object, "quicPort", state.quic_port) ||
        !set_number(env, object, "http3Port", state.http3_port) ||
        !set_number(env, object, "unixMtu", state.unix_mtu) ||
        napi_create_arraybuffer(env, sizeof(state.peer), &peer_bytes, &peer_buffer) != napi_ok ||
        napi_create_typedarray(env, napi_uint8_array, sizeof(state.peer), peer_buffer, 0, &peer) != napi_ok ||
        napi_set_named_property(env, object, "peer", peer) != napi_ok) {
        return fail(env, "Could not return the GNUnet node snapshot");
    }
    std::memcpy(peer_bytes, state.peer, sizeof(state.peer));
    if (state.phase == GNUNET_NODE_FAILED) {
        const auto size = gnunet_node_error(owner->node.get(), nullptr, 0);
        std::string message(size, '\0');
        const auto received = gnunet_node_error(
            owner->node.get(), reinterpret_cast<std::uint8_t*>(message.data()), message.size());
        napi_value error;
        if (napi_create_string_utf8(env, message.data(), std::min(size, received), &error) != napi_ok ||
            napi_set_named_property(env, object, "error", error) != napi_ok) {
            return fail(env, "Could not return the GNUnet node failure");
        }
    }
    return object;
}

napi_value close(napi_env env, napi_callback_info info)
{
    auto* owner = receiver(env, info);
    if (owner == nullptr) {
        return nullptr;
    }
    owner->close();
    return undefined(env);
}

napi_value stop(napi_env env, napi_callback_info info)
{
    const auto* owner = receiver(env, info);
    if (owner == nullptr) {
        return nullptr;
    }
    if (!owner->node || gnunet_node_stop(owner->node.get()) != GNUNET_NODE_OK) {
        return fail(env, "GNUnet node stop could not be requested");
    }
    napi_value undefined;
    if (napi_get_undefined(env, &undefined) != napi_ok) {
        return nullptr;
    }
    return undefined;
}

napi_value notify_network_change(napi_env env, napi_callback_info info)
{
    const auto* owner = receiver(env, info);
    if (owner == nullptr) {
        return nullptr;
    }
    if (!owner->node || gnunet_node_notify_network_change(owner->node.get()) != GNUNET_NODE_OK) {
        return fail(env, "GNUnet network change could not be reported");
    }
    napi_value undefined;
    if (napi_get_undefined(env, &undefined) != napi_ok) {
        return nullptr;
    }
    return undefined;
}

napi_value set_dns_servers(napi_env env, napi_callback_info info)
{
    const auto* owner = receiver(env, info);
    if (owner == nullptr) {
        return nullptr;
    }
    std::size_t argc = 1;
    napi_value argv[1];
    std::string servers;
    if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok || argc != 1 ||
        !read_string(env, argv[0], servers)) {
        return fail(env, "Expected a bounded UTF-8 DNS endpoint list");
    }
    if (!owner->node) {
        return fail(env, "GNUnet node is closed");
    }
    const auto status = gnunet_node_set_dns_servers(owner->node.get(), bytes(servers));
    if (status != GNUNET_NODE_OK) {
        return fail(env, status == GNUNET_NODE_INVALID ? "Invalid numeric DNS endpoint list" :
                                                                       "GNUnet DNS update was refused");
    }
    napi_value undefined;
    return napi_get_undefined(env, &undefined) == napi_ok ? undefined : nullptr;
}

napi_value interface_index(napi_env env, napi_callback_info info)
{
    std::size_t argc = 1;
    napi_value argv[1];
    napi_valuetype type;
    std::size_t size = 0;
    if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok || argc != 1 ||
        napi_typeof(env, argv[0], &type) != napi_ok || type != napi_string ||
        napi_get_value_string_utf8(env, argv[0], nullptr, 0, &size) != napi_ok) {
        return fail(env, "Expected an interface name");
    }
    // Reject a truncated name before asking the OS. Zero means the original
    // callback's interface could not be resolved, never a guessed zone.
    char name[IF_NAMESIZE]{};
    unsigned int index = 0;
    if (size != 0 && size < sizeof(name)) {
        std::size_t used = 0;
        if (napi_get_value_string_utf8(env, argv[0], name, sizeof(name), &used) != napi_ok ||
            used != size) {
            return fail(env, "Could not read the interface name");
        }
        if (std::memchr(name, '\0', used) == nullptr) {
            index = if_nametoindex(name);
        }
    }
    napi_value result;
    return napi_create_uint32(env, index, &result) == napi_ok ? result : nullptr;
}

void finalize(napi_env, void* data, void*)
{
    delete static_cast<Owner*>(data);
}

template <bool WithVpn>
napi_value start(napi_env env, napi_callback_info info)
{
    std::size_t argc = WithVpn ? 2 : 1;
    napi_value argv[2];
    GnNodeOptions options{};
    std::string text[8];
    std::uint32_t maximum = 0;
    if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok ||
        argc != (WithVpn ? 2 : 1) ||
        (WithVpn && !read_uint(env, argv[1], 576, 1500, maximum)) ||
        !read_options(env, argv[0], options, text)) {
        return fail(env, "Invalid GNUnet node options");
    }
    auto owner = std::make_unique<Owner>();
    if (!owner->claim(WithVpn)) return fail(env, "GNUnet start conflicts with the exclusive VPN process");
    GnNode* node = nullptr;
    std::int32_t result;
    if constexpr (WithVpn) {
        GnVpn* vpn = nullptr;
        const GnVpnOptions options_vpn{
            GNUNET_VPN_PEERS_LISTENING, GNUNET_VPN_UNIX_DESCRIPTOR, static_cast<std::uint16_t>(maximum), 0
        };
        result = gnunet_node_start_with_vpn(&options, &options_vpn, &node, &vpn);
        owner->vpn.reset(vpn);
    } else {
        result = gnunet_node_start(&options, &node);
    }
    owner->node.reset(node);
    if (result != GNUNET_NODE_OK || node == nullptr || (WithVpn && !owner->vpn)) {
        return fail(env, result == GNUNET_NODE_INVALID ? "Invalid GNUnet node configuration" :
                                                       "GNUnet node startup could not be scheduled");
    }

    napi_value object;
    const napi_property_descriptor members[] = {
        {"snapshot", nullptr, guarded<snapshot>, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"requestStop", nullptr, guarded<stop>, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"notifyNetworkChange", nullptr, guarded<notify_network_change>, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"setDnsServers", nullptr, guarded<set_dns_servers>, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"vpnNext", nullptr, guarded<vpn_next>, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"vpnInstalled", nullptr, guarded<vpn_installed>, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"vpnComplete", nullptr, guarded<vpn_complete>, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"vpnRevoke", nullptr, guarded<vpn_revoke>, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"close", nullptr, guarded<close>, nullptr, nullptr, nullptr, napi_default, nullptr},
    };
    if (napi_create_object(env, &object) != napi_ok ||
        napi_type_tag_object(env, object, &node_tag) != napi_ok ||
        napi_define_properties(env, object, sizeof(members) / sizeof(members[0]), members) != napi_ok ||
        napi_wrap(env, object, owner.get(), finalize, nullptr, nullptr) != napi_ok) {
        return fail(env, "Could not wrap the GNUnet node owner");
    }
    static_cast<void>(owner.release());
    return object;
}

template <bool Reserve>
napi_value vpn_process(napi_env env, napi_callback_info)
{
    {
        std::lock_guard lock(process_mutex);
        if constexpr (Reserve) {
            if ((process_vpn != ProcessVpn::Unreserved && process_vpn != ProcessVpn::Retired) ||
                ordinary_nodes != 0) {
                return fail(env, "The OpenHarmony VPN process already has a GNUnet owner");
            }
            process_vpn = ProcessVpn::Reserved;
        } else {
            if (process_vpn != ProcessVpn::Reserved) {
                return fail(env, "The original OpenHarmony VPN Worker must retire before release");
            }
            // The framework supplies no explicit process-unbind receipt.
            process_vpn = ProcessVpn::Retired;
        }
    }
    return undefined(env);
}

napi_value initialize(napi_env env, napi_value exports)
{
    const napi_property_descriptor entries[] = {
        {"start", nullptr, guarded<start<false>>, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"startVpn", nullptr, guarded<start<true>>, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"reserveVpnProcess", nullptr, guarded<vpn_process<true>>, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"releaseVpnProcess", nullptr, guarded<vpn_process<false>>, nullptr, nullptr, nullptr, napi_default, nullptr},
        {"interfaceIndex", nullptr, guarded<interface_index>, nullptr, nullptr, nullptr, napi_default, nullptr},
    };
    return napi_define_properties(env, exports, sizeof(entries) / sizeof(entries[0]), entries) == napi_ok
               ? exports
               : nullptr;
}

napi_module module = {
    .nm_version = 1,
    .nm_flags = 0,
    .nm_filename = nullptr,
    .nm_register_func = initialize,
    .nm_modname = "gnunet_node",
    .nm_priv = nullptr,
    .reserved = {nullptr},
};

__attribute__((constructor)) void register_module()
{
    napi_module_register(&module);
}

}  // namespace
