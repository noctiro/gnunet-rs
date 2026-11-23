#ifndef GNUNET_DNS_PROXY_SDK_H
#define GNUNET_DNS_PROXY_SDK_H

#include "gnunet_node.h"

#if defined(__BLOCKS__)
#ifdef __cplusplus
extern "C" {
#endif

typedef struct GnDnsProxy GnDnsProxy;
typedef struct GnDnsProxyPaths {
    GnBytes configuration;
    GnBytes resources;
    GnBytes binaries;
} GnDnsProxyPaths;

/* iOS 18+ app extension entry. Lend the original NEDNSProxyProvider object
 * and a start block receiving the native NSError pointer on failure. Paths
 * are absolute UTF-8 and copied by the call. Success transfers one host handle
 * and ownership of the completion; the block can run before start returns.
 * If submission fails, *out is null and the caller completes its own block.
 */
int32_t gnunet_dns_proxy_start(const GnDnsProxyPaths *paths, void *provider,
                               void (^completion)(void *error), GnDnsProxy **out);

/* Lend the original callback's provider and NEAppProxyFlow. The host retains
 * the flow on a true verdict. Returning false leaves it with NetworkExtension.
 */
int32_t gnunet_dns_proxy_accept(const GnDnsProxy *proxy, void *provider, void *flow);

/* Close admission from the original platform stop callback. A failed
 * submission asks the worker to terminate and reports failure. */
int32_t gnunet_dns_proxy_stop(const GnDnsProxy *proxy, void *provider, intptr_t reason);

/* Consume after a stop request or failed startup, excluding concurrent use.
 * Call on a separate thread. Success requires confirmed native retirement
 * and worker termination. Keep the original platform stop completion until
 * this returns success. */
int32_t gnunet_dns_proxy_join(GnDnsProxy *proxy);

#ifdef __cplusplus
}
#endif
#endif
#endif
