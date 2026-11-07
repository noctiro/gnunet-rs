# Source and scope

Normative revision: GNUnet v0.29.1, `346358e26d4dcc2dc4f51bef5d52dca29c7d8165`.

Source inputs include `src/service/util/gnunet-service-resolver.c`,
`gnunet_resolver_service.h`, `resolver.h`, `resolver_api.c`, `dnsstub.c`,
`dnsparser.c`, the generic service source/header, defaults and Meson graph.
`official-profile.json` retains their identities and requirement anchors.

The daemon uses direct DNSPARSER/DNSSTUB queries, a process-wide cache,128 default stub slots, one30s lookup deadline, startup literal hosts/resolv.conf inputs and generic service NONE shutdown. It does not use libc NSS lookup as a substitute DNS backend. Public local-FQDN helpers are a distinct client/native profile. DNS interception/TUN/helper is another service and is outside this implementation.

Core source preserves section order, asymmetric case policy, strict expiry, temporary1025th bucket, no negative cache/coalescing, CNAME order/fresh timer and Any second-phase deadline/failure behavior. Bounded memory/CNAME work refusal, typed staging/lease lifetimes, generation isolation and evicted-token detachment are explicit Rust resource/ownership policies. They never invent wire fields or successful output.

All new evidence here is pure Rust only. C-only historical local/no-IP and30s observations remain explicitly labeled in api-status.json. Real Resolver daemon UDP/IPC integration and normal C public-client equivalence are pending; the result is not a verified whole service. A native IDNA capability is supplied explicitly rather than represented by the test-only ASCII implementation.
