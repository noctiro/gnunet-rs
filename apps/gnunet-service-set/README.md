# Normal generic SET service

This standard SERVICE entrypoint composes the independent old generic SET core
with the bounded CADET host. It uses the `set` endpoint and its original
union/intersection formats, including explicit C ABI placement and native IBF
columns. It does not redirect public SET operations to SETI or SETU.

Official options/configuration, inherited listeners, configured process identity,
ACL/kernel-credential admission, one shared clock, explicitly driven Resolver,
finite startup and independent shutdown use the shared process facilities. READY
requires CADET MQ attachment. No fixed main port, RPS sampler or discovery
actor is started. Client Listen opens only its exact requested application port.

An accepted incoming operation retains its original physical CADET channel when
ownership transfers to its accepting set; later listener retirement leaves that
accepted operation alive. Original effect and partial/whole-write facts remain
separate from remote completion. There is no invented cancellation ACK.
