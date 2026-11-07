use super::*;
#[derive(Debug)]
pub(super) struct Stamp {
    pub(super) _marker: u8,
}
macro_rules! handle {
    ($name:ident,$doc:literal) => {
        #[doc=$doc]
        #[derive(Clone, Debug)]
        pub struct $name {
            pub(super) owner: Rc<Stamp>,
            pub(super) serial: u64,
        }
        impl PartialEq for $name {
            fn eq(&self, o: &Self) -> bool {
                Rc::ptr_eq(&self.owner, &o.owner) && self.serial == o.serial
            }
        }
        impl Eq for $name {}
        impl $name {
            /// Diagnostic local generation, never a private wire field.
            #[must_use]
            pub const fn value(&self) -> u64 {
                self.serial
            }
        }
    };
}
handle!(
    Source,
    "One actual CADET MQ attachment, retired before a replacement attaches."
);
handle!(
    Tun,
    "One actual verified TUN/device attachment, retired before replacement."
);
handle!(
    Flow,
    "One actual original accepted CADET channel, never a naked wire number."
);
handle!(
    Input,
    "One original accepted VPN frame awaiting actual processing receipt."
);
handle!(
    Write,
    "One immutable original output lease, scoped to this EXIT instance."
);
handle!(
    Dns,
    "One exact original external DNS/socket request and its real results."
);
/// Explicit bounded capacities; allocations follow actual use, never a thread.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Live/quarantined flow metadata slots.
    pub flows: usize,
    /// Global exact ready-inner receipts retained until the actual outer ACK.
    /// Native owners reserve channels*maximum-inner-frames within this bound.
    pub processing_receipts: usize,
    /// Immutable output records shared across TUN and CADET.
    pub output_frames: usize,
    /// Exact retained wire/IP bytes across both queues.
    pub output_bytes: usize,
    /// Maximum complete raw IP packet (no jumbo packets).
    pub packet_bytes: usize,
    /// Maximum complete CADET application frame.
    pub peer_bytes: usize,
    /// Maximum actual DNS packet on the optional DNS port.
    pub dns_bytes: usize,
    /// Bounded entropy/collision attempts per NAT allocation.
    pub entropy_draws: u16,
    /// Idle expiry in caller monotonic microseconds.
    pub idle: u64,
    /// Original frame processing/socket deadline in microseconds.
    pub input_lifetime: u64,
    /// NAT tuple reuse quarantine after real source/IO retirement.
    pub quarantine: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            flows: 256,
            processing_receipts: 16_384,
            output_frames: 512,
            output_bytes: 8 * 1024 * 1024,
            packet_bytes: 65535,
            peer_bytes: gnunet_wire::official::cadet::MAX_APPLICATION_MESSAGE_SIZE,
            dns_bytes: 4096,
            entropy_draws: 64,
            idle: 300_000_000,
            input_lifetime: 30_000_000,
            quarantine: 120_000_000,
        }
    }
}
impl Limits {
    pub(super) fn validate(self) -> Result<(), Error> {
        if self.flows == 0
            || self.processing_receipts == 0
            || self.output_frames == 0
            || self.output_bytes < 64
            || !(60..=65535).contains(&self.packet_bytes)
            || !(28..=65535).contains(&self.peer_bytes)
            || !(12..=65531).contains(&self.dns_bytes)
            || self.entropy_draws == 0
            || self.idle == 0
            || self.idle == u64::MAX
            || self.input_lifetime == 0
            || self.input_lifetime == u64::MAX
            || self.quarantine == u64::MAX
        {
            return Err(Error::Capacity);
        }
        Ok(())
    }
}
/// Explicit configured real local service target, selected by its actual bound
/// CADET descriptor/port and the first actual TCP/UDP service message. A hash
/// may have one TCP and one UDP target; duplicate hash+protocol is rejected.
/// The supplied descriptor grants no authentication.
#[derive(Clone, Copy, Debug)]
pub struct Service {
    /// Actual official service CADET port hash.
    pub port: [u8; 64],
    /// Configured target address and real host-order destination port.
    pub target: Endpoint,
    /// Configured TCP or UDP transport.
    pub protocol: Protocol,
}
/// Actual port on which a native adapter accepted this original channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Target {
    /// Actual Internet gateway family port.
    Internet(Family),
    /// Actual configured service hash.
    Service([u8; 64]),
    /// Actual optional official DNS exit port.
    Dns,
}
/// Explicit capability and source pool configuration, borrowed for this engine.
#[derive(Clone, Copy)]
pub struct Config<'a> {
    /// Enabled Internet families and the explicit authorization source.
    pub policy: Policy<'a>,
    /// Actual provisioned IPv4 source pool, if supported.
    pub ipv4: Option<Pool>,
    /// Actual provisioned IPv6 source pool, if supported.
    pub ipv6: Option<Pool>,
    /// Explicit local service targets.
    pub services: &'a [Service],
    /// Optional actual DNS external request capability.
    pub dns: bool,
    /// Actual remote-C AF profile. No private negotiation is added.
    pub af: AfProfile,
}
/// Kernel-observed TCP lifecycle, without inventing endpoint sequencing/ACKs.
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpState {
    /// Original VPN SYN was actually admitted.
    pub syn: bool,
    /// Actual matching SYN+ACK arrived from TUN.
    pub established: bool,
    /// Actual VPN FIN segment observed.
    pub vpn_fin: bool,
    /// Actual remote FIN segment observed.
    pub remote_fin: bool,
    /// An actual endpoint RST segment observed.
    pub reset: bool,
}
/// Readonly exact flow metadata, not remote delivery evidence.
#[derive(Clone, Debug)]
pub struct Info {
    /// Original actual CADET source.
    pub source: Source,
    /// Actual peer supplied by the native CADET channel.
    pub peer: [u8; 32],
    /// Original actual bound target.
    pub target: Target,
    /// Actual NAT tuple after first forwarding request.
    pub tuple: Option<Tuple>,
    /// True after a logical close request.
    pub closing: bool,
    /// True only after real peer close/source-loss callback.
    pub peer_closed: bool,
    /// Actual observed TCP flags.
    pub tcp: TcpState,
}
/// Immutable output on its original actual source.
pub struct Output<'a> {
    /// Exact original lease.
    pub write: Write,
    /// Original channel association.
    pub flow: Flow,
    /// Exact immutable original complete packet/message.
    pub bytes: &'a [u8],
    /// Original finite caller-clock target, set once at packet/message admission.
    pub expires: MonoInstant,
}
/// Original external action or processing observation. No variant fabricates a
/// peer acceptance, native send/close result, DNS response or receive_done ACK.
pub enum Effect<'a> {
    /// Physically close the original CADET MQ during explicit shutdown; a
    /// logical stop does not retire pending bytes. Then call source_lost.
    CloseSource {
        /// Exact original actual source.
        source: Source,
    },
    /// Physically close the original TUN during explicit shutdown; use tun_lost
    /// with the real pending/unknown-write outcome after actual FD retirement.
    CloseTun {
        /// Exact original actual device.
        tun: Tun,
    },
    /// Physically close this original actual CADET channel.
    Close {
        /// Original channel ownership.
        flow: Flow,
    },
    /// Every forwarding effect for this exact original VPN input is
    /// actually written. Host aggregates original outer DATA deliveries, then calls
    /// acknowledged only after that actual native receive_done frame completes.
    Processed {
        /// Original channel.
        flow: Flow,
        /// Original input receipt; never serialized.
        input: Input,
    },
    /// Submit this original exact DNS query on the real bounded DNS port.
    DnsQuery {
        /// Original actual channel.
        flow: Flow,
        /// Original external socket request scope.
        job: Dns,
        /// Original immutable query with explicit unique transaction ID.
        packet: &'a [u8],
        /// Original request target; retry/queue admission must never renew it.
        expires: MonoInstant,
    },
    /// Cancel/close/drain this exact admitted DNS socket request;
    /// only dns_retired settles its actual original port ownership.
    DnsCancel {
        /// Original socket operation.
        job: Dns,
    },
}
/// True original closure/failure observation; protocol status is never invented.
#[derive(Clone, Debug)]
pub struct Closed {
    /// Original channel.
    pub flow: Flow,
    /// Original cause, None for actual caller close.
    pub failure: Option<Error>,
}
