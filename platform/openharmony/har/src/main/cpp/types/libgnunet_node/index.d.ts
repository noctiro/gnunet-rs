export interface NodeOptions {
  stateDir: string;
  ipcDir: string;
  configFile?: string;
  /** Optional immutable app-private generation containing a hellos directory. */
  bootstrapDataDir?: string;
  tcpBind: string;
  udp4Bind: string;
  udp6Bind?: string;
  dnsServers?: string;
  startupTimeoutMs: number;
  drainTimeoutMs: number;
}

export interface NodeSnapshot {
  phase: number;
  hasReady: boolean;
  /** The verified peer identity at initial readiness. */
  peer: Uint8Array;
  tcpPort: number;
  udp4Port: number;
  udp6Port: number;
  quicPort: number;
  http3Port: number;
  unixMtu: number;
  error?: string;
}

export interface NativeNode {
  snapshot(): NodeSnapshot;
  requestStop(): void;
  notifyNetworkChange(): void;
  /** Whitespace-separated numeric endpoints; an empty string clears the upstreams. */
  setDnsServers(servers: string): void;
  vpnNext(): VpnCommand | undefined;
  vpnInstalled(token: VpnRouteToken, fd: number): void;
  vpnComplete(token: VpnRouteToken, outcome: number): void;
  vpnRevoke(routesAbsent: boolean): void;
  close(): void;
}

export interface VpnRouteToken {
  /** Exact unsigned 64-bit values, encoded as decimal across Workers. */
  epoch: string;
  revision: string;
}

export interface VpnPrefix {
  bits: number;
  network: string;
  interfaceAddress: string;
}

export interface VpnCommand extends VpnRouteToken {
  kind: number;
  mtu: number;
  ipv4?: VpnPrefix;
  ipv6?: VpnPrefix;
}

interface NativeModule {
  start(options: NodeOptions): NativeNode;
  /** Worker entry, after the ability has reserved and protected the process. */
  startVpn(options: NodeOptions, maximumPacket: number): NativeNode;
  reserveVpnProcess(): void;
  releaseVpnProcess(): void;
  /** Resolve the callback's interface name; zero means unavailable or invalid. */
  interfaceIndex(interfaceName: string): number;
}

declare const nativeModule: NativeModule;
export default nativeModule;
