import type { NodeOptions, NodeSnapshot, VpnCommand, VpnRouteToken } from 'libgnunet_node.so';

export enum Command {
  Start,
  Snapshot,
  Stop,
  Close,
  NetworkChange,
  DnsServers,
  VpnNext,
  VpnComplete,
  VpnRevoke
}

export enum VpnCommandKind {
  Install = 1,
  Remove = 2,
  Closed = 4
}

export enum VpnRouteOutcome {
  Removed = 2,
  Failed = 3,
  FailedAbsent = 4
}

export interface VpnCompletion {
  token: VpnRouteToken;
  fd?: number;
  outcome?: VpnRouteOutcome;
}

export interface VpnRequest {
  maximumPacket?: number;
  completion?: VpnCompletion;
  routesAbsent?: boolean;
}

export interface Request {
  id: number;
  command: Command;
  options?: NodeOptions;
  dnsServers?: string;
  vpn?: VpnRequest;
}

export interface Reply {
  id: number;
  snapshot?: NodeSnapshot;
  vpnCommand?: VpnCommand;
  error?: string;
}
