import { connection } from '@kit.NetworkKit';
import type { VpnCommand, VpnPrefix } from 'libgnunet_node.so';
import { Command, Reply, VpnCommandKind, VpnRequest, VpnRouteOutcome } from './NodeMessages';
import { VpnResources, VpnRoutePlan } from './VpnResources';
import type { DefaultNetworkDnsOptions } from './DefaultNetworkDns';

export interface VpnNodeOptions {
  /** The OpenHarmony VPN route interface for the application deployment. */
  routeInterface: string;
  maximumPacket: number;
  dnsAddresses?: string[];
  /** Optional permission to use OS-qualified non-VPN DNS, with original errors. */
  upstreamNetwork?: DefaultNetworkDnsOptions;
}

type Exchange = (command: Command, request?: VpnRequest) => Promise<Reply>;

/**
 * Route operations are serialized on the ability isolate. The Worker owns the
 * controller only. It lends the framework fd once to the Rust packet owner.
 */
export class NodeVpn {
  private readonly resources: VpnResources;
  private readonly routeInterface: string;
  private readonly dnsAddresses: string[];
  private readonly exchange: Exchange;
  private readonly waitForFailedWorker: () => Promise<void>;
  private failure?: Error;

  constructor(resources: VpnResources, options: VpnNodeOptions, exchange: Exchange,
    waitForFailedWorker: () => Promise<void>) {
    if (options.routeInterface.length === 0 || options.routeInterface.length > 64 ||
      options.routeInterface.indexOf('\0') >= 0 || !Number.isInteger(options.maximumPacket) ||
      options.maximumPacket < 576 || options.maximumPacket > 1500 ||
      (options.dnsAddresses !== undefined && options.dnsAddresses.length > 32)) {
      throw new Error('Invalid OpenHarmony VPN interface or packet bounds');
    }
    this.resources = resources;
    this.routeInterface = options.routeInterface;
    this.dnsAddresses = options.dnsAddresses?.slice() ?? [];
    this.exchange = exchange;
    this.waitForFailedWorker = waitForFailedWorker;
  }

  async run(): Promise<void> {
    try {
      while (true) {
        const reply = await this.exchange(Command.VpnNext);
        const command = reply.vpnCommand;
        if (command === undefined) continue;
        switch (command.kind) {
          case VpnCommandKind.Install:
            await this.install(command);
            break;
          case VpnCommandKind.Remove:
            await this.remove(command);
            break;
          case VpnCommandKind.Closed:
            await this.close();
            return;
          default:
            throw new Error('Unexpected GNUnet descriptor-mode command');
        }
      }
    } catch (cause) {
      this.failure = cause as Error;
      const absent = await this.retirePhysical();
      await this.exchange(Command.VpnRevoke, { routesAbsent: absent });
    }
  }

  /**
   * Worker termination can race a native platform Promise. Retire the original
   * VpnConnection even when its Worker cannot accept any further completions.
   */
  async close(): Promise<void> {
    await this.waitForFailedWorker();
    await this.resources.close();
  }

  error(): Error | undefined {
    return this.failure;
  }

  private async install(command: VpnCommand): Promise<void> {
    try {
      const fd = await this.resources.apply(this.plan(command));
      await this.exchange(Command.VpnComplete, { completion: { token: command, fd: fd } });
    } catch (cause) {
      this.failure = cause as Error;
      const absent = await this.retirePhysical();
      await this.exchange(Command.VpnComplete, { completion: {
        token: command, outcome: absent ? VpnRouteOutcome.FailedAbsent : VpnRouteOutcome.Failed
      } });
    }
  }

  private async remove(command: VpnCommand): Promise<void> {
    const absent = await this.retirePhysical();
    await this.exchange(Command.VpnComplete, { completion: {
      token: command, outcome: absent ? VpnRouteOutcome.Removed : VpnRouteOutcome.Failed
    } });
  }

  private async retirePhysical(): Promise<boolean> {
    try {
      await this.close();
      return true;
    } catch (cause) {
      if (this.failure === undefined) this.failure = cause as Error;
      return false;
    }
  }

  private plan(command: VpnCommand): VpnRoutePlan {
    const plan: VpnRoutePlan = { addresses: [], routes: [], dnsAddresses: this.dnsAddresses, mtu: command.mtu };
    if (command.ipv4 !== undefined) this.addPrefix(plan, command.ipv4, 1, '0.0.0.0');
    if (command.ipv6 !== undefined) this.addPrefix(plan, command.ipv6, 2, '::');
    return plan;
  }

  private addPrefix(plan: VpnRoutePlan, prefix: VpnPrefix, family: number, zero: string): void {
    const address: connection.NetAddress = { address: prefix.interfaceAddress, family: family };
    const destination: connection.NetAddress = { address: prefix.network, family: family };
    plan.addresses.push({ address: address, prefixLength: prefix.bits });
    plan.routes.push({
      interface: this.routeInterface,
      destination: { address: destination, prefixLength: prefix.bits },
      gateway: { address: zero, family: family },
      hasGateway: false,
      isDefaultRoute: prefix.bits === 0
    });
  }
}
