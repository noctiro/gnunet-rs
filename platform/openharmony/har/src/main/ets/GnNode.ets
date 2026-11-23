import { ErrorEvent, MessageEvents, worker } from '@kit.ArkTS';
import { vpnExtension } from '@kit.NetworkKit';
import nativeNode from 'libgnunet_node.so';
import type { NodeOptions, NodeSnapshot } from 'libgnunet_node.so';
import { Command, Reply, Request, VpnRequest } from './NodeMessages';
import { DefaultNetworkObserver, DefaultNetworkDnsOptions } from './DefaultNetworkDns';
import { NodeVpn, VpnNodeOptions } from './NodeVpn';
import { VpnResources } from './VpnResources';

export type { NodeOptions, NodeSnapshot } from 'libgnunet_node.so';
export type { DefaultNetworkDnsOptions } from './DefaultNetworkDns';
export type { VpnNodeOptions } from './NodeVpn';
export { IncludedHellos } from './IncludedHellos';

export enum NodePhase {
  Starting,
  Ready,
  Stopping,
  Stopped,
  Failed
}

interface Pending {
  resolve: (reply: Reply) => void;
  reject: (error: Error) => void;
}

function retainFailure(original: Error | undefined, next: Error): Error {
  return original === undefined || original === next ? next : new Error(`${original.message}; ${next.message}`);
}

export class GnNode {
  private thread: worker.ThreadWorker;
  private readonly workerExited: Promise<void>;
  private onWorkerExit?: () => void;
  private pending: Map<number, Pending> = new Map<number, Pending>();
  private next: number = 1;
  private exited: boolean = false;
  private exitError?: Error;
  private closing?: Promise<void>;
  private networkChange?: Promise<void>;
  private networkChangePending: boolean = false;
  private dnsUpdate?: Promise<void>;
  private dnsLatest?: string;
  private defaultNetwork?: DefaultNetworkObserver;
  private networkFailure?: Error;
  private networkClose?: Promise<void>;
  private stopping?: Promise<void>;
  private vpn?: NodeVpn;
  private vpnPump?: Promise<Error | undefined>;
  private vpnRetirement?: Promise<void>;

  private constructor() {
    this.thread = new worker.ThreadWorker('./workers/GnNodeWorker.ets');
    this.workerExited = new Promise<void>((resolve): void => {
      this.onWorkerExit = (): void => resolve();
    });
    this.thread.onmessage = (event: MessageEvents): void => {
      const reply = event.data as Reply;
      const original = this.pending.get(reply.id);
      if (original === undefined) {
        return;
      }
      this.pending.delete(reply.id);
      if (reply.error !== undefined) {
        original.reject(new Error(reply.error));
      } else {
        original.resolve(reply);
      }
    };
    this.thread.onerror = (event: ErrorEvent): void => {
      this.terminate(new Error(event.message));
    };
    this.thread.onexit = (code: number): void => {
      this.onWorkerExit?.();
      if (!this.exited) {
        this.exited = true;
        const error = new Error(`GNUnet Worker exited with code ${code}`);
        this.exitError = error;
        this.rejectPending(error);
        this.releaseDefaultNetwork().catch((error: Error): void => {
          if (this.exitError === undefined) this.exitError = error;
        });
      }
      this.retireVpn().catch((error: Error): void => {
        if (this.exitError === undefined) this.exitError = error;
      });
    };
    this.thread.onmessageerror = (): void => {
      this.terminate(new Error('GNUnet Worker reply could not be decoded'));
    };
  }

  // Launch resolves once the Rust owner exists. Poll snapshot for actual readiness.
  static async launch(options: NodeOptions): Promise<GnNode> {
    const owner = new GnNode();
    try {
      await owner.exchange(Command.Start, options);
      return owner;
    } catch (error) {
      owner.terminate(error as Error);
      throw error;
    }
  }

  /**
   * API 22+. Call from a dedicated VpnExtensionAbility process. Process
   * protection is established before the original Rust owner opens sockets.
   */
  static async launchVpn(options: NodeOptions, context: vpnExtension.VpnExtensionContext,
    vpnOptions: VpnNodeOptions): Promise<GnNode> {
    nativeNode.reserveVpnProcess();
    let resources: VpnResources | undefined;
    let owner: GnNode | undefined;
    try {
      const protectedResources = VpnResources.exclusiveProcess(context);
      resources = protectedResources;
      const node = new GnNode();
      owner = node;
      const vpn = new NodeVpn(protectedResources, vpnOptions,
        (command: Command, request?: VpnRequest): Promise<Reply> => {
          return node.exchange(command, undefined, undefined, request);
        },
        (): Promise<void> => node.exited ? node.workerExited : Promise.resolve()
      );
      node.vpn = vpn;
      const maximumPacket = vpnOptions.maximumPacket;
      const nodeOptions: NodeOptions = {
        stateDir: options.stateDir, ipcDir: options.ipcDir, configFile: options.configFile,
        bootstrapDataDir: options.bootstrapDataDir, tcpBind: options.tcpBind,
        udp4Bind: options.udp4Bind, udp6Bind: options.udp6Bind,
        dnsServers: vpnOptions.upstreamNetwork?.allowUnencryptedDns === true ? [] : options.dnsServers,
        startupTimeoutMs: options.startupTimeoutMs, drainTimeoutMs: options.drainTimeoutMs
      };
      await protectedResources.protectProcess();
      await node.exchange(Command.Start, nodeOptions, undefined, { maximumPacket: maximumPacket });
      node.vpnPump = vpn.run().then((): Error | undefined => vpn.error(), (error: Error): Error => error);
      await node.followDefaultNetwork(vpnOptions.upstreamNetwork ?? {
        allowUnencryptedDns: false,
        onError: (_error: Error): void => { /* Retained by the node and surfaced by snapshot/close. */ }
      });
      return node;
    } catch (cause) {
      try {
        // A starting Worker may already own the original native handle.
        if (owner?.vpn !== undefined) {
          await owner.close();
        } else {
          owner?.terminate();
          await resources?.close();
          nativeNode.releaseVpnProcess();
        }
      } catch (retirement) {
        throw retainFailure(cause as Error, retirement as Error);
      }
      throw cause;
    }
  }

  async snapshot(): Promise<NodeSnapshot> {
    if (this.networkFailure !== undefined) throw this.networkFailure;
    const reply = await this.exchange(Command.Snapshot);
    if (reply.snapshot === undefined) {
      throw new Error('GNUnet Worker returned no snapshot');
    }
    return reply.snapshot;
  }

  requestStop(): Promise<void> {
    if (this.stopping === undefined) this.stopping = this.stopWorker();
    return this.stopping;
  }

  private async stopWorker(): Promise<void> {
    await Promise.all([this.exchange(Command.Stop), this.releaseDefaultNetwork()]);
  }

  // The OS-qualified system default excludes VPN independently of process
  // protection. Raw DNS requires explicit host permission; false observes paths.
  async followDefaultNetwork(options: DefaultNetworkDnsOptions): Promise<void> {
    if (this.exited || this.closing !== undefined || this.stopping !== undefined ||
      this.defaultNetwork !== undefined) {
      throw new Error('GNUnet default network observer is already owned or node is closed');
    }
    const observer: DefaultNetworkObserver = new DefaultNetworkObserver({
      dns: (servers: string[]): Promise<void> => {
        return this.defaultNetwork === observer ? this.replaceDnsServers(servers) : Promise.resolve();
      },
      changed: (): Promise<void> => {
        return this.defaultNetwork === observer ? this.notifyNetworkChange() : Promise.resolve();
      },
      failed: (error: Error): void => {
        if (this.networkFailure === undefined) this.networkFailure = error;
        this.requestStop().catch((stopError: Error): void => options.onError(stopError));
        options.onError(error);
      }
    }, options.allowUnencryptedDns);
    this.defaultNetwork = observer;
    try {
      await observer.start();
    } catch (error) {
      if (this.defaultNetwork === observer) this.defaultNetwork = undefined;
      try { await observer.close(); } catch (cleanup) {
        throw retainFailure(error as Error, cleanup as Error);
      }
      throw error;
    }
  }

  // Forward an application network-change callback to the original Worker.
  notifyNetworkChange(): Promise<void> {
    if (this.exited || this.closing !== undefined || this.stopping !== undefined) {
      return Promise.resolve();
    }
    this.networkChangePending = true;
    if (this.networkChange === undefined) {
      this.networkChange = this.forwardNetworkChanges();
    }
    return this.networkChange;
  }

  private async forwardNetworkChanges(): Promise<void> {
    try {
      while (this.networkChangePending && !this.exited && this.closing === undefined &&
        this.stopping === undefined) {
        this.networkChangePending = false;
        await this.exchange(Command.NetworkChange);
      }
    } finally {
      this.networkChange = undefined;
      this.networkChangePending = false;
    }
  }

  // One in-flight command and one bounded latest snapshot. Empty revocations
  // retain a dedicated slot even when ordinary Worker requests are at capacity.
  setDnsServers(servers: string[]): Promise<void> {
    if (this.defaultNetwork?.usesDns() === true) {
      return Promise.reject(new Error('Automatic system DNS owns this node; manual DNS updates are disabled'));
    }
    return this.replaceDnsServers(servers);
  }

  private replaceDnsServers(servers: string[]): Promise<void> {
    if (this.exited || this.closing !== undefined || this.stopping !== undefined) {
      return Promise.resolve();
    }
    if (servers.length > 32 || servers.some((server: string): boolean => {
      return server.length === 0 || server.length > 256 ||
        /[^0-9a-fA-F:.%\[\]]/.test(server);
    })) {
      return Promise.reject(new Error('Expected at most 32 numeric DNS endpoints'));
    }
    this.dnsLatest = servers.join(' ');
    if (this.dnsUpdate === undefined) {
      this.dnsUpdate = this.forwardDnsServers();
    }
    return this.dnsUpdate;
  }

  private async forwardDnsServers(): Promise<void> {
    try {
      while (this.dnsLatest !== undefined && !this.exited && this.closing === undefined &&
        this.stopping === undefined) {
        const servers = this.dnsLatest;
        this.dnsLatest = undefined;
        await this.exchange(Command.DnsServers, undefined, servers);
      }
    } finally {
      this.dnsUpdate = undefined;
      this.dnsLatest = undefined;
    }
  }

  // Await this to join the Rust node on the original Worker, then retire the Worker.
  close(): Promise<void> {
    if (this.closing === undefined) {
      this.closing = this.closeWorker();
    }
    return this.closing;
  }

  private async closeWorker(): Promise<void> {
    const unregister = this.releaseDefaultNetwork().then((): Error | undefined => undefined,
      (error: Error): Error => error);
    let failure: Error | undefined = this.exitError ?? this.networkFailure;
    try {
      if (!this.exited) {
        if (this.vpnPump !== undefined) {
          await this.exchange(Command.Stop);
          const vpnFailure = await this.vpnPump;
          if (vpnFailure !== undefined) failure = retainFailure(failure, vpnFailure);
        }
        await this.exchange(Command.Close);
      }
      await this.retireVpn();
    } catch (error) {
      failure = retainFailure(failure, error as Error);
      // A failed Worker cannot receive route receipts, but its original
      // platform VPN still needs retirement.
      this.terminate(failure);
      try { await this.retireVpn(); } catch (retirement) {
        failure = retainFailure(failure, retirement as Error);
      }
    }
    const unregisterError = await unregister;
    if (unregisterError !== undefined) failure = retainFailure(failure, unregisterError);
    this.terminate(failure);
    if (failure !== undefined) throw failure;
  }

  private retireVpn(): Promise<void> {
    const vpn = this.vpn;
    if (vpn === undefined) return Promise.resolve();
    if (this.vpnRetirement === undefined) {
      this.vpnRetirement = vpn.close().then((): void => nativeNode.releaseVpnProcess());
    }
    return this.vpnRetirement;
  }

  private exchange(command: Command, options?: NodeOptions, dnsServers?: string, vpn?: VpnRequest): Promise<Reply> {
    const retirement = command === Command.Stop || command === Command.Close ||
      command === Command.VpnNext || command === Command.VpnComplete || command === Command.VpnRevoke;
    if (this.exited || (this.closing !== undefined && !retirement)) {
      return Promise.reject(new Error('GNUnet node is closing or closed'));
    }
    if (this.pending.size >= 32 && !retirement && command !== Command.DnsServers) {
      return Promise.reject(new Error('Too many pending GNUnet Worker requests'));
    }
    const request: Request = {
      id: this.next, command: command, options: options, dnsServers: dnsServers, vpn: vpn
    };
    this.next += 1;
    return new Promise<Reply>((resolve, reject): void => {
      this.pending.set(request.id, { resolve: resolve, reject: reject });
      try {
        this.thread.postMessage(request);
      } catch (error) {
        this.pending.delete(request.id);
        reject(error as Error);
      }
    });
  }

  private rejectPending(error: Error): void {
    this.pending.forEach((request: Pending): void => request.reject(error));
    this.pending.clear();
  }

  private releaseDefaultNetwork(): Promise<void> {
    const observer = this.defaultNetwork;
    this.defaultNetwork = undefined;
    if (observer !== undefined) this.networkClose = observer.close();
    return this.networkClose ?? Promise.resolve();
  }

  private terminate(error?: Error): void {
    if (!this.exited) {
      this.exited = true;
      this.exitError = error;
      this.rejectPending(error ?? new Error('GNUnet node is closed'));
      this.releaseDefaultNetwork().catch((error: Error): void => {
        if (this.exitError === undefined) this.exitError = error;
      });
      this.thread.terminate();
    }
  }
}
