import { BusinessError } from '@kit.BasicServicesKit';
import { connection } from '@kit.NetworkKit';
import nativeNode from 'libgnunet_node.so';

export interface DefaultNetworkDnsOptions {
  // The public API does not expose encrypted/private DNS policy. The host
  // explicitly permits cleartext Resolver queries to this network's endpoints.
  allowUnencryptedDns: boolean;
  onError: (error: Error) => void;
}

export interface DefaultNetworkCallbacks {
  dns: (servers: string[]) => Promise<void>;
  changed: () => Promise<void>;
  failed: (error: Error) => void;
}

/** One system-default observer, shared by ordinary and process-protected nodes. */
export class DefaultNetworkObserver {
  private connection: connection.NetConnection = connection.createNetConnection();
  private closed: boolean = false;
  private failed: boolean = false;
  private registered: boolean = false;
  private revision: number = 0;
  private pending: boolean = false;
  private registration?: Promise<void>;
  private refreshing?: Promise<void>;
  private closing?: Promise<void>;
  private updating?: Promise<void>;
  private readonly callbacks: DefaultNetworkCallbacks;
  private readonly allowUnencryptedDns: boolean;

  constructor(callbacks: DefaultNetworkCallbacks, allowUnencryptedDns: boolean) {
    this.callbacks = callbacks;
    this.allowUnencryptedDns = allowUnencryptedDns;
    // Callback payloads are hints. Never publish a possibly-VPN callback's DNS.
    this.connection.on('netAvailable', (_network: connection.NetHandle): void => this.hint());
    this.connection.on('netConnectionPropertiesChange', (_info: connection.NetConnectionPropertyInfo): void => this.hint());
    this.connection.on('netCapabilitiesChange', (_info: connection.NetCapabilityInfo): void => this.hint());
    this.connection.on('netLost', (_network: connection.NetHandle): void => this.hint());
    this.connection.on('netUnavailable', (): void => this.hint());
  }

  start(): Promise<void> {
    if (this.registration === undefined) this.registration = this.register();
    return this.registration;
  }

  /** The attached automatic observer is the node's single DNS authority. */
  usesDns(): boolean {
    return this.allowUnencryptedDns;
  }

  private async register(): Promise<void> {
    await this.update([]);
    if (this.closed) return;
    await new Promise<void>((resolve, reject): void => {
      this.connection.register((error: BusinessError): void => {
        if (error) {
          reject(new Error(`GNUnet network registration failed (${error.code}): ${error.message}`));
        } else {
          this.registered = true;
          resolve();
        }
      });
    });
    if (this.closed) return;
    this.pending = true;
    await this.refresh();
  }

  private hint(): void {
    if (this.closed || this.failed) return;
    this.revision += 1;
    this.pending = true;
    // Revocation and scan hints use GnNode's dedicated coalesced update slots.
    // They are issued before any replacement properties are read from the OS.
    const actual = this.update([]);
    if (this.updating === undefined) this.updating = this.observeUpdate(actual);
    if (this.registered) this.refresh();
  }

  private refresh(): Promise<void> {
    if (this.refreshing === undefined) {
      const actual = this.readSnapshots();
      this.refreshing = actual;
      this.observeRefresh(actual);
    }
    return this.refreshing;
  }

  private async observeRefresh(actual: Promise<void>): Promise<void> {
    try {
      await actual;
    } catch (error) {
      this.report(error as Error);
    } finally {
      if (this.refreshing === actual) this.refreshing = undefined;
      if (this.pending && !this.closed && !this.failed) this.refresh();
    }
  }

  private async readSnapshots(): Promise<void> {
    while (this.pending && !this.closed && !this.failed) {
      this.pending = false;
      const revision = this.revision;
      try {
        // The documented system default is INTERNET-capable and non-VPN,
        // independently of application/process binding. Calls stay serialized.
        const network = await connection.getDefaultNet();
        if (this.closed || revision !== this.revision) continue;
        if (network.netId === 0) {
          await this.update([]);
          continue;
        }
        if (!Number.isInteger(network.netId) || network.netId < 100) {
          throw new Error('System default returned an invalid network identity');
        }
        if (!this.allowUnencryptedDns) {
          await this.callbacks.changed();
          continue;
        }
        let properties: connection.ConnectionProperties | undefined;
        let failure: Error | undefined;
        try { properties = await connection.getConnectionProperties(network); }
        catch (error) { failure = error as Error; }
        if (this.closed || revision !== this.revision) continue;
        // Even a failed properties read may belong to a network just replaced
        // before its callback was delivered. Qualify errors as well as values.
        const current = await connection.getDefaultNet();
        if (this.closed || revision !== this.revision) continue;
        if (current.netId !== network.netId) {
          this.pending = true;
          continue;
        }
        if (failure !== undefined) throw failure;
        if (properties === undefined) throw new Error('System default returned no properties');
        const servers = this.servers(properties);
        if (this.closed || revision !== this.revision) continue;
        await this.update(servers);
      } catch (error) {
        // A retired read cannot fail a replacement owner or close in progress.
        if (this.closed || revision !== this.revision) continue;
        throw error;
      }
    }
  }

  private servers(properties: connection.ConnectionProperties): string[] {
    const servers: string[] = [];
    let interfaceIndex: number | undefined;
    const dns = properties.dnses ?? [];
    if (dns.length > 32) throw new Error('Default network exceeds the 32-server DNS snapshot bound');
    for (const address of dns) {
      const host = address.address;
      const port = address.port === undefined || address.port === 0 ? 53 : address.port;
      if (host.length === 0 || host.length > 240 || /[^0-9a-fA-F:.%]/.test(host) ||
        !Number.isInteger(port) || port < 1 || port > 65535) continue;
      if (host.indexOf(':') >= 0) {
        let scoped = host;
        const linkLocal = /^fe[89ab][0-9a-f]:/i.test(host);
        if (host.indexOf('%') >= 0) {
          // Preserve the address's explicit scope, even if the callback's
          // interface differs. Never erase or replace an invalid zone.
          if (!/%[0-9]+$/.test(host) ||
            (linkLocal && !/%[1-9][0-9]*$/.test(host))) continue;
        } else if (linkLocal) {
          if (interfaceIndex === undefined) {
            const name = properties.interfaceName;
            interfaceIndex = name ? nativeNode.interfaceIndex(name) : 0;
          }
          if (interfaceIndex === 0) continue;
          scoped = `${host}%${interfaceIndex}`;
        }
        servers.push(`[${scoped}]:${port}`);
      } else {
        servers.push(`${host}:${port}`);
      }
    }
    if (servers.join(' ').length > 4096) {
      throw new Error('Default network exceeds the 4096-byte DNS snapshot bound');
    }
    return servers;
  }

  private update(servers: string[]): Promise<void> {
    return this.allowUnencryptedDns ? this.callbacks.dns(servers) : this.callbacks.changed();
  }

  private report(error: Error): void {
    if (this.closed || this.failed) return;
    this.failed = true;
    this.pending = false;
    this.callbacks.failed(error);
  }

  private async observeUpdate(actual: Promise<void>): Promise<void> {
    try { await actual; } catch (error) { this.report(error as Error); }
    finally { this.updating = undefined; }
  }

  close(): Promise<void> {
    this.closed = true;
    this.pending = false;
    this.revision += 1;
    if (this.closing === undefined) this.closing = this.unregister();
    return this.closing;
  }

  private async unregister(): Promise<void> {
    try { await this.registration; } catch (_) { /* A failed register owns no listener. */ }
    try { await this.refreshing; } catch (_) { /* Preserve the original reported failure. */ }
    await this.updating;
    if (!this.registered) return;
    await new Promise<void>((resolve, reject): void => {
      this.connection.unregister((error: BusinessError): void => {
        if (error) {
          reject(new Error(`GNUnet network unregister failed (${error.code}): ${error.message}`));
        } else {
          this.registered = false;
          resolve();
        }
      });
    });
  }
}
