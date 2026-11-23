import { connection, vpnExtension } from '@kit.NetworkKit';

/** Explicit caller-selected native settings. No route or interface is inferred. */
export interface VpnRoutePlan {
  addresses: connection.LinkAddress[];
  routes: connection.RouteInfo[];
  dnsAddresses: string[];
  mtu: number;
}

export enum VpnResourcePhase {
  New,
  Protecting,
  Protected,
  Applying,
  Active,
  Closing,
  Closed,
  Failed
}

/** Only Destroyed is an actual native VPN-removal completion. */
export enum VpnRemoval {
  NotCreated,
  Destroyed
}

/** Original failures remain independent even when later destruction succeeds. */
export interface VpnResourceFailures {
  protection?: Error;
  creation?: Error;
  destruction?: Error;
}

/**
 * One actual VpnConnection in an application-exclusive VPN extension process.
 * The caller must protect the process before starting any node/native socket.
 * The GnNode provider ties this owner's original apply and destroy receipts
 * to the exact native route operation.
 */
export class VpnResources {
  private static processOwner?: VpnResources;
  private connection: vpnExtension.VpnConnection;
  private current: VpnResourcePhase = VpnResourcePhase.New;
  private nativeProtection?: Promise<void>;
  private protection?: Promise<void>;
  private nativeCreation?: Promise<number>;
  private creation?: Promise<number>;
  private closing?: Promise<VpnRemoval>;
  private fd?: number;
  private protectionFailure?: Error;
  private creationFailure?: Error;
  private destructionFailure?: Error;

  private constructor(context: vpnExtension.VpnExtensionContext) {
    this.connection = vpnExtension.createVpnConnection(context);
  }

  /** API22+ only. The caller explicitly dedicates this process to the VPN. */
  static exclusiveProcess(context: vpnExtension.VpnExtensionContext): VpnResources {
    if (VpnResources.processOwner !== undefined) {
      throw new Error('The original VPN process owner has not retired');
    }
    const owner = new VpnResources(context);
    VpnResources.processOwner = owner;
    return owner;
  }

  phase(): VpnResourcePhase {
    return this.current;
  }

  failures(): VpnResourceFailures {
    return {
      protection: this.protectionFailure,
      creation: this.creationFailure,
      destruction: this.destructionFailure
    };
  }

  /**
   * Resolves only after original protectProcessNet succeeds. A close racing
   * that native call fences its public completion; close still waits for the
   * original operation. There is no per-socket or privileged fallback.
   */
  protectProcess(): Promise<void> {
    if (this.current === VpnResourcePhase.Closing || this.current === VpnResourcePhase.Closed ||
      this.current === VpnResourcePhase.Failed) {
      return Promise.reject(new Error('VPN process owner is closing or failed'));
    }
    if (this.protection !== undefined) return this.protection;
    this.current = VpnResourcePhase.Protecting;
    try {
      this.nativeProtection = this.connection.protectProcessNet();
    } catch (cause) {
      this.nativeProtection = Promise.reject(cause as Error);
    }
    this.protection = this.nativeProtection.then((): void => {
      if (this.current !== VpnResourcePhase.Protecting) {
        throw new Error('Original VPN protection completed after close');
      }
      this.current = VpnResourcePhase.Protected;
    }, (cause: Error): void => {
      this.protectionFailure = cause;
      if (this.current === VpnResourcePhase.Protecting) this.current = VpnResourcePhase.Failed;
      throw cause;
    });
    return this.protection;
  }

  /**
   * Apply exactly one defensively copied plan. The returned original vNIC fd is
   * borrowed from this retained VpnConnection; native consumers must duplicate
   * it rather than close the framework's fd. It is usable only while Active.
   * Replacement requires retiring this original owner before creating another.
   */
  apply(plan: VpnRoutePlan): Promise<number> {
    if (this.current !== VpnResourcePhase.Protected) {
      return Promise.reject(new Error('Original process protection must complete before VPN create'));
    }
    let config: vpnExtension.VpnConfig;
    try {
      config = VpnResources.config(plan);
    } catch (cause) {
      return Promise.reject(cause as Error);
    }
    this.current = VpnResourcePhase.Applying;
    try {
      this.nativeCreation = this.connection.create(config);
    } catch (cause) {
      this.nativeCreation = Promise.reject(cause as Error);
    }
    this.creation = this.nativeCreation.then((fd: number): number => {
      if (!Number.isInteger(fd) || fd < 0 || fd > 0x7fffffff) {
        const failure = new Error('Native VPN create returned an invalid descriptor');
        this.creationFailure = failure;
        if (this.current === VpnResourcePhase.Applying) this.current = VpnResourcePhase.Failed;
        throw failure;
      }
      this.fd = fd;
      if (this.current !== VpnResourcePhase.Applying) {
        throw new Error('Original VPN creation completed after close');
      }
      this.current = VpnResourcePhase.Active;
      return fd;
    }, (cause: Error): number => {
      this.creationFailure = cause;
      if (this.current === VpnResourcePhase.Applying) this.current = VpnResourcePhase.Failed;
      throw cause;
    });
    return this.creation;
  }

  /** Access to the original borrowed fd is revoked synchronously by close(). */
  descriptor(): number {
    if (this.current !== VpnResourcePhase.Active || this.fd === undefined) {
      throw new Error('The original VPN descriptor is not active');
    }
    return this.fd;
  }

  /**
   * Fence new work immediately, settle original protect/create, then destroy
   * the same native VPN once. Pending native operations remain pending; no
   * timeout invents absence. VpnExtensionAbility.onDestroy is void and cannot
   * itself provide this asynchronous completion; explicit callers await close.
   */
  close(): Promise<VpnRemoval> {
    if (this.closing !== undefined) return this.closing;
    this.current = VpnResourcePhase.Closing;
    this.closing = this.retire();
    return this.closing;
  }

  private async retire(): Promise<VpnRemoval> {
    if (this.nativeProtection !== undefined) {
      try { await this.nativeProtection; } catch (cause) { this.protectionFailure = cause as Error; }
    }
    let removal = VpnRemoval.NotCreated;
    if (this.nativeCreation !== undefined) {
      try { await this.nativeCreation; } catch (cause) { this.creationFailure = cause as Error; }
      try {
        await this.connection.destroy();
        removal = VpnRemoval.Destroyed;
      } catch (cause) {
        this.destructionFailure = cause as Error;
        this.current = VpnResourcePhase.Failed;
        // Keep processOwner and original resources quarantined on uncertainty.
        throw this.destructionFailure;
      }
    }
    this.fd = undefined;
    this.current = VpnResourcePhase.Closed;
    if (VpnResources.processOwner === this) VpnResources.processOwner = undefined;
    // This is a VPN teardown receipt, not an undocumented process-unbind ACK.
    return removal;
  }

  private static address(value: connection.NetAddress): connection.NetAddress {
    if ((value.family !== 1 && value.family !== 2) || value.address.length === 0 ||
      value.address.length > 128 || value.address.indexOf('\0') >= 0) {
      throw new Error('VPN addresses require an explicit family and bounded numeric IP');
    }
    return { address: value.address, family: value.family };
  }

  private static link(value: connection.LinkAddress): connection.LinkAddress {
    const address = VpnResources.address(value.address);
    if (!Number.isInteger(value.prefixLength) || value.prefixLength < 0 ||
      value.prefixLength > (address.family === 1 ? 32 : 128)) {
      throw new Error('Invalid VPN address prefix');
    }
    return { address, prefixLength: value.prefixLength };
  }

  private static config(plan: VpnRoutePlan): vpnExtension.VpnConfig {
    if (plan.addresses.length < 1 || plan.addresses.length > 64 || plan.routes.length > 128 ||
      plan.dnsAddresses.length > 32 || !Number.isInteger(plan.mtu) || plan.mtu < 576 || plan.mtu > 1500) {
      throw new Error('VPN plan exceeds the explicit native profile bounds');
    }
    const addresses: connection.LinkAddress[] = plan.addresses.map(VpnResources.link);
    const routes: connection.RouteInfo[] = plan.routes.map((route: connection.RouteInfo): connection.RouteInfo => {
      if (route.interface.length > 64 || route.interface.indexOf('\0') >= 0) {
        throw new Error('Invalid explicit VPN route interface');
      }
      return {
        interface: route.interface,
        destination: VpnResources.link(route.destination),
        gateway: VpnResources.address(route.gateway),
        hasGateway: route.hasGateway,
        isDefaultRoute: route.isDefaultRoute,
        isExcludedRoute: route.isExcludedRoute
      };
    });
    const dns: string[] = plan.dnsAddresses.map((address: string): string => {
      if (address.length === 0 || address.length > 128 || address.indexOf('\0') >= 0) {
        throw new Error('Invalid bounded VPN DNS address');
      }
      return address;
    });
    return {
      addresses, routes, dnsAddresses: dns, mtu: plan.mtu,
      isIPv4Accepted: addresses.some((value: connection.LinkAddress): boolean => value.address.family === 1),
      isIPv6Accepted: addresses.some((value: connection.LinkAddress): boolean => value.address.family === 2),
      isInternal: false,
      isBlocking: false
    };
  }
}
