import { MessageEvents, worker } from '@kit.ArkTS';
import nativeNode, { NativeNode } from 'libgnunet_node.so';
import { Command, Reply, Request } from '../NodeMessages';

let node: NativeNode | undefined;

function handle(request: Request): Reply {
  switch (request.command) {
    case Command.Start:
      if (node !== undefined || request.options === undefined) {
        throw new Error('GNUnet Worker requires one node and valid options');
      }
      const maximumPacket = request.vpn?.maximumPacket;
      node = maximumPacket === undefined ? nativeNode.start(request.options) :
        nativeNode.startVpn(request.options, maximumPacket);
      return { id: request.id };
    case Command.Snapshot:
      if (node === undefined) {
        throw new Error('GNUnet node is closed');
      }
      return { id: request.id, snapshot: node.snapshot() };
    case Command.Stop:
      node?.requestStop();
      return { id: request.id };
    case Command.NetworkChange:
      node?.notifyNetworkChange();
      return { id: request.id };
    case Command.DnsServers:
      if (request.dnsServers === undefined) {
        throw new Error('GNUnet DNS update requires a numeric endpoint list');
      }
      node?.setDnsServers(request.dnsServers);
      return { id: request.id };
    case Command.VpnNext:
      if (node === undefined) throw new Error('GNUnet VPN worker is closed');
      return { id: request.id, vpnCommand: node.vpnNext() };
    case Command.VpnComplete:
      const completion = request.vpn?.completion;
      if (node === undefined || completion === undefined) {
        throw new Error('GNUnet VPN worker requires the original route completion');
      }
      if (completion.fd !== undefined && completion.outcome === undefined) {
        node.vpnInstalled(completion.token, completion.fd);
      } else if (completion.outcome !== undefined && completion.fd === undefined) {
        node.vpnComplete(completion.token, completion.outcome);
      } else {
        throw new Error('GNUnet VPN completion must carry one descriptor or one route outcome');
      }
      return { id: request.id };
    case Command.VpnRevoke:
      const absent = request.vpn?.routesAbsent;
      if (node === undefined || absent === undefined) {
        throw new Error('GNUnet VPN worker requires a settled revocation result');
      }
      node.vpnRevoke(absent);
      return { id: request.id };
    case Command.Close:
      node?.close();
      node = undefined;
      return { id: request.id };
    default:
      throw new Error('Unknown GNUnet Worker command');
  }
}

worker.workerPort.onmessage = (event: MessageEvents): void => {
  const request = event.data as Request;
  let reply: Reply;
  try {
    reply = handle(request);
  } catch (error) {
    reply = { id: request.id, error: (error as Error).message };
  }
  worker.workerPort.postMessage(reply);
};

worker.workerPort.onmessageerror = (): void => {
  throw new Error('GNUnet Worker request could not be decoded');
};
