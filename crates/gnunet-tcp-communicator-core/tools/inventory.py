#!/usr/bin/env python3
"""Fixed source inventory only; no complete-subsystem status is granted."""
import argparse,hashlib,json,re
from pathlib import Path
PIN='346358e26d4dcc2dc4f51bef5d52dca29c7d8165'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def functions(text):
 # Strip comments/literals while preserving offsets and line numbers.
 stripped=re.sub(r'/\*.*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'',lambda m:''.join('\n'if c=='\n'else ' 'for c in m[0]),text,flags=re.S)
 rows=[]
 for m in re.finditer(r'(?m)^([A-Za-z_]\w*)\s*\([^;{}]*?\)\s*\{',stripped):
  depth=1;i=m.end()
  while depth:
   if stripped[i]=='{':depth+=1
   elif stripped[i]=='}':depth-=1
   i+=1
  rows.append({'name':m[1],'line':text.count('\n',0,m.start())+1,'end_line':text.count('\n',0,i)+1,'body_sha256':hashlib.sha256(text[m.start():i].encode()).hexdigest(),'assessment':'pending full owner/host implementation and source-bound validation'})
 return rows

def main():
 p=argparse.ArgumentParser();p.add_argument('--source',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args();source=a.source.resolve();tcp=source/'src/service/transport/gnunet-communicator-tcp.c'
 paths=set(source.glob('src/service/core/gnunet-service-core*.[ch]'))|set(source.glob('src/service/core/core_api*.c'))
 for rel in ['src/service/core/core.h','src/include/gnunet_core_service.h','src/include/gnunet_core_underlay.h','src/include/gnunet_transport_communication_service.h','src/include/gnunet_transport_core_service.h','src/include/gnunet_transport_application_service.h','src/include/gnunet_transport_monitor_service.h','src/include/gnunet_protocols.h','src/include/gnunet_signatures.h','src/include/gnunet_crypto_lib.h','src/service/transport/transport.h','src/service/transport/communicator.h','src/service/transport/transport_api_communication.c','src/service/transport/transport_api_core.c','src/service/transport/transport_api_application.c','src/service/transport/transport_api_monitor.c','src/service/transport/gnunet-service-transport.c','src/service/transport/meson.build','src/lib/util/crypto_elligator.c','src/lib/util/crypto_hpke.c','src/lib/util/crypto_ecc.c','src/include/gnunet_pils_service.h','src/include/gnunet_peerstore_service.h','src/include/gnunet_nat_service.h']:paths.add(source/rel)
 paths.add(tcp)
 rows={str(path.relative_to(source)):{'sha256':sha(path),'bytes':path.stat().st_size,'functions':functions(path.read_text())if path.suffix=='.c'else []}for path in sorted(paths,key=lambda x:str(x).encode())}
 result={'schema':1,'source_revision':PIN,'status':'inventory-only','sources':rows,'tcp_function_count':len(rows[str(tcp.relative_to(source))]['functions']),'wire_sizes':{'TcpHandshakeSignature':144,'TcpHandshakeAckSignature':112,'TcpRekeySignature':112,'TCPConfirmation':136,'initial_KX':168,'TCPConfirmationAck':140,'TCPBox_prefix':36,'TCPBox_max_total':65571,'TCPRekey':140,'TCPFinish':36,'TCPNATProbeMessage':36},'wire_size_status':'source-layout calculation awaiting fresh normal C header/component check','selected_suite':{'initial_KEM':'0x0022 Elligator2 X25519 HKDF-SHA256, representative32','rekey_KEM':'0x0020 ordinary X25519 DHKEM via EdDSA key conversion','cipher':'AES256 CTR128BE persistent stream','MAC':'HMAC-SHA512 truncate32 then key=SHA512(old64)','initial_plain_prefix':32,'ACK':'Ed25519 purpose39, no record MAC','BOX_size':'excludes36-byte prefix'},'whole_subsystems':{'TRANSPORT':'pending; all communicator IPC, service routing/validation/flow-control/backchannels/monitor/application/core bindings retained','CORE':'pending; CAKE full source owner, transcript/epochs/replay/version/application/MQ/monitor/underlay retained','PILS':'pending actual service/key ring lifecycle','PEERSTORE':'pending actual monotonic iterate/store/cancel/expiration lifecycle','NAT':'pending registration/reversal/address change ownership'},'full_function_promotion':False}
 a.output.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'sources':len(rows),'tcp_functions':result['tcp_function_count'],'output':str(a.output)}))
if __name__=='__main__':main()
