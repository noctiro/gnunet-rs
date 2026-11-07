#!/usr/bin/env python3
"""Original numeric/CLIENT bodies, real normal socket connect, observer-only scheduling."""
import argparse, hashlib, json, os, pathlib, socket, subprocess, sys
from common import disjoint, sha

def braced(text, needle, semicolon=False):
    start = text.index(needle)
    brace = text.index('{', start)
    (depth, end) = (1, brace + 1)
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    if semicolon:
        if not text[end] == ';':
            raise ValueError('required condition failed at original line 15')
        end += 1
    return text[start:end]

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--c-build', type=pathlib.Path, required=True)
    p.add_argument('--source', type=pathlib.Path, required=True)
    p.add_argument('--output', type=pathlib.Path, required=True)
    a = p.parse_args()
    a.output = a.output.resolve()
    disjoint(a.output, pathlib.Path(__file__).resolve().parents[1], a.source, a.c_build.parent)
    a.output.mkdir(parents=True, exist_ok=False)
    build = json.loads(a.c_build.read_text())
    if not (build['status'] == 'passed' and build['inputs_unchanged'] is True):
        raise ValueError('required condition failed at original line 30')
    inputs = dict(build['inputs'])
    for path in [a.c_build, pathlib.Path(__file__), pathlib.Path(__file__).with_name('common.py')]:
        inputs[str(path.resolve())] = sha(path)
    for (path, expected) in inputs.items():
        if not sha(path) == expected:
            raise ValueError(path)
    client = a.source / 'src/lib/util/client.c'
    resolver = a.source / 'src/lib/util/resolver_api.c'
    for path in [client, resolver]:
        inputs[str(path.resolve())] = sha(path)
    helper = next((path for path in inputs if path.endswith('/tools/reference/build_reference.py')))
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(pathlib.Path(helper).parent))
    from build_reference import source_state
    if not source_state(a.source) == build['upstream']:
        raise ValueError('required condition failed at original line 44')
    if not build['upstream']['revision'] == '346358e26d4dcc2dc4f51bef5d52dca29c7d8165':
        raise ValueError('required condition failed at original line 45')
    (c, r) = (client.read_text(), resolver.read_text())
    selected = {'AddressProbe': braced(c, 'struct AddressProbe\n{', True), 'ClientState': braced(c, 'struct ClientState\n{', True), 'RequestHandle': braced(r, 'struct GNUNET_RESOLVER_RequestHandle\n{', True), 'try_connect_using_address': braced(c, 'static void\ntry_connect_using_address ('), 'numeric_resolution': braced(r, 'static void\nnumeric_resolution (')}
    prelude = '#include "platform.h"\n#include "gnunet_util_lib.h"\n#include "gnunet_resolver_service.h"\nstatic unsigned events, failures, registered;\nstatic void *request_identity;\nstatic void event(const char *name){printf("EVENT|%u|%s\\n",++events,name);fflush(stdout);}\nstatic struct GNUNET_NETWORK_Handle *observed_create(int domain,int type,int protocol){\n  struct GNUNET_NETWORK_Handle *out=GNUNET_NETWORK_socket_create(domain,type,protocol);\n  GNUNET_assert(out!=NULL);event("socket_created");return out;\n}\nstatic int observed_connect(struct GNUNET_NETWORK_Handle *sock,const struct sockaddr *addr,socklen_t len){\n  int out=GNUNET_NETWORK_socket_connect(sock,addr,len);int saved=errno;\n  GNUNET_assert(out==GNUNET_OK||saved==EINPROGRESS);event("native_connect_returned");errno=saved;return out;\n}\nstatic void connect_probe_continuation(void *cls){(void)cls;abort();}\nstatic struct GNUNET_SCHEDULER_Task *observed_write(struct GNUNET_TIME_Relative timeout,struct GNUNET_NETWORK_Handle *sock,GNUNET_SCHEDULER_TaskCallback callback,void *cls){\n  static char token;GNUNET_assert(sock!=NULL&&cls!=NULL&&callback==connect_probe_continuation);\n  GNUNET_assert(timeout.rel_value_us==5000000);registered++;event("write_registered_5s");return (void*)&token;\n}\nstatic void observed_free(void *ptr){if(ptr==request_identity)event("request_freed");GNUNET_free_nz(ptr);}\n#undef GNUNET_free\n#define GNUNET_free(ptr) do {observed_free(ptr);(ptr)=NULL;}while(0)\n#define GNUNET_NETWORK_socket_create observed_create\n#define GNUNET_NETWORK_socket_connect observed_connect\n#define GNUNET_SCHEDULER_add_write_net observed_write\n#define CONNECT_RETRY_TIMEOUT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS,5)\n#define LOG(...) ((void)0)\nstruct ClientState;\n'
    middle = '\nstatic void connect_fail_continuation(struct ClientState *state){(void)state;failures++;abort();}\n'
    tail = '\nstatic void callback(void *cls,const struct sockaddr *addr,socklen_t len){\n  struct ClientState *state=cls;event(addr?"address_callback_enter":"null_callback_enter");\n  try_connect_using_address(cls,addr,len);\n  if(addr){GNUNET_assert(state->dns_active==request_identity&&state->ap_head!=NULL);event("address_callback_return");}\n  else {GNUNET_assert(state->dns_active==NULL&&state->ap_head!=NULL);event("null_callback_return");}\n}\nint main(int argc,char **argv){\n  GNUNET_assert(argc==2);unsigned port=atoi(argv[1]);GNUNET_assert(port>0&&port<=65535);\n  struct ClientState state={0};state.port=port;\n  const char name[]="127.0.0.1";\n  struct GNUNET_RESOLVER_RequestHandle *rh=GNUNET_malloc(sizeof(*rh)+sizeof(name));\n  memcpy(&rh[1],name,sizeof(name));rh->af=AF_UNSPEC;rh->addr_callback=callback;rh->cls=&state;\n  request_identity=rh;state.dns_active=rh;numeric_resolution(rh);\n  GNUNET_assert(state.dns_active==NULL&&state.sock==NULL&&registered==1&&failures==0);\n  event("numeric_task_return");\n  GNUNET_assert(getchar()==42); /* keep original native socket live until parent actually accepts */\n  struct AddressProbe *ap=state.ap_head;GNUNET_assert(ap&&ap==state.ap_tail);\n  GNUNET_assert(GNUNET_OK==GNUNET_NETWORK_socket_close(ap->sock));GNUNET_free(ap);\n  event("probe_closed_without_completion");return 0;\n}\n'
    caller = a.output / 'numeric-component.c'
    caller.write_text(prelude + selected['AddressProbe'] + '\n' + selected['ClientState'] + '\n' + selected['RequestHandle'] + middle + selected['try_connect_using_address'] + '\n' + selected['numeric_resolution'] + tail)
    binary = a.output / 'numeric-component'
    argv = build['argv'].copy()
    idx = next((i for (i, v) in enumerate(argv) if v.endswith('/tools/two_services.c')))
    argv[idx] = str(caller)
    argv[argv.index('-o') + 1] = str(binary)
    compile_run = subprocess.run(argv, cwd=build['cwd'], capture_output=True)
    (a.output / 'compile.stdout').write_bytes(compile_run.stdout)
    (a.output / 'compile.stderr').write_bytes(compile_run.stderr)
    if not compile_run.returncode == 0:
        raise ValueError(compile_run.stderr.decode(errors='replace'))
    env = {k: v for (k, v) in os.environ.items() if not k.startswith('GNUNET_')}
    env.update(build['runtime_environment'])
    binary_sha = sha(binary)
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(3)
        proc = subprocess.Popen([str(binary), str(listener.getsockname()[1])], env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            (conn, address) = listener.accept()
            with conn:
                proc.stdin.write(b'*')
                proc.stdin.flush()
                conn.settimeout(3)
                if not conn.recv(1) == b'':
                    raise ValueError('component must close original socket, no synthetic payload')
            proc.stdin.close()
            proc.stdin = None
            (stdout, stderr) = proc.communicate(timeout=3)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
    (a.output / 'stdout').write_bytes(stdout)
    (a.output / 'stderr').write_bytes(stderr)
    expected = ['address_callback_enter', 'socket_created', 'native_connect_returned', 'write_registered_5s', 'address_callback_return', 'null_callback_enter', 'null_callback_return', 'request_freed', 'numeric_task_return', 'probe_closed_without_completion']
    rows = [line.split('|') for line in stdout.decode().splitlines()]
    if not (proc.returncode == 0 and rows == [['EVENT', str(i + 1), name] for (i, name) in enumerate(expected)]):
        raise ValueError((proc.returncode, stdout, stderr))
    unchanged = sha(binary) == binary_sha and all((sha(path) == value for (path, value) in inputs.items())) and (source_state(a.source) == build['upstream'])
    if not unchanged:
        raise ValueError('required condition failed at original line 141')
    result = {'status': 'passed', 'scope': 'Exact original numeric_resolution and try_connect_using_address bodies and three structs. Normal unchanged util socket create/connect/close; actual owned IPv4 loopback accept and EOF. Scheduling observer records write-net registration but never executes or fabricates its completion. No full C scheduler/daemon claim.', 'inputs': inputs, 'inputs_unchanged': unchanged, 'extracted': {name: {'sha256': hashlib.sha256(body.encode()).hexdigest(), 'lines': len(body.splitlines())} for (name, body) in selected.items()}, 'generated_source': {'path': str(caller), 'sha256': sha(caller)}, 'binary': {'path': str(binary), 'sha256': binary_sha}, 'compile_argv': argv, 'exit_code': proc.returncode, 'trace': expected, 'actual_peer': {'address': list(address), 'eof': True}, 'rust_witnesses': ['numeric_client_starts_real_socket_then_finishes_own_callback_stack_before_connection_notice', 'numeric_address_hold_precedes_real_socket_and_only_own_null_continues']}
    (a.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': 'passed', 'result': str(a.output / 'result.json')}))
if __name__ == '__main__':
    main()
