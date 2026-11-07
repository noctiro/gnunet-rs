#!/usr/bin/env python3
"""Exact unmodified reconnect/check_disconnect bodies; scheduler shims record only."""
import argparse, json, os, pathlib, subprocess
from paired import sha

def extract(text, name):
    start = text.index('static void\n' + name + ' ()')
    brace = text.index('{', start)
    depth = 1
    end = brace + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[start:end]

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--c-build', type=pathlib.Path, required=True)
    p.add_argument('--source', type=pathlib.Path, required=True)
    p.add_argument('--output', type=pathlib.Path, required=True)
    a = p.parse_args()
    a.output = a.output.resolve()
    a.output.mkdir(parents=True, exist_ok=False)
    build = json.loads(a.c_build.read_text())
    normal = json.loads(pathlib.Path(build['normal_receipt']).read_text())
    if not build['status'] == 'passed':
        raise ValueError('required condition failed at original line 12')
    source = a.source / 'src/lib/util/resolver_api.c'
    text = source.read_text()
    inventory = json.loads((pathlib.Path(__file__).resolve().parents[1] / 'inventory.json').read_text())
    if not sha(source) == inventory['source_sha256']['src/lib/util/resolver_api.c']:
        raise ValueError('required condition failed at original line 12')
    bodies = {name: extract(text, name) for name in ['check_disconnect', 'reconnect']}
    inputs = dict(build['inputs'])
    inputs.update({str(a.c_build.resolve()): sha(a.c_build), str(source.resolve()): sha(source), str(pathlib.Path(__file__).resolve()): sha(__file__), str(pathlib.Path(__file__).with_name('paired.py')): sha(pathlib.Path(__file__).with_name('paired.py'))})
    for (k, v) in inputs.items():
        if not sha(k) == v:
            raise ValueError(k)
    prelude = '#include "platform.h"\n#include "gnunet_util_lib.h"\nstruct GNUNET_RESOLVER_RequestHandle {struct GNUNET_RESOLVER_RequestHandle *next,*prev;int was_transmitted;};\nstatic struct GNUNET_RESOLVER_RequestHandle *req_head,*req_tail;\nstatic struct GNUNET_MQ_Handle *mq;\nstatic struct GNUNET_SCHEDULER_Task *r_task,*s_task;\nstatic struct GNUNET_CONFIGURATION_Handle *resolver_cfg;\nstatic struct GNUNET_TIME_Relative backoff;\nstatic void shutdown_task(void *cls){(void)cls;abort();}\nstatic void reconnect_task(void *cls){(void)cls;abort();}\nstruct Record {void *identity;int active;const char *callback;uint64_t delay;};\nstatic struct Record records[8];static unsigned used,cancels;\nstatic struct GNUNET_SCHEDULER_Task *observe_add(struct GNUNET_TIME_Relative delay,void (*callback)(void*),void *cls){GNUNET_assert(used<8);GNUNET_assert(cls==NULL);void *identity=GNUNET_malloc(1);records[used++]=(struct Record){identity,1,callback==shutdown_task?"idle":(callback==reconnect_task?"retry":"unexpected"),delay.rel_value_us};return identity;}\nstatic void *observe_cancel(struct GNUNET_SCHEDULER_Task *task){for(unsigned i=0;i<used;i++)if(records[i].identity==task){GNUNET_assert(records[i].active);records[i].active=0;cancels++;return NULL;}abort();}\n#define GNUNET_SCHEDULER_add_delayed observe_add\n#define GNUNET_SCHEDULER_cancel observe_cancel\n#define LOG(...) ((void)0)\n'
    main = 'int main(void){resolver_cfg=GNUNET_CONFIGURATION_create(GNUNET_OS_project_data_gnunet());backoff=GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MILLISECONDS,2);req_head=req_tail=GNUNET_new(struct GNUNET_RESOLVER_RequestHandle);req_head->was_transmitted=GNUNET_SYSERR;reconnect();GNUNET_assert(req_head==NULL&&req_tail==NULL&&r_task!=NULL&&s_task!=NULL);GNUNET_assert(used==2&&records[0].delay==1000&&records[1].delay==2000&&backoff.rel_value_us==4000);reconnect();GNUNET_assert(used==2);printf("{\\"head_removed\\":true,\\"schedules\\":[");for(unsigned i=0;i<used;i++)printf("%s{\\"callback\\":\\"%s\\",\\"delay_us\\":%llu}",i?",":"",records[i].callback,(unsigned long long)records[i].delay);printf("],\\"next_backoff_us\\":%llu,\\"existing_retry_preserved\\":true,\\"cancel_calls\\":%u}\\n",(unsigned long long)backoff.rel_value_us,cancels);for(unsigned i=0;i<used;i++)GNUNET_free(records[i].identity);GNUNET_CONFIGURATION_destroy(resolver_cfg);return 0;}\n'
    caller = a.output / 'component.c'
    caller.write_text(prelude + '\n' + bodies['check_disconnect'] + '\n' + bodies['reconnect'] + '\n' + main)
    binary = a.output / 'component'
    argv = build['argv'].copy()
    idx = next((i for (i, v) in enumerate(argv) if v.endswith('/tools/public_broker.c')))
    argv[idx] = str(caller)
    argv[argv.index('-o') + 1] = str(binary)
    proc = subprocess.run(argv, cwd=build['cwd'], capture_output=True)
    (a.output / 'compile.stdout').write_bytes(proc.stdout)
    (a.output / 'compile.stderr').write_bytes(proc.stderr)
    if not proc.returncode == 0:
        raise ValueError(proc.stderr.decode())
    env = os.environ.copy()
    env.update(normal['runtime_environment'])
    before = sha(binary)
    actor = subprocess.run([str(binary)], env=env, capture_output=True, timeout=3)
    (a.output / 'stdout').write_bytes(actor.stdout)
    (a.output / 'stderr').write_bytes(actor.stderr)
    if not actor.returncode == 0:
        raise ValueError(actor.stderr)
    data = json.loads(actor.stdout)
    if not data == {'head_removed': True, 'schedules': [{'callback': 'idle', 'delay_us': 1000}, {'callback': 'retry', 'delay_us': 2000}], 'next_backoff_us': 4000, 'existing_retry_preserved': True, 'cancel_calls': 0}:
        raise ValueError('required condition failed at original line 34')
    unchanged = sha(binary) == before and all((sha(k) == v for (k, v) in inputs.items()))
    if not unchanged:
        raise ValueError('required condition failed at original line 34')
    result = {'status': 'passed', 'scope': 'Exact two upstream function bodies, normal util time/DLL/allocation; observational scheduler shims record callback/delay and never execute or fabricate a network connection. Not normal scheduler integration. Rust linkage is pure test sole_canceled_head_reconnect_schedules_original_retry_before_next_admission.', 'inputs': inputs, 'extracted_functions': {k: {'sha256': __import__('hashlib').sha256(v.encode()).hexdigest(), 'lines': len(v.splitlines())} for (k, v) in bodies.items()}, 'generated_source': {'path': str(caller), 'sha256': sha(caller)}, 'binary': {'path': str(binary), 'sha256': before}, 'exit_code': actor.returncode, 'observation': data, 'inputs_unchanged': unchanged}
    (a.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'status': 'passed', 'result': str(a.output / 'result.json')}))
if __name__ == '__main__':
    main()
