#!/usr/bin/env python3
"""Full original set_user_id body with one declared fixture name-source port.
This is a source component oracle, not evidence that normal USERNAME filename
configuration can select an ordinary account in this pinned C implementation.
"""
import argparse,hashlib,json,pathlib
from _common import require_disjoint_output,workspace_root

def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
def main():
    ap=argparse.ArgumentParser();ap.add_argument('--package',type=pathlib.Path,default=pathlib.Path(__file__).resolve().parents[1]);ap.add_argument('--source',type=pathlib.Path,required=True);ap.add_argument('--output',type=pathlib.Path,required=True);a=ap.parse_args();require_disjoint_output(a.output,[workspace_root(a.package),a.source,pathlib.Path(__file__).resolve().parent]);a.output.mkdir(exist_ok=False);path=a.source/'src/lib/util/service.c';text=path.read_text();assert sha(path)=='51d9a618682670f23bd6450531e91ca56b0b626bb0ef0d4eb269508a45801dae','unreviewed upstream service.c';name=text.index('\nset_user_id (');start=text.rfind('static enum GNUNET_GenericReturnValue',0,name);brace=text.index('{',name);depth=1;end=brace+1
    while depth:
        if text[end]=='{':depth+=1
        elif text[end]=='}':depth-=1
        end+=1
    function=text[start:end];assert hashlib.sha256(function.encode()).hexdigest()=='64eb969360782519d34e89b8aea784dbc4b77c27a01b48cd1e1fc8554e72d9e6','unreviewed set_user_id body';assert function.count('setregid')==1 and function.count('initgroups')==1
    prefix=r'''/* Test-only extracted original AGPL3.0-or-later GNUnet function.
The sole fixture port get_user_name returns argv's current account without
filename expansion. All set-id/group syscalls below remain actual native calls. */
#include "platform.h"
#include "gnunet_util_lib.h"
static const char *name_port;
static const char *calls[16];static unsigned call_count;
static uid_t allowed_uid;static gid_t allowed_gid;
static char *get_user_name(struct GNUNET_SERVICE_Handle *unused){(void)unused;return GNUNET_strdup(name_port);}
#define LOG(...) do{}while(0)
static int sg(gid_t g){calls[call_count++]="SetGid";if(g!=allowed_gid){errno=EPERM;return -1;}return setgid(g);}
static int seg(gid_t g){calls[call_count++]="SetEffectiveGid";if(g!=allowed_gid){errno=EPERM;return -1;}return setegid(g);}
static int ig(const char *n,int g){calls[call_count++]="InitGroups";if((gid_t)g!=allowed_gid){errno=EPERM;return -1;}return initgroups(n,g);}
static int su(uid_t u){calls[call_count++]="SetUid";if(u!=allowed_uid){errno=EPERM;return -1;}return setuid(u);}
static int seu(uid_t u){calls[call_count++]="SetEffectiveUid";if(u!=allowed_uid){errno=EPERM;return -1;}return seteuid(u);}
static int srg(gid_t r,gid_t e){calls[call_count++]="SetBothGid";if(r!=allowed_gid||e!=allowed_gid){errno=EPERM;return -1;}return setregid(r,e);}
static int sru(uid_t r,uid_t e){calls[call_count++]="SetBothUid";if(r!=allowed_uid||e!=allowed_uid){errno=EPERM;return -1;}return setreuid(r,e);}
#define setgid sg
#define setegid seg
#define initgroups ig
#define setuid su
#define seteuid seu
#define setregid srg
#define setreuid sru
'''
    suffix=r'''
int main(int argc,char **argv){if(argc!=2)return 2;name_port=argv[1];allowed_uid=getuid();allowed_gid=getgid();int ret=set_user_id(NULL);printf("{\"result\":%d,\"ids\":[%u,%u,%u,%u],\"calls\":[",ret,(unsigned)getuid(),(unsigned)geteuid(),(unsigned)getgid(),(unsigned)getegid());for(unsigned i=0;i<call_count;i++)printf("%s\"%s\"",i?",":"",calls[i]);puts("]}");return ret==GNUNET_OK?0:3;}
'''
    generated=a.output/'credential-component.c';generated.write_text(prefix+function+suffix);receipt={'kind':'source-component-original-body-not-normal-config-success','source':{'path':str(path),'sha256':sha(path)},'function_body_sha256':hashlib.sha256(function.encode()).hexdigest(),'function_body':function,'fixture_port':'get_user_name returns explicit current account; no filename expansion','native_syscalls':'actual original operations, guarded to current uid/gid only','generated':{'path':str(generated),'sha256':sha(generated)},'generator':{'path':str(pathlib.Path(__file__).resolve()),'sha256':sha(__file__)}};(a.output/'result.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps({'generated':str(generated),'result':str(a.output/'result.json')}))
if __name__=='__main__':main()
