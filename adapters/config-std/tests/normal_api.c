/* Test-only caller of the unmodified normal GNUnet configuration public APIs. */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <inttypes.h>
#define CHECK(x) do{if(!(x)){fprintf(stderr,"failed line %d\n",__LINE__);exit(2);}}while(0)
static void row(const char *name,const void *data,size_t n){printf("%s|",name);for(size_t i=0;i<n;i++)printf("%02x",((const unsigned char*)data)[i]);puts("");}
static void number(const char *name,int64_t value){printf("%s|%"PRId64"\n",name,value);}
static void value(struct GNUNET_CONFIGURATION_Handle *c,const char *name,const char *s,const char *k){char *v=NULL;int r=GNUNET_CONFIGURATION_get_value_string(c,s,k,&v);number(name,r);if(v){row(name,v,strlen(v));GNUNET_free(v);}}
static void serial(const char *name,struct GNUNET_CONFIGURATION_Handle *c){size_t n;char *v=GNUNET_CONFIGURATION_serialize(c,&n);row(name,v,n);GNUNET_free(v);}
static void each(void *cls,const char *s,const char *k,const char *v){(*(int*)cls)++;row("iter-section",s,strlen(s));row("iter-key",k,strlen(k));row("iter-value",v,strlen(v));}
static void section(void *cls,const char *s){(*(int*)cls)++;row("section",s,strlen(s));}
static enum GNUNET_GenericReturnValue filename(void *cls,const char *name){int *count=cls;(*count)++;row("filename",name,strlen(name));return GNUNET_OK;}
static enum GNUNET_GenericReturnValue abort_filename(void *cls,const char *name){(*(int*)cls)++;(void)name;return GNUNET_SYSERR;}
static void clean(void *cls,const char *s,const char *k,unsigned line){(*(int*)cls)++;row("clean-section",s,strlen(s));row("clean-key",k,strlen(k));number("clean-line",line);}
static enum GNUNET_GenericReturnValue configured(void *cls,const struct GNUNET_CONFIGURATION_Handle *cfg){(*(int*)cls)++;CHECK(GNUNET_YES==GNUNET_CONFIGURATION_have_value(cfg,"demo","number"));return GNUNET_NO;}
int main(int argc,char **argv){
 CHECK(argc==2);CHECK(GNUNET_OK==GNUNET_log_setup("configuration-normal-api","ERROR",NULL));
 const struct GNUNET_OS_ProjectData *pd=GNUNET_OS_project_data_gnunet();char main[4096],written[4096],diff_file[4096],empty[4096],ignored[4096];
 CHECK(snprintf(main,sizeof main,"%s/main.conf",argv[1])>0);snprintf(written,sizeof written,"%s/written.conf",argv[1]);snprintf(diff_file,sizeof diff_file,"%s/diff.conf",argv[1]);snprintf(empty,sizeof empty,"%s/empty",argv[1]);snprintf(ignored,sizeof ignored,"%s/ignored",argv[1]);
 struct GNUNET_CONFIGURATION_Handle *c=GNUNET_CONFIGURATION_create(pd);number("project-identity",GNUNET_CONFIGURATION_get_project_data(c)==pd);number("new-dirty",GNUNET_CONFIGURATION_is_dirty(c));serial("new",c);
 char *default_name=GNUNET_CONFIGURATION_default_filename(pd);row("default-file",default_name?default_name:"",default_name?strlen(default_name):0);GNUNET_free(default_name);
 number("empty-directory",GNUNET_CONFIGURATION_load_from(c,empty));number("ignored-directory",GNUNET_CONFIGURATION_load_from(c,ignored));
 GNUNET_CONFIGURATION_enable_diagnostics(c);CHECK(GNUNET_OK==GNUNET_CONFIGURATION_load(c,main));serial("loaded",c);
 char *expanded=GNUNET_CONFIGURATION_expand_dollar(c,GNUNET_strdup("$DATADIR/relative"));row("dollar",expanded,strlen(expanded));GNUNET_free(expanded);
 struct GNUNET_CONFIGURATION_Handle *memory=GNUNET_CONFIGURATION_create(pd);const char input[]="[memory]\nx=raw\n";number("deserialize",GNUNET_CONFIGURATION_deserialize(memory,input,sizeof(input)-1,NULL));number("parse",GNUNET_CONFIGURATION_parse(memory,main));value(memory,"memory-value","memory","x");GNUNET_CONFIGURATION_destroy(memory);
 char *d=GNUNET_CONFIGURATION_serialize_diagnostics(c);row("diagnostics",d,strlen(d));GNUNET_free(d);d=GNUNET_CONFIGURATION_serialize_diagnostics_verbose(c);row("verbose",d,strlen(d));GNUNET_free(d);
 unsigned long long n=0;float f=0;struct GNUNET_TIME_Relative t;unsigned char data[2];const char *choice=NULL;const char *choices[]={"RED","GREEN",NULL};
 CHECK(GNUNET_OK==GNUNET_CONFIGURATION_get_value_number(c,"demo","number",&n));number("number",(int64_t)n);CHECK(GNUNET_OK==GNUNET_CONFIGURATION_get_value_float(c,"demo","float",&f));uint32_t fb;memcpy(&fb,&f,4);number("float-bits",fb);
 CHECK(GNUNET_OK==GNUNET_CONFIGURATION_get_value_size(c,"demo","size",&n));number("size",n);CHECK(GNUNET_OK==GNUNET_CONFIGURATION_get_value_time(c,"demo","time",&t));number("time",t.rel_value_us);number("yes",GNUNET_CONFIGURATION_get_value_yesno(c,"demo","yes"));CHECK(GNUNET_OK==GNUNET_CONFIGURATION_get_value_choice(c,"demo","choice",choices,&choice));row("choice",choice,strlen(choice));CHECK(GNUNET_OK==GNUNET_CONFIGURATION_get_data(c,"demo","data",data,2));row("data",data,2);
 int count=0;GNUNET_CONFIGURATION_iterate_section_values(c,"DEMO",&each,&count);number("section-count",count);count=0;GNUNET_CONFIGURATION_iterate_sections(c,&section,&count);number("sections-count",count);count=0;GNUNET_CONFIGURATION_iterate(c,&each,&count);number("all-count",count);
 count=0;number("filename-count",GNUNET_CONFIGURATION_iterate_value_filenames(c,"demo","files",&filename,&count));count=0;number("filename-abort",GNUNET_CONFIGURATION_iterate_value_filenames(c,"demo","files",&abort_filename,&count));number("filename-abort-calls",count);
 number("append",GNUNET_CONFIGURATION_append_value_filename(c,"demo","files","/new path"));number("append-again",GNUNET_CONFIGURATION_append_value_filename(c,"demo","files","/new path"));number("remove",GNUNET_CONFIGURATION_remove_value_filename(c,"demo","files","/new path"));
 char *path=NULL;CHECK(GNUNET_OK==GNUNET_CONFIGURATION_get_value_filename(c,"demo","path",&path));row("filename-expanded",path,strlen(path));GNUNET_free(path);
 GNUNET_CONFIGURATION_set_value_number(c,"scratch","number",UINT64_MAX);GNUNET_CONFIGURATION_set_value_float(c,"scratch","float",-1.25f);value(c,"set-float","scratch","float");GNUNET_CONFIGURATION_set_value_string(c,"scratch","remove","yes");GNUNET_CONFIGURATION_set_value_string(c,"scratch","remove",NULL);number("tombstone-have",GNUNET_CONFIGURATION_have_value(c,"scratch","remove"));number("setter-dirty",GNUNET_CONFIGURATION_is_dirty(c));GNUNET_CONFIGURATION_remove_section(c,"scratch");number("removed-dirty",GNUNET_CONFIGURATION_is_dirty(c));
 struct GNUNET_CONFIGURATION_Handle *copy=GNUNET_CONFIGURATION_dup(c);serial("duplicate",copy);GNUNET_CONFIGURATION_set_value_string(copy,"demo","value","different");struct GNUNET_CONFIGURATION_Handle *diff=GNUNET_CONFIGURATION_get_diff(c,copy);serial("diff",diff);number("write-diff",GNUNET_CONFIGURATION_write_diffs(c,copy,diff_file));number("write",GNUNET_CONFIGURATION_write(c,written));number("written-dirty",GNUNET_CONFIGURATION_is_dirty(c));
 unsigned removed=0;count=0;number("clean",GNUNET_CONFIGURATION_clean_file(c,main,&clean,&count,&removed));number("clean-count",removed);number("clean-callbacks",count);
 count=0;number("parse-and-run",GNUNET_CONFIGURATION_parse_and_run(pd,main,&configured,&count));number("parse-and-run-calls",count);
 GNUNET_CONFIGURATION_set_value_string(c,"PATHS","SUID_BINARY_PATH","/test/raw/$UNEXPANDED/");path=GNUNET_CONFIGURATION_get_suid_binary_path(pd,c,"helper");row("suid",path,strlen(path));GNUNET_free(path);GNUNET_CONFIGURATION_set_value_string(c,"PATHS","SUID_BINARY_PATH","/changed");path=GNUNET_CONFIGURATION_get_suid_binary_path(pd,c,"helper");row("suid-cached",path,strlen(path));GNUNET_free(path);path=GNUNET_CONFIGURATION_get_suid_binary_path(pd,c,"/absolute/helper");row("suid-absolute",path,strlen(path));GNUNET_free(path);
 struct GNUNET_CONFIGURATION_ConfigSettings settings={.api_version=GNUNET_UTIL_VERSION,.section=GNUNET_strdup("demo"),.option=GNUNET_strdup("value")};
 FILE *saved=stdout;char *tool=NULL;size_t tool_len=0;stdout=open_memstream(&tool,&tool_len);CHECK(stdout);GNUNET_CONFIGURATION_config_tool_run(&settings,NULL,main,c);CHECK(0==fclose(stdout));stdout=saved;row("tool-query",tool,tool_len);GNUNET_free(tool);number("tool-ret",settings.global_ret);GNUNET_CONFIGURATION_config_settings_free(&settings);number("settings-freed",!settings.section&&!settings.option&&!settings.value);
 GNUNET_CONFIGURATION_destroy(diff);GNUNET_CONFIGURATION_destroy(copy);GNUNET_CONFIGURATION_destroy(c);return 0;
}
