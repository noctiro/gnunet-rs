/* Ordinary public API caller: construct path strings only; execute no returned path. */
#include "gnunet_util_lib.h"
#include <stdio.h>
#include <string.h>

static void emit(const char *name,char *path) {
  printf("%s|",name);
  for(const unsigned char *p=(const unsigned char *)path;*p;p++)printf("%02x",*p);
  printf("\n");GNUNET_free(path);
}
static void resolve(const char *name,const struct GNUNET_OS_ProjectData *pd,
                    const struct GNUNET_CONFIGURATION_Handle *cfg,const char *program) {
  emit(name,GNUNET_CONFIGURATION_get_suid_binary_path(pd,cfg,program));
}
int main(int argc,char **argv) {
  if(argc!=4)return 89;
  (void)argv[1];(void)argv[3];
  struct GNUNET_OS_ProjectData a=*GNUNET_OS_project_data_gnunet();
  a.project_dirname="config-a";a.env_varname="GCFG_SUID_A";a.env_varname_alt=NULL;
  struct GNUNET_OS_ProjectData b=a,c=a;
  b.project_dirname="supplied-b";b.env_varname="GCFG_SUID_B";
  c.project_dirname="supplied-c";c.env_varname="GCFG_SUID_C";
  struct GNUNET_CONFIGURATION_Handle *cfg=GNUNET_CONFIGURATION_create(&a);
  const char *mode=argv[2];
  if(!strcmp(mode,"libexec-b-first")) {
    GNUNET_CONFIGURATION_set_value_string(cfg,"PATHS","SUID_BINARY_PATH","/unused/override");
    emit("first",GNUNET_OS_get_libexec_binary_path(&b,"plain-helper"));
    emit("second",GNUNET_OS_get_libexec_binary_path(&c,"plain-helper"));
    GNUNET_CONFIGURATION_set_value_string(cfg,"PATHS","SUID_BINARY_PATH",NULL);
    resolve("fallback",&c,cfg,"plain-helper");
  } else if(!strcmp(mode,"suid-then-libexec")) {
    resolve("first",&b,cfg,"plain-helper");
    emit("second",GNUNET_OS_get_libexec_binary_path(&c,"plain-helper"));
    emit("absolute",GNUNET_OS_get_libexec_binary_path(&c,"/ordinary/absolute-helper"));
  } else if(!strcmp(mode,"libexec-absolute-first")) {
    emit("absolute",GNUNET_OS_get_libexec_binary_path(&b,"/ordinary/absolute-helper"));
    emit("first",GNUNET_OS_get_libexec_binary_path(&c,"plain-helper"));
    emit("second",GNUNET_OS_get_libexec_binary_path(&b,"plain-helper"));
  } else if(!strcmp(mode,"libexec-empty")) {
    emit("empty",GNUNET_OS_get_libexec_binary_path(&b,""));
    emit("first",GNUNET_OS_get_libexec_binary_path(&c,"plain-helper"));
  } else if(!strcmp(mode,"b-first")) {
    resolve("first",&b,cfg,"plain-helper");resolve("second",&c,cfg,"plain-helper");resolve("third",&a,cfg,"plain-helper");
  } else if(!strcmp(mode,"c-first")) {
    resolve("first",&c,cfg,"plain-helper");resolve("second",&b,cfg,"plain-helper");
  } else if(!strcmp(mode,"absolute-first")) {
    resolve("absolute",&b,cfg,"/ordinary/absolute-helper");resolve("first",&c,cfg,"plain-helper");resolve("second",&b,cfg,"plain-helper");
  } else if(!strcmp(mode,"raw-override")) {
    GNUNET_CONFIGURATION_set_value_string(cfg,"PATHS","SUID_BINARY_PATH","/raw/$UNEXPANDED/");
    resolve("first",&b,cfg,"plain-helper");
    GNUNET_CONFIGURATION_set_value_string(cfg,"PATHS","SUID_BINARY_PATH","/changed");
    resolve("second",&c,cfg,"plain-helper");resolve("absolute",&c,cfg,"/ordinary/absolute-helper");
  } else if(!strcmp(mode,"empty-then-override")) {
    GNUNET_CONFIGURATION_set_value_string(cfg,"PATHS","SUID_BINARY_PATH","");
    resolve("fallback",&b,cfg,"plain-helper");
    GNUNET_CONFIGURATION_set_value_string(cfg,"PATHS","SUID_BINARY_PATH","/raw/$UNEXPANDED/");
    resolve("first",&c,cfg,"plain-helper");
    GNUNET_CONFIGURATION_set_value_string(cfg,"PATHS","SUID_BINARY_PATH","/changed");
    resolve("second",&a,cfg,"plain-helper");
  } else if(!strcmp(mode,"self-project")) {
    resolve("first",&a,cfg,"plain-helper");resolve("second",&b,cfg,"plain-helper");
  } else {GNUNET_CONFIGURATION_destroy(cfg);return 88;}
  GNUNET_CONFIGURATION_destroy(cfg);return 0;
}
