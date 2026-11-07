/* Only public filename selection; no files are created and no config is loaded. */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <stdio.h>
int main(int argc,char**argv){if(argc!=2)return 2;struct GNUNET_OS_ProjectData pd=*GNUNET_OS_project_data_gnunet();pd.config_file=argv[1];pd.project_dirname=argv[1];char*user;GNUNET_asprintf(&user,"~/.config/%s",argv[1]);pd.user_config_file=user;char*name=GNUNET_CONFIGURATION_default_filename(&pd);if(name){printf("SOME %s\n",name);GNUNET_free(name);}else puts("NONE");GNUNET_free(user);return 0;}
