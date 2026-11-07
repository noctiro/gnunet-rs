/* Standard gettext native ABI oracle, distinct from GNUnet's ENABLE_NLS=0 library. */
#include <locale.h>
#include <libintl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static void row(const char*name,const char*value){printf("%s ",name);for(const unsigned char*p=(const unsigned char*)value;*p;p++)printf("%02x",*p);putchar('\n');}
int main(int argc,char**argv){if(argc!=2)return 2;int selected=setlocale(LC_ALL,"")!=NULL;printf("SELECTED %d\n",selected);row("LOCALE",setlocale(LC_MESSAGES,NULL));if(!bindtextdomain("gnunet",argv[1])||!bindtextdomain("owned-project",argv[1])||!textdomain("owned-project"))return 3;row("DOMAIN",textdomain(NULL));row("GET",gettext("Owned help"));row("DGET",dgettext("gnunet","ERROR"));row("FALLBACK",gettext("untranslated owned message"));
 for(unsigned long i=0;i<3;i++){char name[32];snprintf(name,sizeof(name),"NGET%lu",i);row(name,ngettext("one item","many items",i));snprintf(name,sizeof(name),"DNGET%lu",i);row(name,dngettext("gnunet","one item","many items",i));}
 char text[4096];snprintf(text,sizeof(text),dgettext("gnunet","Option `%s' can't be used with other options.\n"),"raw%value");row("FORMAT",text);snprintf(text,sizeof(text),dgettext("gnunet","Message `%.*s' repeated %u times in the last %s\n"),3,"abcdef",42u,"2 s");row("BULK",text);row("UNSAFE_FORMAT_DATA_ONLY",dgettext("gnunet","unsafe source %s"));return 0;}
