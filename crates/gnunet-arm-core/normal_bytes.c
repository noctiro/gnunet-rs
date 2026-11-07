/* New read-only native-layout caller. Official headers/build/config stay intact.
 * No ARM API/startup/process-control/network operation is performed. */
#include "platform.h"
#include "gnunet_arm_service.h"
#include "arm.h"
#include <stddef.h>
static uint64_t be64(uint64_t x) { return htonl(1)==1 ? x : __builtin_bswap64(x); }
static void emit(const char *label, void *p, size_t n, uint16_t type) {
 if (NULL == p) exit(1);
 struct GNUNET_MessageHeader *h=p; h->size=htons(n); h->type=htons(type);
 printf("{\"kind\":\"frame\",\"label\":\"%s\",\"size\":%zu,\"hex\":\"",label,n);
 for(size_t i=0;i<n;i++) printf("%02x",((unsigned char*)p)[i]);
 printf("\"}\n"); free(p);
}
int main(void) {
 printf("{\"kind\":\"layout\",\"message\":%zu,\"result\":%zu,\"list\":%zu,\"info\":%zu,\"status\":%zu,\"message_align\":%zu,\"result_field\":%zu,\"list_count\":%zu,\"info_restart\":%zu,\"info_last_start\":%zu}\n",sizeof(struct GNUNET_ARM_Message),sizeof(struct GNUNET_ARM_ResultMessage),sizeof(struct GNUNET_ARM_ListResultMessage),sizeof(struct GNUNET_ARM_ServiceInfoMessage),sizeof(struct GNUNET_ARM_StatusMessage),_Alignof(struct GNUNET_ARM_Message),offsetof(struct GNUNET_ARM_ResultMessage,result),offsetof(struct GNUNET_ARM_ListResultMessage,count),offsetof(struct GNUNET_ARM_ServiceInfoMessage,restart_at),offsetof(struct GNUNET_ARM_ServiceInfoMessage,last_started_at));
 const uint64_t id=be64(UINT64_C(0x0102030405060708));
 for(unsigned i=0;i<2;i++) { size_t n=sizeof(struct GNUNET_ARM_Message)+4; struct GNUNET_ARM_Message *m=calloc(1,n);if(!m)return 1;m->request_id=id;memcpy(&m[1],"svc",4);emit(i?"STOP":"START",m,n,i?GNUNET_MESSAGE_TYPE_ARM_STOP:GNUNET_MESSAGE_TYPE_ARM_START); }
 struct GNUNET_ARM_Message *list=calloc(1,sizeof(*list));if(!list)return 1;list->request_id=id;emit("LIST",list,sizeof(*list),GNUNET_MESSAGE_TYPE_ARM_LIST);
 emit("MONITOR",calloc(1,sizeof(struct GNUNET_MessageHeader)),sizeof(struct GNUNET_MessageHeader),GNUNET_MESSAGE_TYPE_ARM_MONITOR);
 emit("TEST",calloc(1,sizeof(struct GNUNET_MessageHeader)),sizeof(struct GNUNET_MessageHeader),GNUNET_MESSAGE_TYPE_ARM_TEST);
 struct GNUNET_ARM_ResultMessage *r=calloc(1,sizeof(*r));if(!r)return 1;r->arm_msg.request_id=id;r->result=htonl(0x10111213);emit("RESULT",r,sizeof(*r),GNUNET_MESSAGE_TYPE_ARM_RESULT);
 size_t n=sizeof(struct GNUNET_ARM_StatusMessage)+4;struct GNUNET_ARM_StatusMessage *s=calloc(1,n);if(!s)return 1;s->status=htonl(0x10111213);memcpy(&s[1],"arm",4);emit("STATUS",s,n,GNUNET_MESSAGE_TYPE_ARM_STATUS);
 n=sizeof(struct GNUNET_ARM_ListResultMessage)+sizeof(struct GNUNET_ARM_ServiceInfoMessage)+7;struct GNUNET_ARM_ListResultMessage *l=calloc(1,n);if(!l)return 1;l->arm_msg.request_id=id;l->count=htons(1);struct GNUNET_ARM_ServiceInfoMessage *info=(void*)&l[1];info->name_index=htons(0);info->binary_index=htons(4);info->last_exit_status=htons((uint16_t)-1);info->status=htonl(GNUNET_ARM_SERVICE_STATUS_FAILED);info->restart_at.abs_value_us__=be64(9);info->last_started_at.abs_value_us__=be64(10);memcpy(&info[1],"svc\0bn",7);int promoted=ntohs(info->last_exit_status);emit("LIST_RESULT",l,n,GNUNET_MESSAGE_TYPE_ARM_LIST_RESULT);
 printf("{\"kind\":\"public_exit_status\",\"value\":%d}\n",promoted);return 0;
}
