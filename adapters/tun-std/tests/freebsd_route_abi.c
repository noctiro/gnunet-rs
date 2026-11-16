/* Independent checks against the host's installed FreeBSD Netlink headers. */
#include <sys/types.h>
#include <sys/socket.h>
#include <netlink/netlink.h>
#include <netlink/route/common.h>
#include <netlink/route/route.h>
#include <stddef.h>
#include <stdio.h>

int main(void) {
  const unsigned long long values[] = {
    sizeof(struct sockaddr_nl), _Alignof(struct sockaddr_nl),
    offsetof(struct sockaddr_nl, nl_family), offsetof(struct sockaddr_nl, nl_pid),
    offsetof(struct sockaddr_nl, nl_groups), AF_NETLINK, NETLINK_ROUTE,
    sizeof(struct nlmsghdr), offsetof(struct nlmsghdr, nlmsg_seq),
    sizeof(struct rtmsg), offsetof(struct rtmsg, rtm_flags),
    sizeof(struct nlattr), NL_RTM_NEWROUTE, NL_RTM_DELROUTE, NL_RTM_GETROUTE,
    NLM_F_REQUEST, NLM_F_MULTI, NLM_F_ACK, NLM_F_DUMP_INTR, NLM_F_DUMP,
    NLM_F_EXCL, NLM_F_CREATE, NLMSG_NOOP, NLMSG_ERROR, NLMSG_DONE, NLMSG_OVERRUN,
    RTPROT_STATIC, RT_SCOPE_UNIVERSE, RTN_UNICAST, RTM_F_CLONED,
    NL_RTA_DST, NL_RTA_OIF, NL_RTA_GATEWAY, NL_RTA_PRIORITY, NL_RTA_PREFSRC,
    NL_RTA_METRICS, NL_RTA_CACHEINFO, NL_RTA_TABLE,
    NL_RTA_KNH_ID, NL_RTA_WEIGHT, NL_RTA_RTFLAGS, NL_RTA_EXPIRES, NL_RTA_NH_ID,
    RT_TABLE_MAIN, RT_TABLE_UNSPEC
  };
  for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
    printf("%s%llu", i == 0 ? "" : " ", values[i]);
  putchar('\n');
  return 0;
}
