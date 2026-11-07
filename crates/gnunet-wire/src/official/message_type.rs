//! Numeric assignments from GNUnet v0.29.1 `src/include/gnunet_protocols.h`.
//! Registry presence does not mean that a service codec or state machine is implemented.
//! Source commit: `346358e26d4dcc2dc4f51bef5d52dca29c7d8165`.
//! Header SHA256: `9a86ea10c53da11d68c255fa732d24f9d8695a6405396b965893384d3c952392`.
use super::MessageType;

/// Official `GNUNET_MESSAGE_TYPE_TEST` assignment.
pub const TEST: MessageType = MessageType::new(0);
/// Official `GNUNET_MESSAGE_TYPE_REQUEST_AGPL` assignment.
pub const REQUEST_AGPL: MessageType = MessageType::new(1);
/// Official `GNUNET_MESSAGE_TYPE_RESPONSE_AGPL` assignment.
pub const RESPONSE_AGPL: MessageType = MessageType::new(2);
/// Official `GNUNET_MESSAGE_TYPE_RESOLVER_REQUEST` assignment.
pub const RESOLVER_REQUEST: MessageType = MessageType::new(4);
/// Official `GNUNET_MESSAGE_TYPE_RESOLVER_RESPONSE` assignment.
pub const RESOLVER_RESPONSE: MessageType = MessageType::new(5);
/// Official `GNUNET_MESSAGE_TYPE_DUMMY` assignment.
pub const DUMMY: MessageType = MessageType::new(6);
/// Official `GNUNET_MESSAGE_TYPE_DUMMY2` assignment.
pub const DUMMY2: MessageType = MessageType::new(7);
/// Official `GNUNET_MESSAGE_TYPE_ARM_START` assignment.
pub const ARM_START: MessageType = MessageType::new(8);
/// Official `GNUNET_MESSAGE_TYPE_ARM_STOP` assignment.
pub const ARM_STOP: MessageType = MessageType::new(9);
/// Official `GNUNET_MESSAGE_TYPE_ARM_RESULT` assignment.
pub const ARM_RESULT: MessageType = MessageType::new(10);
/// Official `GNUNET_MESSAGE_TYPE_ARM_STATUS` assignment.
pub const ARM_STATUS: MessageType = MessageType::new(11);
/// Official `GNUNET_MESSAGE_TYPE_ARM_LIST` assignment.
pub const ARM_LIST: MessageType = MessageType::new(12);
/// Official `GNUNET_MESSAGE_TYPE_ARM_LIST_RESULT` assignment.
pub const ARM_LIST_RESULT: MessageType = MessageType::new(13);
/// Official `GNUNET_MESSAGE_TYPE_ARM_MONITOR` assignment.
pub const ARM_MONITOR: MessageType = MessageType::new(14);
/// Official `GNUNET_MESSAGE_TYPE_ARM_TEST` assignment.
pub const ARM_TEST: MessageType = MessageType::new(15);
/// Official `GNUNET_MESSAGE_TYPE_HELLO_URI` assignment.
pub const HELLO_URI: MessageType = MessageType::new(16);
/// Official `GNUNET_MESSAGE_TYPE_HELLO` assignment.
pub const HELLO: MessageType = MessageType::new(17);
/// Official `GNUNET_MESSAGE_TYPE_FRAGMENT` assignment.
pub const FRAGMENT: MessageType = MessageType::new(18);
/// Official `GNUNET_MESSAGE_TYPE_FRAGMENT_ACK` assignment.
pub const FRAGMENT_ACK: MessageType = MessageType::new(19);
/// Official `GNUNET_MESSAGE_TYPE_WLAN_DATA_TO_HELPER` assignment.
pub const WLAN_DATA_TO_HELPER: MessageType = MessageType::new(39);
/// Official `GNUNET_MESSAGE_TYPE_WLAN_DATA_FROM_HELPER` assignment.
pub const WLAN_DATA_FROM_HELPER: MessageType = MessageType::new(40);
/// Official `GNUNET_MESSAGE_TYPE_WLAN_HELPER_CONTROL` assignment.
pub const WLAN_HELPER_CONTROL: MessageType = MessageType::new(41);
/// Official `GNUNET_MESSAGE_TYPE_WLAN_ADVERTISEMENT` assignment.
pub const WLAN_ADVERTISEMENT: MessageType = MessageType::new(42);
/// Official `GNUNET_MESSAGE_TYPE_WLAN_DATA` assignment.
pub const WLAN_DATA: MessageType = MessageType::new(43);
/// Official `GNUNET_MESSAGE_TYPE_DV_RECV` assignment.
pub const DV_RECV: MessageType = MessageType::new(44);
/// Official `GNUNET_MESSAGE_TYPE_DV_SEND` assignment.
pub const DV_SEND: MessageType = MessageType::new(45);
/// Official `GNUNET_MESSAGE_TYPE_DV_SEND_ACK` assignment.
pub const DV_SEND_ACK: MessageType = MessageType::new(46);
/// Official `GNUNET_MESSAGE_TYPE_DV_ROUTE` assignment.
pub const DV_ROUTE: MessageType = MessageType::new(47);
/// Official `GNUNET_MESSAGE_TYPE_DV_START` assignment.
pub const DV_START: MessageType = MessageType::new(48);
/// Official `GNUNET_MESSAGE_TYPE_DV_CONNECT` assignment.
pub const DV_CONNECT: MessageType = MessageType::new(49);
/// Official `GNUNET_MESSAGE_TYPE_DV_DISCONNECT` assignment.
pub const DV_DISCONNECT: MessageType = MessageType::new(50);
/// Official `GNUNET_MESSAGE_TYPE_DV_SEND_NACK` assignment.
pub const DV_SEND_NACK: MessageType = MessageType::new(51);
/// Official `GNUNET_MESSAGE_TYPE_DV_DISTANCE_CHANGED` assignment.
pub const DV_DISTANCE_CHANGED: MessageType = MessageType::new(52);
/// Official `GNUNET_MESSAGE_TYPE_DV_BOX` assignment.
pub const DV_BOX: MessageType = MessageType::new(53);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_XU_MESSAGE` assignment.
pub const TRANSPORT_XU_MESSAGE: MessageType = MessageType::new(55);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_MESSAGE` assignment.
pub const TRANSPORT_UDP_MESSAGE: MessageType = MessageType::new(56);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_UDP_ACK` assignment.
pub const TRANSPORT_UDP_ACK: MessageType = MessageType::new(57);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_NAT_PROBE` assignment.
pub const TRANSPORT_TCP_NAT_PROBE: MessageType = MessageType::new(60);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_WELCOME` assignment.
pub const TRANSPORT_TCP_WELCOME: MessageType = MessageType::new(61);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_ATS` assignment.
pub const TRANSPORT_ATS: MessageType = MessageType::new(62);
/// Official `GNUNET_MESSAGE_TYPE_NAT_TEST` assignment.
pub const NAT_TEST: MessageType = MessageType::new(63);
/// Official `GNUNET_MESSAGE_TYPE_CORE_INIT` assignment.
pub const CORE_INIT: MessageType = MessageType::new(64);
/// Official `GNUNET_MESSAGE_TYPE_CORE_INIT_REPLY` assignment.
pub const CORE_INIT_REPLY: MessageType = MessageType::new(65);
/// Official `GNUNET_MESSAGE_TYPE_CORE_NOTIFY_CONNECT` assignment.
pub const CORE_NOTIFY_CONNECT: MessageType = MessageType::new(67);
/// Official `GNUNET_MESSAGE_TYPE_CORE_NOTIFY_DISCONNECT` assignment.
pub const CORE_NOTIFY_DISCONNECT: MessageType = MessageType::new(68);
/// Official `GNUNET_MESSAGE_TYPE_CORE_NOTIFY_STATUS_CHANGE` assignment.
pub const CORE_NOTIFY_STATUS_CHANGE: MessageType = MessageType::new(69);
/// Official `GNUNET_MESSAGE_TYPE_CORE_NOTIFY_INBOUND` assignment.
pub const CORE_NOTIFY_INBOUND: MessageType = MessageType::new(70);
/// Official `GNUNET_MESSAGE_TYPE_CORE_NOTIFY_OUTBOUND` assignment.
pub const CORE_NOTIFY_OUTBOUND: MessageType = MessageType::new(71);
/// Official `GNUNET_MESSAGE_TYPE_CORE_SEND_REQUEST` assignment.
pub const CORE_SEND_REQUEST: MessageType = MessageType::new(74);
/// Official `GNUNET_MESSAGE_TYPE_CORE_SEND_READY` assignment.
pub const CORE_SEND_READY: MessageType = MessageType::new(75);
/// Official `GNUNET_MESSAGE_TYPE_CORE_SEND` assignment.
pub const CORE_SEND: MessageType = MessageType::new(76);
/// Official `GNUNET_MESSAGE_TYPE_CORE_MONITOR_PEERS` assignment.
pub const CORE_MONITOR_PEERS: MessageType = MessageType::new(78);
/// Official `GNUNET_MESSAGE_TYPE_CORE_MONITOR_NOTIFY` assignment.
pub const CORE_MONITOR_NOTIFY: MessageType = MessageType::new(79);
/// Official `GNUNET_MESSAGE_TYPE_CORE_INITIATOR_HELLO` assignment.
pub const CORE_INITIATOR_HELLO: MessageType = MessageType::new(80);
/// Official `GNUNET_MESSAGE_TYPE_CORE_RESPONDER_HELLO` assignment.
pub const CORE_RESPONDER_HELLO: MessageType = MessageType::new(81);
/// Official `GNUNET_MESSAGE_TYPE_CORE_INITIATOR_DONE` assignment.
pub const CORE_INITIATOR_DONE: MessageType = MessageType::new(82);
/// Official `GNUNET_MESSAGE_TYPE_CORE_ENCRYPTED_MESSAGE_CAKE` assignment.
pub const CORE_ENCRYPTED_MESSAGE_CAKE: MessageType = MessageType::new(83);
/// Official `GNUNET_MESSAGE_TYPE_CORE_HEARTBEAT` assignment.
pub const CORE_HEARTBEAT: MessageType = MessageType::new(84);
/// Official `GNUNET_MESSAGE_TYPE_CORE_ACK` assignment.
pub const CORE_ACK: MessageType = MessageType::new(85);
/// Official `GNUNET_MESSAGE_TYPE_DATASTORE_RESERVE` assignment.
pub const DATASTORE_RESERVE: MessageType = MessageType::new(92);
/// Official `GNUNET_MESSAGE_TYPE_DATASTORE_RELEASE_RESERVE` assignment.
pub const DATASTORE_RELEASE_RESERVE: MessageType = MessageType::new(93);
/// Official `GNUNET_MESSAGE_TYPE_DATASTORE_STATUS` assignment.
pub const DATASTORE_STATUS: MessageType = MessageType::new(94);
/// Official `GNUNET_MESSAGE_TYPE_DATASTORE_PUT` assignment.
pub const DATASTORE_PUT: MessageType = MessageType::new(95);
/// Official `GNUNET_MESSAGE_TYPE_DATASTORE_GET` assignment.
pub const DATASTORE_GET: MessageType = MessageType::new(97);
/// Official `GNUNET_MESSAGE_TYPE_DATASTORE_GET_REPLICATION` assignment.
pub const DATASTORE_GET_REPLICATION: MessageType = MessageType::new(98);
/// Official `GNUNET_MESSAGE_TYPE_DATASTORE_GET_ZERO_ANONYMITY` assignment.
pub const DATASTORE_GET_ZERO_ANONYMITY: MessageType = MessageType::new(99);
/// Official `GNUNET_MESSAGE_TYPE_DATASTORE_DATA` assignment.
pub const DATASTORE_DATA: MessageType = MessageType::new(100);
/// Official `GNUNET_MESSAGE_TYPE_DATASTORE_DATA_END` assignment.
pub const DATASTORE_DATA_END: MessageType = MessageType::new(101);
/// Official `GNUNET_MESSAGE_TYPE_DATASTORE_REMOVE` assignment.
pub const DATASTORE_REMOVE: MessageType = MessageType::new(102);
/// Official `GNUNET_MESSAGE_TYPE_DATASTORE_DROP` assignment.
pub const DATASTORE_DROP: MessageType = MessageType::new(103);
/// Official `GNUNET_MESSAGE_TYPE_DATASTORE_GET_KEY` assignment.
pub const DATASTORE_GET_KEY: MessageType = MessageType::new(104);
/// Official `GNUNET_MESSAGE_TYPE_FS_REQUEST_LOC_SIGN` assignment.
pub const FS_REQUEST_LOC_SIGN: MessageType = MessageType::new(126);
/// Official `GNUNET_MESSAGE_TYPE_FS_REQUEST_LOC_SIGNATURE` assignment.
pub const FS_REQUEST_LOC_SIGNATURE: MessageType = MessageType::new(127);
/// Official `GNUNET_MESSAGE_TYPE_FS_INDEX_START` assignment.
pub const FS_INDEX_START: MessageType = MessageType::new(128);
/// Official `GNUNET_MESSAGE_TYPE_FS_INDEX_START_OK` assignment.
pub const FS_INDEX_START_OK: MessageType = MessageType::new(129);
/// Official `GNUNET_MESSAGE_TYPE_FS_INDEX_START_FAILED` assignment.
pub const FS_INDEX_START_FAILED: MessageType = MessageType::new(130);
/// Official `GNUNET_MESSAGE_TYPE_FS_INDEX_LIST_GET` assignment.
pub const FS_INDEX_LIST_GET: MessageType = MessageType::new(131);
/// Official `GNUNET_MESSAGE_TYPE_FS_INDEX_LIST_ENTRY` assignment.
pub const FS_INDEX_LIST_ENTRY: MessageType = MessageType::new(132);
/// Official `GNUNET_MESSAGE_TYPE_FS_INDEX_LIST_END` assignment.
pub const FS_INDEX_LIST_END: MessageType = MessageType::new(133);
/// Official `GNUNET_MESSAGE_TYPE_FS_UNINDEX` assignment.
pub const FS_UNINDEX: MessageType = MessageType::new(134);
/// Official `GNUNET_MESSAGE_TYPE_FS_UNINDEX_OK` assignment.
pub const FS_UNINDEX_OK: MessageType = MessageType::new(135);
/// Official `GNUNET_MESSAGE_TYPE_FS_START_SEARCH` assignment.
pub const FS_START_SEARCH: MessageType = MessageType::new(136);
/// Official `GNUNET_MESSAGE_TYPE_FS_GET` assignment.
pub const FS_GET: MessageType = MessageType::new(137);
/// Official `GNUNET_MESSAGE_TYPE_FS_PUT` assignment.
pub const FS_PUT: MessageType = MessageType::new(138);
/// Official `GNUNET_MESSAGE_TYPE_FS_MIGRATION_STOP` assignment.
pub const FS_MIGRATION_STOP: MessageType = MessageType::new(139);
/// Official `GNUNET_MESSAGE_TYPE_FS_CADET_QUERY` assignment.
pub const FS_CADET_QUERY: MessageType = MessageType::new(140);
/// Official `GNUNET_MESSAGE_TYPE_FS_CADET_REPLY` assignment.
pub const FS_CADET_REPLY: MessageType = MessageType::new(141);
/// Official `GNUNET_MESSAGE_TYPE_DHT_CLIENT_PUT` assignment.
pub const DHT_CLIENT_PUT: MessageType = MessageType::new(142);
/// Official `GNUNET_MESSAGE_TYPE_DHT_CLIENT_GET` assignment.
pub const DHT_CLIENT_GET: MessageType = MessageType::new(143);
/// Official `GNUNET_MESSAGE_TYPE_DHT_CLIENT_GET_STOP` assignment.
pub const DHT_CLIENT_GET_STOP: MessageType = MessageType::new(144);
/// Official `GNUNET_MESSAGE_TYPE_DHT_CLIENT_RESULT` assignment.
pub const DHT_CLIENT_RESULT: MessageType = MessageType::new(145);
/// Official `GNUNET_MESSAGE_TYPE_DHT_P2P_PUT` assignment.
pub const DHT_P2P_PUT: MessageType = MessageType::new(146);
/// Official `GNUNET_MESSAGE_TYPE_DHT_P2P_GET` assignment.
pub const DHT_P2P_GET: MessageType = MessageType::new(147);
/// Official `GNUNET_MESSAGE_TYPE_DHT_P2P_RESULT` assignment.
pub const DHT_P2P_RESULT: MessageType = MessageType::new(148);
/// Official `GNUNET_MESSAGE_TYPE_DHT_MONITOR_GET` assignment.
pub const DHT_MONITOR_GET: MessageType = MessageType::new(149);
/// Official `GNUNET_MESSAGE_TYPE_DHT_MONITOR_GET_RESP` assignment.
pub const DHT_MONITOR_GET_RESP: MessageType = MessageType::new(150);
/// Official `GNUNET_MESSAGE_TYPE_DHT_MONITOR_PUT` assignment.
pub const DHT_MONITOR_PUT: MessageType = MessageType::new(151);
/// Official `GNUNET_MESSAGE_TYPE_DHT_MONITOR_PUT_RESP` assignment.
pub const DHT_MONITOR_PUT_RESP: MessageType = MessageType::new(152);
/// Official `GNUNET_MESSAGE_TYPE_DHT_MONITOR_START` assignment.
pub const DHT_MONITOR_START: MessageType = MessageType::new(153);
/// Official `GNUNET_MESSAGE_TYPE_DHT_MONITOR_STOP` assignment.
pub const DHT_MONITOR_STOP: MessageType = MessageType::new(154);
/// Official `GNUNET_MESSAGE_TYPE_DHT_CLIENT_GET_RESULTS_KNOWN` assignment.
pub const DHT_CLIENT_GET_RESULTS_KNOWN: MessageType = MessageType::new(156);
/// Official `GNUNET_MESSAGE_TYPE_DHT_P2P_HELLO` assignment.
pub const DHT_P2P_HELLO: MessageType = MessageType::new(157);
/// Official `GNUNET_MESSAGE_TYPE_DHT_CORE` assignment.
pub const DHT_CORE: MessageType = MessageType::new(158);
/// Official `GNUNET_MESSAGE_TYPE_DHT_CLIENT_HELLO_URL` assignment.
pub const DHT_CLIENT_HELLO_URL: MessageType = MessageType::new(159);
/// Official `GNUNET_MESSAGE_TYPE_DHT_CLIENT_HELLO_GET` assignment.
pub const DHT_CLIENT_HELLO_GET: MessageType = MessageType::new(161);
/// Official `GNUNET_MESSAGE_TYPE_HOSTLIST_ADVERTISEMENT` assignment.
pub const HOSTLIST_ADVERTISEMENT: MessageType = MessageType::new(160);
/// Official `GNUNET_MESSAGE_TYPE_STATISTICS_SET` assignment.
pub const STATISTICS_SET: MessageType = MessageType::new(168);
/// Official `GNUNET_MESSAGE_TYPE_STATISTICS_GET` assignment.
pub const STATISTICS_GET: MessageType = MessageType::new(169);
/// Official `GNUNET_MESSAGE_TYPE_STATISTICS_VALUE` assignment.
pub const STATISTICS_VALUE: MessageType = MessageType::new(170);
/// Official `GNUNET_MESSAGE_TYPE_STATISTICS_END` assignment.
pub const STATISTICS_END: MessageType = MessageType::new(171);
/// Official `GNUNET_MESSAGE_TYPE_STATISTICS_WATCH` assignment.
pub const STATISTICS_WATCH: MessageType = MessageType::new(172);
/// Official `GNUNET_MESSAGE_TYPE_STATISTICS_WATCH_VALUE` assignment.
pub const STATISTICS_WATCH_VALUE: MessageType = MessageType::new(173);
/// Official `GNUNET_MESSAGE_TYPE_STATISTICS_DISCONNECT` assignment.
pub const STATISTICS_DISCONNECT: MessageType = MessageType::new(174);
/// Official `GNUNET_MESSAGE_TYPE_STATISTICS_DISCONNECT_CONFIRM` assignment.
pub const STATISTICS_DISCONNECT_CONFIRM: MessageType = MessageType::new(175);
/// Official `GNUNET_MESSAGE_TYPE_VPN_HELPER` assignment.
pub const VPN_HELPER: MessageType = MessageType::new(185);
/// Official `GNUNET_MESSAGE_TYPE_VPN_ICMP_TO_SERVICE` assignment.
pub const VPN_ICMP_TO_SERVICE: MessageType = MessageType::new(190);
/// Official `GNUNET_MESSAGE_TYPE_VPN_ICMP_TO_INTERNET` assignment.
pub const VPN_ICMP_TO_INTERNET: MessageType = MessageType::new(191);
/// Official `GNUNET_MESSAGE_TYPE_VPN_ICMP_TO_VPN` assignment.
pub const VPN_ICMP_TO_VPN: MessageType = MessageType::new(192);
/// Official `GNUNET_MESSAGE_TYPE_VPN_DNS_TO_INTERNET` assignment.
pub const VPN_DNS_TO_INTERNET: MessageType = MessageType::new(193);
/// Official `GNUNET_MESSAGE_TYPE_VPN_DNS_FROM_INTERNET` assignment.
pub const VPN_DNS_FROM_INTERNET: MessageType = MessageType::new(194);
/// Official `GNUNET_MESSAGE_TYPE_VPN_TCP_TO_SERVICE_START` assignment.
pub const VPN_TCP_TO_SERVICE_START: MessageType = MessageType::new(195);
/// Official `GNUNET_MESSAGE_TYPE_VPN_TCP_TO_INTERNET_START` assignment.
pub const VPN_TCP_TO_INTERNET_START: MessageType = MessageType::new(196);
/// Official `GNUNET_MESSAGE_TYPE_VPN_TCP_DATA_TO_EXIT` assignment.
pub const VPN_TCP_DATA_TO_EXIT: MessageType = MessageType::new(197);
/// Official `GNUNET_MESSAGE_TYPE_VPN_TCP_DATA_TO_VPN` assignment.
pub const VPN_TCP_DATA_TO_VPN: MessageType = MessageType::new(198);
/// Official `GNUNET_MESSAGE_TYPE_VPN_UDP_TO_SERVICE` assignment.
pub const VPN_UDP_TO_SERVICE: MessageType = MessageType::new(199);
/// Official `GNUNET_MESSAGE_TYPE_VPN_UDP_TO_INTERNET` assignment.
pub const VPN_UDP_TO_INTERNET: MessageType = MessageType::new(200);
/// Official `GNUNET_MESSAGE_TYPE_VPN_UDP_REPLY` assignment.
pub const VPN_UDP_REPLY: MessageType = MessageType::new(201);
/// Official `GNUNET_MESSAGE_TYPE_VPN_CLIENT_REDIRECT_TO_IP` assignment.
pub const VPN_CLIENT_REDIRECT_TO_IP: MessageType = MessageType::new(202);
/// Official `GNUNET_MESSAGE_TYPE_VPN_CLIENT_REDIRECT_TO_SERVICE` assignment.
pub const VPN_CLIENT_REDIRECT_TO_SERVICE: MessageType = MessageType::new(203);
/// Official `GNUNET_MESSAGE_TYPE_VPN_CLIENT_USE_IP` assignment.
pub const VPN_CLIENT_USE_IP: MessageType = MessageType::new(204);
/// Official `GNUNET_MESSAGE_TYPE_DNS_CLIENT_INIT` assignment.
pub const DNS_CLIENT_INIT: MessageType = MessageType::new(211);
/// Official `GNUNET_MESSAGE_TYPE_DNS_CLIENT_REQUEST` assignment.
pub const DNS_CLIENT_REQUEST: MessageType = MessageType::new(212);
/// Official `GNUNET_MESSAGE_TYPE_DNS_CLIENT_RESPONSE` assignment.
pub const DNS_CLIENT_RESPONSE: MessageType = MessageType::new(213);
/// Official `GNUNET_MESSAGE_TYPE_DNS_HELPER` assignment.
pub const DNS_HELPER: MessageType = MessageType::new(214);
/// Official `GNUNET_MESSAGE_TYPE_CHAT_JOIN_REQUEST` assignment.
pub const CHAT_JOIN_REQUEST: MessageType = MessageType::new(300);
/// Official `GNUNET_MESSAGE_TYPE_CHAT_JOIN_NOTIFICATION` assignment.
pub const CHAT_JOIN_NOTIFICATION: MessageType = MessageType::new(301);
/// Official `GNUNET_MESSAGE_TYPE_CHAT_LEAVE_NOTIFICATION` assignment.
pub const CHAT_LEAVE_NOTIFICATION: MessageType = MessageType::new(302);
/// Official `GNUNET_MESSAGE_TYPE_CHAT_MESSAGE_NOTIFICATION` assignment.
pub const CHAT_MESSAGE_NOTIFICATION: MessageType = MessageType::new(303);
/// Official `GNUNET_MESSAGE_TYPE_CHAT_TRANSMIT_REQUEST` assignment.
pub const CHAT_TRANSMIT_REQUEST: MessageType = MessageType::new(304);
/// Official `GNUNET_MESSAGE_TYPE_CHAT_CONFIRMATION_RECEIPT` assignment.
pub const CHAT_CONFIRMATION_RECEIPT: MessageType = MessageType::new(305);
/// Official `GNUNET_MESSAGE_TYPE_CHAT_CONFIRMATION_NOTIFICATION` assignment.
pub const CHAT_CONFIRMATION_NOTIFICATION: MessageType = MessageType::new(306);
/// Official `GNUNET_MESSAGE_TYPE_CHAT_P2P_JOIN_NOTIFICATION` assignment.
pub const CHAT_P2P_JOIN_NOTIFICATION: MessageType = MessageType::new(307);
/// Official `GNUNET_MESSAGE_TYPE_CHAT_P2P_LEAVE_NOTIFICATION` assignment.
pub const CHAT_P2P_LEAVE_NOTIFICATION: MessageType = MessageType::new(308);
/// Official `GNUNET_MESSAGE_TYPE_CHAT_P2P_SYNC_REQUEST` assignment.
pub const CHAT_P2P_SYNC_REQUEST: MessageType = MessageType::new(309);
/// Official `GNUNET_MESSAGE_TYPE_CHAT_P2P_MESSAGE_NOTIFICATION` assignment.
pub const CHAT_P2P_MESSAGE_NOTIFICATION: MessageType = MessageType::new(310);
/// Official `GNUNET_MESSAGE_TYPE_CHAT_P2P_CONFIRMATION_RECEIPT` assignment.
pub const CHAT_P2P_CONFIRMATION_RECEIPT: MessageType = MessageType::new(311);
/// Official `GNUNET_MESSAGE_TYPE_NSE_START` assignment.
pub const NSE_START: MessageType = MessageType::new(321);
/// Official `GNUNET_MESSAGE_TYPE_NSE_P2P_FLOOD` assignment.
pub const NSE_P2P_FLOOD: MessageType = MessageType::new(322);
/// Official `GNUNET_MESSAGE_TYPE_NSE_ESTIMATE` assignment.
pub const NSE_ESTIMATE: MessageType = MessageType::new(323);
/// Official `GNUNET_MESSAGE_TYPE_PEERINFO_GET` assignment.
pub const PEERINFO_GET: MessageType = MessageType::new(330);
/// Official `GNUNET_MESSAGE_TYPE_PEERINFO_GET_ALL` assignment.
pub const PEERINFO_GET_ALL: MessageType = MessageType::new(331);
/// Official `GNUNET_MESSAGE_TYPE_PEERINFO_INFO` assignment.
pub const PEERINFO_INFO: MessageType = MessageType::new(332);
/// Official `GNUNET_MESSAGE_TYPE_PEERINFO_INFO_END` assignment.
pub const PEERINFO_INFO_END: MessageType = MessageType::new(333);
/// Official `GNUNET_MESSAGE_TYPE_PEERINFO_NOTIFY` assignment.
pub const PEERINFO_NOTIFY: MessageType = MessageType::new(334);
/// Official `GNUNET_MESSAGE_TYPE_ATS_START` assignment.
pub const ATS_START: MessageType = MessageType::new(340);
/// Official `GNUNET_MESSAGE_TYPE_ATS_REQUEST_ADDRESS` assignment.
pub const ATS_REQUEST_ADDRESS: MessageType = MessageType::new(341);
/// Official `GNUNET_MESSAGE_TYPE_ATS_REQUEST_ADDRESS_CANCEL` assignment.
pub const ATS_REQUEST_ADDRESS_CANCEL: MessageType = MessageType::new(342);
/// Official `GNUNET_MESSAGE_TYPE_ATS_ADDRESS_UPDATE` assignment.
pub const ATS_ADDRESS_UPDATE: MessageType = MessageType::new(343);
/// Official `GNUNET_MESSAGE_TYPE_ATS_ADDRESS_DESTROYED` assignment.
pub const ATS_ADDRESS_DESTROYED: MessageType = MessageType::new(344);
/// Official `GNUNET_MESSAGE_TYPE_ATS_ADDRESS_SUGGESTION` assignment.
pub const ATS_ADDRESS_SUGGESTION: MessageType = MessageType::new(345);
/// Official `GNUNET_MESSAGE_TYPE_ATS_PEER_INFORMATION` assignment.
pub const ATS_PEER_INFORMATION: MessageType = MessageType::new(346);
/// Official `GNUNET_MESSAGE_TYPE_ATS_RESERVATION_REQUEST` assignment.
pub const ATS_RESERVATION_REQUEST: MessageType = MessageType::new(347);
/// Official `GNUNET_MESSAGE_TYPE_ATS_RESERVATION_RESULT` assignment.
pub const ATS_RESERVATION_RESULT: MessageType = MessageType::new(348);
/// Official `GNUNET_MESSAGE_TYPE_ATS_PREFERENCE_CHANGE` assignment.
pub const ATS_PREFERENCE_CHANGE: MessageType = MessageType::new(349);
/// Official `GNUNET_MESSAGE_TYPE_ATS_SESSION_RELEASE` assignment.
pub const ATS_SESSION_RELEASE: MessageType = MessageType::new(350);
/// Official `GNUNET_MESSAGE_TYPE_ATS_ADDRESS_ADD` assignment.
pub const ATS_ADDRESS_ADD: MessageType = MessageType::new(353);
/// Official `GNUNET_MESSAGE_TYPE_ATS_ADDRESSLIST_REQUEST` assignment.
pub const ATS_ADDRESSLIST_REQUEST: MessageType = MessageType::new(354);
/// Official `GNUNET_MESSAGE_TYPE_ATS_ADDRESSLIST_RESPONSE` assignment.
pub const ATS_ADDRESSLIST_RESPONSE: MessageType = MessageType::new(355);
/// Official `GNUNET_MESSAGE_TYPE_ATS_PREFERENCE_FEEDBACK` assignment.
pub const ATS_PREFERENCE_FEEDBACK: MessageType = MessageType::new(356);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_START` assignment.
pub const TRANSPORT_START: MessageType = MessageType::new(360);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_CONNECT` assignment.
pub const TRANSPORT_CONNECT: MessageType = MessageType::new(361);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_DISCONNECT` assignment.
pub const TRANSPORT_DISCONNECT: MessageType = MessageType::new(362);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_SEND` assignment.
pub const TRANSPORT_SEND: MessageType = MessageType::new(363);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_OK` assignment.
pub const TRANSPORT_SEND_OK: MessageType = MessageType::new(364);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_RECV` assignment.
pub const TRANSPORT_RECV: MessageType = MessageType::new(365);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_SET_QUOTA` assignment.
pub const TRANSPORT_SET_QUOTA: MessageType = MessageType::new(366);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_RECV_OK` assignment.
pub const TRANSPORT_RECV_OK: MessageType = MessageType::new(366);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_TO_STRING` assignment.
pub const TRANSPORT_ADDRESS_TO_STRING: MessageType = MessageType::new(367);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_TO_STRING_REPLY` assignment.
pub const TRANSPORT_ADDRESS_TO_STRING_REPLY: MessageType = MessageType::new(368);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_INIT` assignment.
pub const TRANSPORT_BLACKLIST_INIT: MessageType = MessageType::new(369);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_QUERY` assignment.
pub const TRANSPORT_BLACKLIST_QUERY: MessageType = MessageType::new(370);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_BLACKLIST_REPLY` assignment.
pub const TRANSPORT_BLACKLIST_REPLY: MessageType = MessageType::new(371);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_PING` assignment.
pub const TRANSPORT_PING: MessageType = MessageType::new(372);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_PONG` assignment.
pub const TRANSPORT_PONG: MessageType = MessageType::new(373);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_SYN` assignment.
pub const TRANSPORT_SESSION_SYN: MessageType = MessageType::new(375);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_SYN_ACK` assignment.
pub const TRANSPORT_SESSION_SYN_ACK: MessageType = MessageType::new(376);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_ACK` assignment.
pub const TRANSPORT_SESSION_ACK: MessageType = MessageType::new(377);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_DISCONNECT` assignment.
pub const TRANSPORT_SESSION_DISCONNECT: MessageType = MessageType::new(378);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_QUOTA` assignment.
pub const TRANSPORT_SESSION_QUOTA: MessageType = MessageType::new(379);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PEER_REQUEST` assignment.
pub const TRANSPORT_MONITOR_PEER_REQUEST: MessageType = MessageType::new(380);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE` assignment.
pub const TRANSPORT_SESSION_KEEPALIVE: MessageType = MessageType::new(381);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_SESSION_KEEPALIVE_RESPONSE` assignment.
pub const TRANSPORT_SESSION_KEEPALIVE_RESPONSE: MessageType = MessageType::new(382);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PEER_RESPONSE` assignment.
pub const TRANSPORT_MONITOR_PEER_RESPONSE: MessageType = MessageType::new(383);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_BROADCAST_BEACON` assignment.
pub const TRANSPORT_BROADCAST_BEACON: MessageType = MessageType::new(384);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_TRAFFIC_METRIC` assignment.
pub const TRANSPORT_TRAFFIC_METRIC: MessageType = MessageType::new(385);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PLUGIN_START` assignment.
pub const TRANSPORT_MONITOR_PLUGIN_START: MessageType = MessageType::new(388);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PLUGIN_EVENT` assignment.
pub const TRANSPORT_MONITOR_PLUGIN_EVENT: MessageType = MessageType::new(389);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PLUGIN_SYNC` assignment.
pub const TRANSPORT_MONITOR_PLUGIN_SYNC: MessageType = MessageType::new(390);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PEER_RESPONSE_END` assignment.
pub const TRANSPORT_MONITOR_PEER_RESPONSE_END: MessageType = MessageType::new(391);
/// Official `GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_PROGRESS_FILE` assignment.
pub const FS_PUBLISH_HELPER_PROGRESS_FILE: MessageType = MessageType::new(420);
/// Official `GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_PROGRESS_DIRECTORY` assignment.
pub const FS_PUBLISH_HELPER_PROGRESS_DIRECTORY: MessageType = MessageType::new(421);
/// Official `GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_ERROR` assignment.
pub const FS_PUBLISH_HELPER_ERROR: MessageType = MessageType::new(422);
/// Official `GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_SKIP_FILE` assignment.
pub const FS_PUBLISH_HELPER_SKIP_FILE: MessageType = MessageType::new(423);
/// Official `GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_COUNTING_DONE` assignment.
pub const FS_PUBLISH_HELPER_COUNTING_DONE: MessageType = MessageType::new(424);
/// Official `GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_META_DATA` assignment.
pub const FS_PUBLISH_HELPER_META_DATA: MessageType = MessageType::new(425);
/// Official `GNUNET_MESSAGE_TYPE_FS_PUBLISH_HELPER_FINISHED` assignment.
pub const FS_PUBLISH_HELPER_FINISHED: MessageType = MessageType::new(426);
/// Official `GNUNET_MESSAGE_TYPE_NAMECACHE_LOOKUP_BLOCK` assignment.
pub const NAMECACHE_LOOKUP_BLOCK: MessageType = MessageType::new(431);
/// Official `GNUNET_MESSAGE_TYPE_NAMECACHE_LOOKUP_BLOCK_RESPONSE` assignment.
pub const NAMECACHE_LOOKUP_BLOCK_RESPONSE: MessageType = MessageType::new(432);
/// Official `GNUNET_MESSAGE_TYPE_NAMECACHE_BLOCK_CACHE` assignment.
pub const NAMECACHE_BLOCK_CACHE: MessageType = MessageType::new(433);
/// Official `GNUNET_MESSAGE_TYPE_NAMECACHE_BLOCK_CACHE_RESPONSE` assignment.
pub const NAMECACHE_BLOCK_CACHE_RESPONSE: MessageType = MessageType::new(434);
/// Official `GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_STORE` assignment.
pub const NAMESTORE_RECORD_STORE: MessageType = MessageType::new(435);
/// Official `GNUNET_MESSAGE_TYPE_NAMESTORE_GENERIC_RESPONSE` assignment.
pub const NAMESTORE_GENERIC_RESPONSE: MessageType = MessageType::new(436);
/// Official `GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_LOOKUP` assignment.
pub const NAMESTORE_RECORD_LOOKUP: MessageType = MessageType::new(437);
/// Official `GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_LOOKUP_RESPONSE` assignment.
pub const NAMESTORE_RECORD_LOOKUP_RESPONSE: MessageType = MessageType::new(438);
/// Official `GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME` assignment.
pub const NAMESTORE_ZONE_TO_NAME: MessageType = MessageType::new(439);
/// Official `GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_TO_NAME_RESPONSE` assignment.
pub const NAMESTORE_ZONE_TO_NAME_RESPONSE: MessageType = MessageType::new(440);
/// Official `GNUNET_MESSAGE_TYPE_NAMESTORE_MONITOR_START` assignment.
pub const NAMESTORE_MONITOR_START: MessageType = MessageType::new(441);
/// Official `GNUNET_MESSAGE_TYPE_NAMESTORE_MONITOR_SYNC` assignment.
pub const NAMESTORE_MONITOR_SYNC: MessageType = MessageType::new(442);
/// Official `GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_RESULT` assignment.
pub const NAMESTORE_RECORD_RESULT: MessageType = MessageType::new(443);
/// Official `GNUNET_MESSAGE_TYPE_NAMESTORE_MONITOR_NEXT` assignment.
pub const NAMESTORE_MONITOR_NEXT: MessageType = MessageType::new(444);
/// Official `GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_START` assignment.
pub const NAMESTORE_ZONE_ITERATION_START: MessageType = MessageType::new(445);
/// Official `GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_NEXT` assignment.
pub const NAMESTORE_ZONE_ITERATION_NEXT: MessageType = MessageType::new(447);
/// Official `GNUNET_MESSAGE_TYPE_NAMESTORE_ZONE_ITERATION_STOP` assignment.
pub const NAMESTORE_ZONE_ITERATION_STOP: MessageType = MessageType::new(448);
/// Official `GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_RESULT_END` assignment.
pub const NAMESTORE_RECORD_RESULT_END: MessageType = MessageType::new(449);
/// Official `GNUNET_MESSAGE_TYPE_LOCKMANAGER_ACQUIRE` assignment.
pub const LOCKMANAGER_ACQUIRE: MessageType = MessageType::new(450);
/// Official `GNUNET_MESSAGE_TYPE_LOCKMANAGER_RELEASE` assignment.
pub const LOCKMANAGER_RELEASE: MessageType = MessageType::new(451);
/// Official `GNUNET_MESSAGE_TYPE_LOCKMANAGER_SUCCESS` assignment.
pub const LOCKMANAGER_SUCCESS: MessageType = MessageType::new(452);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_INIT` assignment.
pub const TESTBED_INIT: MessageType = MessageType::new(460);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_ADD_HOST` assignment.
pub const TESTBED_ADD_HOST: MessageType = MessageType::new(461);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_ADD_HOST_SUCCESS` assignment.
pub const TESTBED_ADD_HOST_SUCCESS: MessageType = MessageType::new(462);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_LINK_CONTROLLERS` assignment.
pub const TESTBED_LINK_CONTROLLERS: MessageType = MessageType::new(463);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_CREATE_PEER` assignment.
pub const TESTBED_CREATE_PEER: MessageType = MessageType::new(464);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_RECONFIGURE_PEER` assignment.
pub const TESTBED_RECONFIGURE_PEER: MessageType = MessageType::new(465);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_START_PEER` assignment.
pub const TESTBED_START_PEER: MessageType = MessageType::new(466);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_STOP_PEER` assignment.
pub const TESTBED_STOP_PEER: MessageType = MessageType::new(467);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_DESTROY_PEER` assignment.
pub const TESTBED_DESTROY_PEER: MessageType = MessageType::new(468);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_CONFIGURE_UNDERLAY_LINK` assignment.
pub const TESTBED_CONFIGURE_UNDERLAY_LINK: MessageType = MessageType::new(469);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_OVERLAY_CONNECT` assignment.
pub const TESTBED_OVERLAY_CONNECT: MessageType = MessageType::new(470);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_PEER_EVENT` assignment.
pub const TESTBED_PEER_EVENT: MessageType = MessageType::new(471);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_PEER_CONNECT_EVENT` assignment.
pub const TESTBED_PEER_CONNECT_EVENT: MessageType = MessageType::new(472);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_OPERATION_FAIL_EVENT` assignment.
pub const TESTBED_OPERATION_FAIL_EVENT: MessageType = MessageType::new(473);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_CREATE_PEER_SUCCESS` assignment.
pub const TESTBED_CREATE_PEER_SUCCESS: MessageType = MessageType::new(474);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_GENERIC_OPERATION_SUCCESS` assignment.
pub const TESTBED_GENERIC_OPERATION_SUCCESS: MessageType = MessageType::new(475);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_GET_PEER_INFORMATION` assignment.
pub const TESTBED_GET_PEER_INFORMATION: MessageType = MessageType::new(476);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_PEER_INFORMATION` assignment.
pub const TESTBED_PEER_INFORMATION: MessageType = MessageType::new(477);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_REMOTE_OVERLAY_CONNECT` assignment.
pub const TESTBED_REMOTE_OVERLAY_CONNECT: MessageType = MessageType::new(478);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_GET_SLAVE_CONFIGURATION` assignment.
pub const TESTBED_GET_SLAVE_CONFIGURATION: MessageType = MessageType::new(479);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_SLAVE_CONFIGURATION` assignment.
pub const TESTBED_SLAVE_CONFIGURATION: MessageType = MessageType::new(480);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_LINK_CONTROLLERS_RESULT` assignment.
pub const TESTBED_LINK_CONTROLLERS_RESULT: MessageType = MessageType::new(481);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_SHUTDOWN_PEERS` assignment.
pub const TESTBED_SHUTDOWN_PEERS: MessageType = MessageType::new(482);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_MANAGE_PEER_SERVICE` assignment.
pub const TESTBED_MANAGE_PEER_SERVICE: MessageType = MessageType::new(483);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_INIT` assignment.
pub const TESTBED_BARRIER_INIT: MessageType = MessageType::new(484);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_CANCEL` assignment.
pub const TESTBED_BARRIER_CANCEL: MessageType = MessageType::new(485);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_STATUS` assignment.
pub const TESTBED_BARRIER_STATUS: MessageType = MessageType::new(486);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_BARRIER_WAIT` assignment.
pub const TESTBED_BARRIER_WAIT: MessageType = MessageType::new(487);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_MAX` assignment.
pub const TESTBED_MAX: MessageType = MessageType::new(488);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_HELPER_INIT` assignment.
pub const TESTBED_HELPER_INIT: MessageType = MessageType::new(495);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_HELPER_REPLY` assignment.
pub const TESTBED_HELPER_REPLY: MessageType = MessageType::new(496);
/// Official `GNUNET_MESSAGE_TYPE_GNS_LOOKUP` assignment.
pub const GNS_LOOKUP: MessageType = MessageType::new(500);
/// Official `GNUNET_MESSAGE_TYPE_GNS_LOOKUP_RESULT` assignment.
pub const GNS_LOOKUP_RESULT: MessageType = MessageType::new(501);
/// Official `GNUNET_MESSAGE_TYPE_GNS_REVERSE_LOOKUP` assignment.
pub const GNS_REVERSE_LOOKUP: MessageType = MessageType::new(503);
/// Official `GNUNET_MESSAGE_TYPE_GNS_REVERSE_LOOKUP_RESULT` assignment.
pub const GNS_REVERSE_LOOKUP_RESULT: MessageType = MessageType::new(504);
/// Official `GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_JOIN` assignment.
pub const CONSENSUS_CLIENT_JOIN: MessageType = MessageType::new(520);
/// Official `GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_INSERT` assignment.
pub const CONSENSUS_CLIENT_INSERT: MessageType = MessageType::new(521);
/// Official `GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_BEGIN` assignment.
pub const CONSENSUS_CLIENT_BEGIN: MessageType = MessageType::new(522);
/// Official `GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_RECEIVED_ELEMENT` assignment.
pub const CONSENSUS_CLIENT_RECEIVED_ELEMENT: MessageType = MessageType::new(523);
/// Official `GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_CONCLUDE` assignment.
pub const CONSENSUS_CLIENT_CONCLUDE: MessageType = MessageType::new(524);
/// Official `GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_CONCLUDE_DONE` assignment.
pub const CONSENSUS_CLIENT_CONCLUDE_DONE: MessageType = MessageType::new(525);
/// Official `GNUNET_MESSAGE_TYPE_CONSENSUS_CLIENT_ACK` assignment.
pub const CONSENSUS_CLIENT_ACK: MessageType = MessageType::new(540);
/// Official `GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_DELTA_ESTIMATE` assignment.
pub const CONSENSUS_P2P_DELTA_ESTIMATE: MessageType = MessageType::new(541);
/// Official `GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_DIFFERENCE_DIGEST` assignment.
pub const CONSENSUS_P2P_DIFFERENCE_DIGEST: MessageType = MessageType::new(542);
/// Official `GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_ELEMENTS` assignment.
pub const CONSENSUS_P2P_ELEMENTS: MessageType = MessageType::new(543);
/// Official `GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_ELEMENTS_REQUEST` assignment.
pub const CONSENSUS_P2P_ELEMENTS_REQUEST: MessageType = MessageType::new(544);
/// Official `GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_ELEMENTS_REPORT` assignment.
pub const CONSENSUS_P2P_ELEMENTS_REPORT: MessageType = MessageType::new(545);
/// Official `GNUNET_MESSAGE_TYPE_CONSENSUS_P2P_ROUND_CONTEXT` assignment.
pub const CONSENSUS_P2P_ROUND_CONTEXT: MessageType = MessageType::new(547);
/// Official `GNUNET_MESSAGE_TYPE_SETU_CANCEL` assignment.
pub const SETU_CANCEL: MessageType = MessageType::new(550);
/// Official `GNUNET_MESSAGE_TYPE_SETU_ADD` assignment.
pub const SETU_ADD: MessageType = MessageType::new(551);
/// Official `GNUNET_MESSAGE_TYPE_SETU_CREATE` assignment.
pub const SETU_CREATE: MessageType = MessageType::new(552);
/// Official `GNUNET_MESSAGE_TYPE_SETU_RESULT` assignment.
pub const SETU_RESULT: MessageType = MessageType::new(553);
/// Official `GNUNET_MESSAGE_TYPE_SETU_EVALUATE` assignment.
pub const SETU_EVALUATE: MessageType = MessageType::new(554);
/// Official `GNUNET_MESSAGE_TYPE_SETU_LISTEN` assignment.
pub const SETU_LISTEN: MessageType = MessageType::new(555);
/// Official `GNUNET_MESSAGE_TYPE_SETU_REJECT` assignment.
pub const SETU_REJECT: MessageType = MessageType::new(556);
/// Official `GNUNET_MESSAGE_TYPE_SETU_ACCEPT` assignment.
pub const SETU_ACCEPT: MessageType = MessageType::new(557);
/// Official `GNUNET_MESSAGE_TYPE_SETU_REQUEST` assignment.
pub const SETU_REQUEST: MessageType = MessageType::new(558);
/// Official `GNUNET_MESSAGE_TYPE_SETU_P2P_REQUEST_FULL` assignment.
pub const SETU_P2P_REQUEST_FULL: MessageType = MessageType::new(559);
/// Official `GNUNET_MESSAGE_TYPE_SETU_P2P_DEMAND` assignment.
pub const SETU_P2P_DEMAND: MessageType = MessageType::new(560);
/// Official `GNUNET_MESSAGE_TYPE_SETU_P2P_INQUIRY` assignment.
pub const SETU_P2P_INQUIRY: MessageType = MessageType::new(561);
/// Official `GNUNET_MESSAGE_TYPE_SETU_P2P_OFFER` assignment.
pub const SETU_P2P_OFFER: MessageType = MessageType::new(562);
/// Official `GNUNET_MESSAGE_TYPE_SETU_P2P_OPERATION_REQUEST` assignment.
pub const SETU_P2P_OPERATION_REQUEST: MessageType = MessageType::new(563);
/// Official `GNUNET_MESSAGE_TYPE_SETU_P2P_SE` assignment.
pub const SETU_P2P_SE: MessageType = MessageType::new(564);
/// Official `GNUNET_MESSAGE_TYPE_SETU_P2P_IBF` assignment.
pub const SETU_P2P_IBF: MessageType = MessageType::new(565);
/// Official `GNUNET_MESSAGE_TYPE_SETU_P2P_ELEMENTS` assignment.
pub const SETU_P2P_ELEMENTS: MessageType = MessageType::new(566);
/// Official `GNUNET_MESSAGE_TYPE_SETU_P2P_DONE` assignment.
pub const SETU_P2P_DONE: MessageType = MessageType::new(568);
/// Official `GNUNET_MESSAGE_TYPE_SETU_P2P_SEC` assignment.
pub const SETU_P2P_SEC: MessageType = MessageType::new(569);
/// Official `GNUNET_MESSAGE_TYPE_SETU_P2P_FULL_DONE` assignment.
pub const SETU_P2P_FULL_DONE: MessageType = MessageType::new(570);
/// Official `GNUNET_MESSAGE_TYPE_SETU_P2P_FULL_ELEMENT` assignment.
pub const SETU_P2P_FULL_ELEMENT: MessageType = MessageType::new(571);
/// Official `GNUNET_MESSAGE_TYPE_SETU_P2P_OVER` assignment.
pub const SETU_P2P_OVER: MessageType = MessageType::new(572);
/// Official `GNUNET_MESSAGE_TYPE_SETU_P2P_SEND_FULL` assignment.
pub const SETU_P2P_SEND_FULL: MessageType = MessageType::new(710);
/// Official `GNUNET_MESSAGE_TYPE_SETI_CANCEL` assignment.
pub const SETI_CANCEL: MessageType = MessageType::new(580);
/// Official `GNUNET_MESSAGE_TYPE_SETI_ADD` assignment.
pub const SETI_ADD: MessageType = MessageType::new(581);
/// Official `GNUNET_MESSAGE_TYPE_SETI_CREATE` assignment.
pub const SETI_CREATE: MessageType = MessageType::new(582);
/// Official `GNUNET_MESSAGE_TYPE_SETI_RESULT` assignment.
pub const SETI_RESULT: MessageType = MessageType::new(583);
/// Official `GNUNET_MESSAGE_TYPE_SETI_EVALUATE` assignment.
pub const SETI_EVALUATE: MessageType = MessageType::new(584);
/// Official `GNUNET_MESSAGE_TYPE_SETI_LISTEN` assignment.
pub const SETI_LISTEN: MessageType = MessageType::new(585);
/// Official `GNUNET_MESSAGE_TYPE_SETI_REJECT` assignment.
pub const SETI_REJECT: MessageType = MessageType::new(586);
/// Official `GNUNET_MESSAGE_TYPE_SETI_ACCEPT` assignment.
pub const SETI_ACCEPT: MessageType = MessageType::new(587);
/// Official `GNUNET_MESSAGE_TYPE_SETI_REQUEST` assignment.
pub const SETI_REQUEST: MessageType = MessageType::new(588);
/// Official `GNUNET_MESSAGE_TYPE_SETI_P2P_ELEMENT_INFO` assignment.
pub const SETI_P2P_ELEMENT_INFO: MessageType = MessageType::new(591);
/// Official `GNUNET_MESSAGE_TYPE_SETI_P2P_BF` assignment.
pub const SETI_P2P_BF: MessageType = MessageType::new(592);
/// Official `GNUNET_MESSAGE_TYPE_SETI_P2P_DONE` assignment.
pub const SETI_P2P_DONE: MessageType = MessageType::new(593);
/// Official `GNUNET_MESSAGE_TYPE_SETI_P2P_OPERATION_REQUEST` assignment.
pub const SETI_P2P_OPERATION_REQUEST: MessageType = MessageType::new(594);
/// Official `GNUNET_MESSAGE_TYPE_SET_UNION_P2P_REQUEST_FULL` assignment.
pub const SET_UNION_P2P_REQUEST_FULL: MessageType = MessageType::new(565);
/// Official `GNUNET_MESSAGE_TYPE_SET_UNION_P2P_DEMAND` assignment.
pub const SET_UNION_P2P_DEMAND: MessageType = MessageType::new(566);
/// Official `GNUNET_MESSAGE_TYPE_SET_UNION_P2P_INQUIRY` assignment.
pub const SET_UNION_P2P_INQUIRY: MessageType = MessageType::new(567);
/// Official `GNUNET_MESSAGE_TYPE_SET_UNION_P2P_OFFER` assignment.
pub const SET_UNION_P2P_OFFER: MessageType = MessageType::new(568);
/// Official `GNUNET_MESSAGE_TYPE_SET_REJECT` assignment.
pub const SET_REJECT: MessageType = MessageType::new(569);
/// Official `GNUNET_MESSAGE_TYPE_SET_CANCEL` assignment.
pub const SET_CANCEL: MessageType = MessageType::new(570);
/// Official `GNUNET_MESSAGE_TYPE_SET_ITER_ACK` assignment.
pub const SET_ITER_ACK: MessageType = MessageType::new(571);
/// Official `GNUNET_MESSAGE_TYPE_SET_RESULT` assignment.
pub const SET_RESULT: MessageType = MessageType::new(572);
/// Official `GNUNET_MESSAGE_TYPE_SET_ADD` assignment.
pub const SET_ADD: MessageType = MessageType::new(573);
/// Official `GNUNET_MESSAGE_TYPE_SET_REMOVE` assignment.
pub const SET_REMOVE: MessageType = MessageType::new(574);
/// Official `GNUNET_MESSAGE_TYPE_SET_LISTEN` assignment.
pub const SET_LISTEN: MessageType = MessageType::new(575);
/// Official `GNUNET_MESSAGE_TYPE_SET_ACCEPT` assignment.
pub const SET_ACCEPT: MessageType = MessageType::new(576);
/// Official `GNUNET_MESSAGE_TYPE_SET_EVALUATE` assignment.
pub const SET_EVALUATE: MessageType = MessageType::new(577);
/// Official `GNUNET_MESSAGE_TYPE_SET_CONCLUDE` assignment.
pub const SET_CONCLUDE: MessageType = MessageType::new(578);
/// Official `GNUNET_MESSAGE_TYPE_SET_REQUEST` assignment.
pub const SET_REQUEST: MessageType = MessageType::new(579);
/// Official `GNUNET_MESSAGE_TYPE_SET_CREATE` assignment.
pub const SET_CREATE: MessageType = MessageType::new(580);
/// Official `GNUNET_MESSAGE_TYPE_SET_P2P_OPERATION_REQUEST` assignment.
pub const SET_P2P_OPERATION_REQUEST: MessageType = MessageType::new(581);
/// Official `GNUNET_MESSAGE_TYPE_SET_UNION_P2P_SE` assignment.
pub const SET_UNION_P2P_SE: MessageType = MessageType::new(582);
/// Official `GNUNET_MESSAGE_TYPE_SET_UNION_P2P_IBF` assignment.
pub const SET_UNION_P2P_IBF: MessageType = MessageType::new(583);
/// Official `GNUNET_MESSAGE_TYPE_SET_P2P_ELEMENTS` assignment.
pub const SET_P2P_ELEMENTS: MessageType = MessageType::new(584);
/// Official `GNUNET_MESSAGE_TYPE_SET_UNION_P2P_DONE` assignment.
pub const SET_UNION_P2P_DONE: MessageType = MessageType::new(586);
/// Official `GNUNET_MESSAGE_TYPE_SET_ITER_REQUEST` assignment.
pub const SET_ITER_REQUEST: MessageType = MessageType::new(587);
/// Official `GNUNET_MESSAGE_TYPE_SET_ITER_ELEMENT` assignment.
pub const SET_ITER_ELEMENT: MessageType = MessageType::new(588);
/// Official `GNUNET_MESSAGE_TYPE_SET_ITER_DONE` assignment.
pub const SET_ITER_DONE: MessageType = MessageType::new(589);
/// Official `GNUNET_MESSAGE_TYPE_SET_UNION_P2P_SEC` assignment.
pub const SET_UNION_P2P_SEC: MessageType = MessageType::new(590);
/// Official `GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_ELEMENT_INFO` assignment.
pub const SET_INTERSECTION_P2P_ELEMENT_INFO: MessageType = MessageType::new(591);
/// Official `GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_BF` assignment.
pub const SET_INTERSECTION_P2P_BF: MessageType = MessageType::new(592);
/// Official `GNUNET_MESSAGE_TYPE_SET_INTERSECTION_P2P_DONE` assignment.
pub const SET_INTERSECTION_P2P_DONE: MessageType = MessageType::new(593);
/// Official `GNUNET_MESSAGE_TYPE_SET_COPY_LAZY_PREPARE` assignment.
pub const SET_COPY_LAZY_PREPARE: MessageType = MessageType::new(594);
/// Official `GNUNET_MESSAGE_TYPE_SET_COPY_LAZY_RESPONSE` assignment.
pub const SET_COPY_LAZY_RESPONSE: MessageType = MessageType::new(595);
/// Official `GNUNET_MESSAGE_TYPE_SET_COPY_LAZY_CONNECT` assignment.
pub const SET_COPY_LAZY_CONNECT: MessageType = MessageType::new(596);
/// Official `GNUNET_MESSAGE_TYPE_SET_UNION_P2P_FULL_DONE` assignment.
pub const SET_UNION_P2P_FULL_DONE: MessageType = MessageType::new(597);
/// Official `GNUNET_MESSAGE_TYPE_SET_UNION_P2P_FULL_ELEMENT` assignment.
pub const SET_UNION_P2P_FULL_ELEMENT: MessageType = MessageType::new(598);
/// Official `GNUNET_MESSAGE_TYPE_SET_UNION_P2P_OVER` assignment.
pub const SET_UNION_P2P_OVER: MessageType = MessageType::new(599);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_LOGGER_MSG` assignment.
pub const TESTBED_LOGGER_MSG: MessageType = MessageType::new(600);
/// Official `GNUNET_MESSAGE_TYPE_TESTBED_LOGGER_ACK` assignment.
pub const TESTBED_LOGGER_ACK: MessageType = MessageType::new(601);
/// Official `GNUNET_MESSAGE_TYPE_REGEX_ANNOUNCE` assignment.
pub const REGEX_ANNOUNCE: MessageType = MessageType::new(620);
/// Official `GNUNET_MESSAGE_TYPE_REGEX_SEARCH` assignment.
pub const REGEX_SEARCH: MessageType = MessageType::new(621);
/// Official `GNUNET_MESSAGE_TYPE_REGEX_RESULT` assignment.
pub const REGEX_RESULT: MessageType = MessageType::new(622);
/// Official `GNUNET_MESSAGE_TYPE_IDENTITY_START` assignment.
pub const IDENTITY_START: MessageType = MessageType::new(624);
/// Official `GNUNET_MESSAGE_TYPE_IDENTITY_RESULT_CODE` assignment.
pub const IDENTITY_RESULT_CODE: MessageType = MessageType::new(625);
/// Official `GNUNET_MESSAGE_TYPE_IDENTITY_UPDATE` assignment.
pub const IDENTITY_UPDATE: MessageType = MessageType::new(626);
/// Official `GNUNET_MESSAGE_TYPE_IDENTITY_CREATE` assignment.
pub const IDENTITY_CREATE: MessageType = MessageType::new(629);
/// Official `GNUNET_MESSAGE_TYPE_IDENTITY_RENAME` assignment.
pub const IDENTITY_RENAME: MessageType = MessageType::new(630);
/// Official `GNUNET_MESSAGE_TYPE_IDENTITY_DELETE` assignment.
pub const IDENTITY_DELETE: MessageType = MessageType::new(631);
/// Official `GNUNET_MESSAGE_TYPE_IDENTITY_LOOKUP` assignment.
pub const IDENTITY_LOOKUP: MessageType = MessageType::new(632);
/// Official `GNUNET_MESSAGE_TYPE_IDENTITY_LOOKUP_BY_SUFFIX` assignment.
pub const IDENTITY_LOOKUP_BY_SUFFIX: MessageType = MessageType::new(633);
/// Official `GNUNET_MESSAGE_TYPE_REVOCATION_QUERY` assignment.
pub const REVOCATION_QUERY: MessageType = MessageType::new(636);
/// Official `GNUNET_MESSAGE_TYPE_REVOCATION_QUERY_RESPONSE` assignment.
pub const REVOCATION_QUERY_RESPONSE: MessageType = MessageType::new(637);
/// Official `GNUNET_MESSAGE_TYPE_REVOCATION_REVOKE` assignment.
pub const REVOCATION_REVOKE: MessageType = MessageType::new(638);
/// Official `GNUNET_MESSAGE_TYPE_REVOCATION_REVOKE_RESPONSE` assignment.
pub const REVOCATION_REVOKE_RESPONSE: MessageType = MessageType::new(639);
/// Official `GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_ALICE` assignment.
pub const SCALARPRODUCT_CLIENT_TO_ALICE: MessageType = MessageType::new(640);
/// Official `GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_TO_BOB` assignment.
pub const SCALARPRODUCT_CLIENT_TO_BOB: MessageType = MessageType::new(641);
/// Official `GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_MULTIPART_ALICE` assignment.
pub const SCALARPRODUCT_CLIENT_MULTIPART_ALICE: MessageType = MessageType::new(642);
/// Official `GNUNET_MESSAGE_TYPE_SCALARPRODUCT_CLIENT_MULTIPART_BOB` assignment.
pub const SCALARPRODUCT_CLIENT_MULTIPART_BOB: MessageType = MessageType::new(643);
/// Official `GNUNET_MESSAGE_TYPE_SCALARPRODUCT_SESSION_INITIALIZATION` assignment.
pub const SCALARPRODUCT_SESSION_INITIALIZATION: MessageType = MessageType::new(644);
/// Official `GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ALICE_CRYPTODATA` assignment.
pub const SCALARPRODUCT_ALICE_CRYPTODATA: MessageType = MessageType::new(645);
/// Official `GNUNET_MESSAGE_TYPE_SCALARPRODUCT_BOB_CRYPTODATA` assignment.
pub const SCALARPRODUCT_BOB_CRYPTODATA: MessageType = MessageType::new(647);
/// Official `GNUNET_MESSAGE_TYPE_SCALARPRODUCT_BOB_CRYPTODATA_MULTIPART` assignment.
pub const SCALARPRODUCT_BOB_CRYPTODATA_MULTIPART: MessageType = MessageType::new(648);
/// Official `GNUNET_MESSAGE_TYPE_SCALARPRODUCT_RESULT` assignment.
pub const SCALARPRODUCT_RESULT: MessageType = MessageType::new(649);
/// Official `GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ECC_SESSION_INITIALIZATION` assignment.
pub const SCALARPRODUCT_ECC_SESSION_INITIALIZATION: MessageType = MessageType::new(650);
/// Official `GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ECC_ALICE_CRYPTODATA` assignment.
pub const SCALARPRODUCT_ECC_ALICE_CRYPTODATA: MessageType = MessageType::new(651);
/// Official `GNUNET_MESSAGE_TYPE_SCALARPRODUCT_ECC_BOB_CRYPTODATA` assignment.
pub const SCALARPRODUCT_ECC_BOB_CRYPTODATA: MessageType = MessageType::new(652);
/// Official `GNUNET_MESSAGE_TYPE_PSYCSTORE_MEMBERSHIP_STORE` assignment.
pub const PSYCSTORE_MEMBERSHIP_STORE: MessageType = MessageType::new(660);
/// Official `GNUNET_MESSAGE_TYPE_PSYCSTORE_MEMBERSHIP_TEST` assignment.
pub const PSYCSTORE_MEMBERSHIP_TEST: MessageType = MessageType::new(661);
/// Official `GNUNET_MESSAGE_TYPE_PSYCSTORE_FRAGMENT_STORE` assignment.
pub const PSYCSTORE_FRAGMENT_STORE: MessageType = MessageType::new(662);
/// Official `GNUNET_MESSAGE_TYPE_PSYCSTORE_FRAGMENT_GET` assignment.
pub const PSYCSTORE_FRAGMENT_GET: MessageType = MessageType::new(663);
/// Official `GNUNET_MESSAGE_TYPE_PSYCSTORE_MESSAGE_GET` assignment.
pub const PSYCSTORE_MESSAGE_GET: MessageType = MessageType::new(664);
/// Official `GNUNET_MESSAGE_TYPE_PSYCSTORE_MESSAGE_GET_FRAGMENT` assignment.
pub const PSYCSTORE_MESSAGE_GET_FRAGMENT: MessageType = MessageType::new(665);
/// Official `GNUNET_MESSAGE_TYPE_PSYCSTORE_COUNTERS_GET` assignment.
pub const PSYCSTORE_COUNTERS_GET: MessageType = MessageType::new(666);
/// Official `GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_MODIFY` assignment.
pub const PSYCSTORE_STATE_MODIFY: MessageType = MessageType::new(668);
/// Official `GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_SYNC` assignment.
pub const PSYCSTORE_STATE_SYNC: MessageType = MessageType::new(669);
/// Official `GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_RESET` assignment.
pub const PSYCSTORE_STATE_RESET: MessageType = MessageType::new(670);
/// Official `GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_HASH_UPDATE` assignment.
pub const PSYCSTORE_STATE_HASH_UPDATE: MessageType = MessageType::new(671);
/// Official `GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_GET` assignment.
pub const PSYCSTORE_STATE_GET: MessageType = MessageType::new(672);
/// Official `GNUNET_MESSAGE_TYPE_PSYCSTORE_STATE_GET_PREFIX` assignment.
pub const PSYCSTORE_STATE_GET_PREFIX: MessageType = MessageType::new(673);
/// Official `GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_CODE` assignment.
pub const PSYCSTORE_RESULT_CODE: MessageType = MessageType::new(674);
/// Official `GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_FRAGMENT` assignment.
pub const PSYCSTORE_RESULT_FRAGMENT: MessageType = MessageType::new(675);
/// Official `GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_COUNTERS` assignment.
pub const PSYCSTORE_RESULT_COUNTERS: MessageType = MessageType::new(676);
/// Official `GNUNET_MESSAGE_TYPE_PSYCSTORE_RESULT_STATE` assignment.
pub const PSYCSTORE_RESULT_STATE: MessageType = MessageType::new(677);
/// Official `GNUNET_MESSAGE_TYPE_PSYC_RESULT_CODE` assignment.
pub const PSYC_RESULT_CODE: MessageType = MessageType::new(680);
/// Official `GNUNET_MESSAGE_TYPE_PSYC_MASTER_START` assignment.
pub const PSYC_MASTER_START: MessageType = MessageType::new(681);
/// Official `GNUNET_MESSAGE_TYPE_PSYC_MASTER_START_ACK` assignment.
pub const PSYC_MASTER_START_ACK: MessageType = MessageType::new(682);
/// Official `GNUNET_MESSAGE_TYPE_PSYC_SLAVE_JOIN` assignment.
pub const PSYC_SLAVE_JOIN: MessageType = MessageType::new(683);
/// Official `GNUNET_MESSAGE_TYPE_PSYC_SLAVE_JOIN_ACK` assignment.
pub const PSYC_SLAVE_JOIN_ACK: MessageType = MessageType::new(684);
/// Official `GNUNET_MESSAGE_TYPE_PSYC_PART_REQUEST` assignment.
pub const PSYC_PART_REQUEST: MessageType = MessageType::new(685);
/// Official `GNUNET_MESSAGE_TYPE_PSYC_PART_ACK` assignment.
pub const PSYC_PART_ACK: MessageType = MessageType::new(686);
/// Official `GNUNET_MESSAGE_TYPE_PSYC_JOIN_REQUEST` assignment.
pub const PSYC_JOIN_REQUEST: MessageType = MessageType::new(687);
/// Official `GNUNET_MESSAGE_TYPE_PSYC_JOIN_DECISION` assignment.
pub const PSYC_JOIN_DECISION: MessageType = MessageType::new(688);
/// Official `GNUNET_MESSAGE_TYPE_PSYC_CHANNEL_MEMBERSHIP_STORE` assignment.
pub const PSYC_CHANNEL_MEMBERSHIP_STORE: MessageType = MessageType::new(689);
/// Official `GNUNET_MESSAGE_TYPE_PSYC_MESSAGE` assignment.
pub const PSYC_MESSAGE: MessageType = MessageType::new(691);
/// Official `GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_HEADER` assignment.
pub const PSYC_MESSAGE_HEADER: MessageType = MessageType::new(692);
/// Official `GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_METHOD` assignment.
pub const PSYC_MESSAGE_METHOD: MessageType = MessageType::new(693);
/// Official `GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MODIFIER` assignment.
pub const PSYC_MESSAGE_MODIFIER: MessageType = MessageType::new(694);
/// Official `GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_MOD_CONT` assignment.
pub const PSYC_MESSAGE_MOD_CONT: MessageType = MessageType::new(695);
/// Official `GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_DATA` assignment.
pub const PSYC_MESSAGE_DATA: MessageType = MessageType::new(696);
/// Official `GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_END` assignment.
pub const PSYC_MESSAGE_END: MessageType = MessageType::new(697);
/// Official `GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_CANCEL` assignment.
pub const PSYC_MESSAGE_CANCEL: MessageType = MessageType::new(698);
/// Official `GNUNET_MESSAGE_TYPE_PSYC_MESSAGE_ACK` assignment.
pub const PSYC_MESSAGE_ACK: MessageType = MessageType::new(699);
/// Official `GNUNET_MESSAGE_TYPE_PSYC_HISTORY_REPLAY` assignment.
pub const PSYC_HISTORY_REPLAY: MessageType = MessageType::new(701);
/// Official `GNUNET_MESSAGE_TYPE_PSYC_HISTORY_RESULT` assignment.
pub const PSYC_HISTORY_RESULT: MessageType = MessageType::new(702);
/// Official `GNUNET_MESSAGE_TYPE_PSYC_STATE_GET` assignment.
pub const PSYC_STATE_GET: MessageType = MessageType::new(703);
/// Official `GNUNET_MESSAGE_TYPE_PSYC_STATE_GET_PREFIX` assignment.
pub const PSYC_STATE_GET_PREFIX: MessageType = MessageType::new(704);
/// Official `GNUNET_MESSAGE_TYPE_PSYC_STATE_RESULT` assignment.
pub const PSYC_STATE_RESULT: MessageType = MessageType::new(705);
/// Official `GNUNET_MESSAGE_TYPE_CONVERSATION_AUDIO` assignment.
pub const CONVERSATION_AUDIO: MessageType = MessageType::new(730);
/// Official `GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_REGISTER` assignment.
pub const CONVERSATION_CS_PHONE_REGISTER: MessageType = MessageType::new(731);
/// Official `GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_PICK_UP` assignment.
pub const CONVERSATION_CS_PHONE_PICK_UP: MessageType = MessageType::new(732);
/// Official `GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_HANG_UP` assignment.
pub const CONVERSATION_CS_PHONE_HANG_UP: MessageType = MessageType::new(733);
/// Official `GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_CALL` assignment.
pub const CONVERSATION_CS_PHONE_CALL: MessageType = MessageType::new(734);
/// Official `GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_RING` assignment.
pub const CONVERSATION_CS_PHONE_RING: MessageType = MessageType::new(735);
/// Official `GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_SUSPEND` assignment.
pub const CONVERSATION_CS_PHONE_SUSPEND: MessageType = MessageType::new(736);
/// Official `GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_RESUME` assignment.
pub const CONVERSATION_CS_PHONE_RESUME: MessageType = MessageType::new(737);
/// Official `GNUNET_MESSAGE_TYPE_CONVERSATION_CS_PHONE_PICKED_UP` assignment.
pub const CONVERSATION_CS_PHONE_PICKED_UP: MessageType = MessageType::new(738);
/// Official `GNUNET_MESSAGE_TYPE_CONVERSATION_CS_AUDIO` assignment.
pub const CONVERSATION_CS_AUDIO: MessageType = MessageType::new(739);
/// Official `GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_PHONE_RING` assignment.
pub const CONVERSATION_CADET_PHONE_RING: MessageType = MessageType::new(740);
/// Official `GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_PHONE_HANG_UP` assignment.
pub const CONVERSATION_CADET_PHONE_HANG_UP: MessageType = MessageType::new(741);
/// Official `GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_PHONE_PICK_UP` assignment.
pub const CONVERSATION_CADET_PHONE_PICK_UP: MessageType = MessageType::new(742);
/// Official `GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_PHONE_SUSPEND` assignment.
pub const CONVERSATION_CADET_PHONE_SUSPEND: MessageType = MessageType::new(743);
/// Official `GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_PHONE_RESUME` assignment.
pub const CONVERSATION_CADET_PHONE_RESUME: MessageType = MessageType::new(744);
/// Official `GNUNET_MESSAGE_TYPE_CONVERSATION_CADET_AUDIO` assignment.
pub const CONVERSATION_CADET_AUDIO: MessageType = MessageType::new(745);
/// Official `GNUNET_MESSAGE_TYPE_MULTICAST_ORIGIN_START` assignment.
pub const MULTICAST_ORIGIN_START: MessageType = MessageType::new(750);
/// Official `GNUNET_MESSAGE_TYPE_MULTICAST_MEMBER_JOIN` assignment.
pub const MULTICAST_MEMBER_JOIN: MessageType = MessageType::new(751);
/// Official `GNUNET_MESSAGE_TYPE_MULTICAST_JOIN_REQUEST` assignment.
pub const MULTICAST_JOIN_REQUEST: MessageType = MessageType::new(752);
/// Official `GNUNET_MESSAGE_TYPE_MULTICAST_JOIN_DECISION` assignment.
pub const MULTICAST_JOIN_DECISION: MessageType = MessageType::new(753);
/// Official `GNUNET_MESSAGE_TYPE_MULTICAST_PART_REQUEST` assignment.
pub const MULTICAST_PART_REQUEST: MessageType = MessageType::new(754);
/// Official `GNUNET_MESSAGE_TYPE_MULTICAST_PART_ACK` assignment.
pub const MULTICAST_PART_ACK: MessageType = MessageType::new(755);
/// Official `GNUNET_MESSAGE_TYPE_MULTICAST_GROUP_END` assignment.
pub const MULTICAST_GROUP_END: MessageType = MessageType::new(756);
/// Official `GNUNET_MESSAGE_TYPE_MULTICAST_MESSAGE` assignment.
pub const MULTICAST_MESSAGE: MessageType = MessageType::new(757);
/// Official `GNUNET_MESSAGE_TYPE_MULTICAST_REQUEST` assignment.
pub const MULTICAST_REQUEST: MessageType = MessageType::new(758);
/// Official `GNUNET_MESSAGE_TYPE_MULTICAST_FRAGMENT_ACK` assignment.
pub const MULTICAST_FRAGMENT_ACK: MessageType = MessageType::new(759);
/// Official `GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_REQUEST` assignment.
pub const MULTICAST_REPLAY_REQUEST: MessageType = MessageType::new(760);
/// Official `GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_RESPONSE` assignment.
pub const MULTICAST_REPLAY_RESPONSE: MessageType = MessageType::new(761);
/// Official `GNUNET_MESSAGE_TYPE_MULTICAST_REPLAY_RESPONSE_END` assignment.
pub const MULTICAST_REPLAY_RESPONSE_END: MessageType = MessageType::new(762);
/// Official `GNUNET_MESSAGE_TYPE_SECRETSHARING_CLIENT_GENERATE` assignment.
pub const SECRETSHARING_CLIENT_GENERATE: MessageType = MessageType::new(780);
/// Official `GNUNET_MESSAGE_TYPE_SECRETSHARING_CLIENT_DECRYPT` assignment.
pub const SECRETSHARING_CLIENT_DECRYPT: MessageType = MessageType::new(781);
/// Official `GNUNET_MESSAGE_TYPE_SECRETSHARING_CLIENT_DECRYPT_DONE` assignment.
pub const SECRETSHARING_CLIENT_DECRYPT_DONE: MessageType = MessageType::new(782);
/// Official `GNUNET_MESSAGE_TYPE_SECRETSHARING_CLIENT_SECRET_READY` assignment.
pub const SECRETSHARING_CLIENT_SECRET_READY: MessageType = MessageType::new(783);
/// Official `GNUNET_MESSAGE_TYPE_PEERSTORE_STORE` assignment.
pub const PEERSTORE_STORE: MessageType = MessageType::new(820);
/// Official `GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE_START` assignment.
pub const PEERSTORE_ITERATE_START: MessageType = MessageType::new(821);
/// Official `GNUNET_MESSAGE_TYPE_PEERSTORE_RECORD` assignment.
pub const PEERSTORE_RECORD: MessageType = MessageType::new(822);
/// Official `GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE_END` assignment.
pub const PEERSTORE_ITERATE_END: MessageType = MessageType::new(823);
/// Official `GNUNET_MESSAGE_TYPE_PEERSTORE_MONITOR_START` assignment.
pub const PEERSTORE_MONITOR_START: MessageType = MessageType::new(824);
/// Official `GNUNET_MESSAGE_TYPE_PEERSTORE_MONITOR_SYNC` assignment.
pub const PEERSTORE_MONITOR_SYNC: MessageType = MessageType::new(825);
/// Official `GNUNET_MESSAGE_TYPE_PEERSTORE_MONITOR_NEXT` assignment.
pub const PEERSTORE_MONITOR_NEXT: MessageType = MessageType::new(826);
/// Official `GNUNET_MESSAGE_TYPE_PEERSTORE_STORE_RESULT` assignment.
pub const PEERSTORE_STORE_RESULT: MessageType = MessageType::new(827);
/// Official `GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE_NEXT` assignment.
pub const PEERSTORE_ITERATE_NEXT: MessageType = MessageType::new(828);
/// Official `GNUNET_MESSAGE_TYPE_PEERSTORE_ITERATE_STOP` assignment.
pub const PEERSTORE_ITERATE_STOP: MessageType = MessageType::new(829);
/// Official `GNUNET_MESSAGE_TYPE_SOCIAL_RESULT_CODE` assignment.
pub const SOCIAL_RESULT_CODE: MessageType = MessageType::new(840);
/// Official `GNUNET_MESSAGE_TYPE_SOCIAL_HOST_ENTER` assignment.
pub const SOCIAL_HOST_ENTER: MessageType = MessageType::new(841);
/// Official `GNUNET_MESSAGE_TYPE_SOCIAL_HOST_ENTER_ACK` assignment.
pub const SOCIAL_HOST_ENTER_ACK: MessageType = MessageType::new(842);
/// Official `GNUNET_MESSAGE_TYPE_SOCIAL_GUEST_ENTER` assignment.
pub const SOCIAL_GUEST_ENTER: MessageType = MessageType::new(843);
/// Official `GNUNET_MESSAGE_TYPE_SOCIAL_GUEST_ENTER_BY_NAME` assignment.
pub const SOCIAL_GUEST_ENTER_BY_NAME: MessageType = MessageType::new(844);
/// Official `GNUNET_MESSAGE_TYPE_SOCIAL_GUEST_ENTER_ACK` assignment.
pub const SOCIAL_GUEST_ENTER_ACK: MessageType = MessageType::new(845);
/// Official `GNUNET_MESSAGE_TYPE_SOCIAL_ENTRY_REQUEST` assignment.
pub const SOCIAL_ENTRY_REQUEST: MessageType = MessageType::new(846);
/// Official `GNUNET_MESSAGE_TYPE_SOCIAL_ENTRY_DECISION` assignment.
pub const SOCIAL_ENTRY_DECISION: MessageType = MessageType::new(847);
/// Official `GNUNET_MESSAGE_TYPE_SOCIAL_PLACE_LEAVE` assignment.
pub const SOCIAL_PLACE_LEAVE: MessageType = MessageType::new(848);
/// Official `GNUNET_MESSAGE_TYPE_SOCIAL_PLACE_LEAVE_ACK` assignment.
pub const SOCIAL_PLACE_LEAVE_ACK: MessageType = MessageType::new(849);
/// Official `GNUNET_MESSAGE_TYPE_SOCIAL_ZONE_ADD_PLACE` assignment.
pub const SOCIAL_ZONE_ADD_PLACE: MessageType = MessageType::new(850);
/// Official `GNUNET_MESSAGE_TYPE_SOCIAL_ZONE_ADD_NYM` assignment.
pub const SOCIAL_ZONE_ADD_NYM: MessageType = MessageType::new(851);
/// Official `GNUNET_MESSAGE_TYPE_SOCIAL_APP_CONNECT` assignment.
pub const SOCIAL_APP_CONNECT: MessageType = MessageType::new(852);
/// Official `GNUNET_MESSAGE_TYPE_SOCIAL_APP_DETACH` assignment.
pub const SOCIAL_APP_DETACH: MessageType = MessageType::new(853);
/// Official `GNUNET_MESSAGE_TYPE_SOCIAL_APP_EGO` assignment.
pub const SOCIAL_APP_EGO: MessageType = MessageType::new(854);
/// Official `GNUNET_MESSAGE_TYPE_SOCIAL_APP_EGO_END` assignment.
pub const SOCIAL_APP_EGO_END: MessageType = MessageType::new(855);
/// Official `GNUNET_MESSAGE_TYPE_SOCIAL_APP_PLACE` assignment.
pub const SOCIAL_APP_PLACE: MessageType = MessageType::new(856);
/// Official `GNUNET_MESSAGE_TYPE_SOCIAL_APP_PLACE_END` assignment.
pub const SOCIAL_APP_PLACE_END: MessageType = MessageType::new(857);
/// Official `GNUNET_MESSAGE_TYPE_SOCIAL_MSG_PROC_SET` assignment.
pub const SOCIAL_MSG_PROC_SET: MessageType = MessageType::new(858);
/// Official `GNUNET_MESSAGE_TYPE_SOCIAL_MSG_PROC_CLEAR` assignment.
pub const SOCIAL_MSG_PROC_CLEAR: MessageType = MessageType::new(859);
/// Official `GNUNET_MESSAGE_TYPE_XDHT_P2P_TRAIL_SETUP` assignment.
pub const XDHT_P2P_TRAIL_SETUP: MessageType = MessageType::new(880);
/// Official `GNUNET_MESSAGE_TYPE_XDHT_P2P_TRAIL_SETUP_RESULT` assignment.
pub const XDHT_P2P_TRAIL_SETUP_RESULT: MessageType = MessageType::new(881);
/// Official `GNUNET_MESSAGE_TYPE_XDHT_P2P_VERIFY_SUCCESSOR` assignment.
pub const XDHT_P2P_VERIFY_SUCCESSOR: MessageType = MessageType::new(882);
/// Official `GNUNET_MESSAGE_TYPE_XDHT_P2P_NOTIFY_NEW_SUCCESSOR` assignment.
pub const XDHT_P2P_NOTIFY_NEW_SUCCESSOR: MessageType = MessageType::new(883);
/// Official `GNUNET_MESSAGE_TYPE_XDHT_P2P_VERIFY_SUCCESSOR_RESULT` assignment.
pub const XDHT_P2P_VERIFY_SUCCESSOR_RESULT: MessageType = MessageType::new(884);
/// Official `GNUNET_MESSAGE_TYPE_XDHT_P2P_GET_RESULT` assignment.
pub const XDHT_P2P_GET_RESULT: MessageType = MessageType::new(885);
/// Official `GNUNET_MESSAGE_TYPE_XDHT_P2P_TRAIL_SETUP_REJECTION` assignment.
pub const XDHT_P2P_TRAIL_SETUP_REJECTION: MessageType = MessageType::new(886);
/// Official `GNUNET_MESSAGE_TYPE_XDHT_P2P_TRAIL_TEARDOWN` assignment.
pub const XDHT_P2P_TRAIL_TEARDOWN: MessageType = MessageType::new(887);
/// Official `GNUNET_MESSAGE_TYPE_XDHT_P2P_ADD_TRAIL` assignment.
pub const XDHT_P2P_ADD_TRAIL: MessageType = MessageType::new(888);
/// Official `GNUNET_MESSAGE_TYPE_XDHT_P2P_PUT` assignment.
pub const XDHT_P2P_PUT: MessageType = MessageType::new(890);
/// Official `GNUNET_MESSAGE_TYPE_XDHT_P2P_GET` assignment.
pub const XDHT_P2P_GET: MessageType = MessageType::new(891);
/// Official `GNUNET_MESSAGE_TYPE_XDHT_P2P_NOTIFY_SUCCESSOR_CONFIRMATION` assignment.
pub const XDHT_P2P_NOTIFY_SUCCESSOR_CONFIRMATION: MessageType = MessageType::new(892);
/// Official `GNUNET_MESSAGE_TYPE_WDHT_RANDOM_WALK` assignment.
pub const WDHT_RANDOM_WALK: MessageType = MessageType::new(910);
/// Official `GNUNET_MESSAGE_TYPE_WDHT_RANDOM_WALK_RESPONSE` assignment.
pub const WDHT_RANDOM_WALK_RESPONSE: MessageType = MessageType::new(911);
/// Official `GNUNET_MESSAGE_TYPE_WDHT_TRAIL_DESTROY` assignment.
pub const WDHT_TRAIL_DESTROY: MessageType = MessageType::new(912);
/// Official `GNUNET_MESSAGE_TYPE_WDHT_TRAIL_ROUTE` assignment.
pub const WDHT_TRAIL_ROUTE: MessageType = MessageType::new(913);
/// Official `GNUNET_MESSAGE_TYPE_WDHT_SUCCESSOR_FIND` assignment.
pub const WDHT_SUCCESSOR_FIND: MessageType = MessageType::new(914);
/// Official `GNUNET_MESSAGE_TYPE_WDHT_GET` assignment.
pub const WDHT_GET: MessageType = MessageType::new(915);
/// Official `GNUNET_MESSAGE_TYPE_WDHT_PUT` assignment.
pub const WDHT_PUT: MessageType = MessageType::new(916);
/// Official `GNUNET_MESSAGE_TYPE_WDHT_GET_RESULT` assignment.
pub const WDHT_GET_RESULT: MessageType = MessageType::new(917);
/// Official `GNUNET_MESSAGE_TYPE_RPS_PP_CHECK_LIVE` assignment.
pub const RPS_PP_CHECK_LIVE: MessageType = MessageType::new(950);
/// Official `GNUNET_MESSAGE_TYPE_RPS_PP_PUSH` assignment.
pub const RPS_PP_PUSH: MessageType = MessageType::new(951);
/// Official `GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REQUEST` assignment.
pub const RPS_PP_PULL_REQUEST: MessageType = MessageType::new(952);
/// Official `GNUNET_MESSAGE_TYPE_RPS_PP_PULL_REPLY` assignment.
pub const RPS_PP_PULL_REPLY: MessageType = MessageType::new(953);
/// Official `GNUNET_MESSAGE_TYPE_RPS_CS_SEED` assignment.
pub const RPS_CS_SEED: MessageType = MessageType::new(954);
/// Official `GNUNET_MESSAGE_TYPE_RPS_ACT_MALICIOUS` assignment.
pub const RPS_ACT_MALICIOUS: MessageType = MessageType::new(955);
/// Official `GNUNET_MESSAGE_TYPE_RPS_CS_SUB_START` assignment.
pub const RPS_CS_SUB_START: MessageType = MessageType::new(956);
/// Official `GNUNET_MESSAGE_TYPE_RPS_CS_SUB_STOP` assignment.
pub const RPS_CS_SUB_STOP: MessageType = MessageType::new(957);
/// Official `GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_STORE` assignment.
pub const RECLAIM_ATTRIBUTE_STORE: MessageType = MessageType::new(961);
/// Official `GNUNET_MESSAGE_TYPE_RECLAIM_SUCCESS_RESPONSE` assignment.
pub const RECLAIM_SUCCESS_RESPONSE: MessageType = MessageType::new(962);
/// Official `GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_ITERATION_START` assignment.
pub const RECLAIM_ATTRIBUTE_ITERATION_START: MessageType = MessageType::new(963);
/// Official `GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_ITERATION_STOP` assignment.
pub const RECLAIM_ATTRIBUTE_ITERATION_STOP: MessageType = MessageType::new(964);
/// Official `GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_ITERATION_NEXT` assignment.
pub const RECLAIM_ATTRIBUTE_ITERATION_NEXT: MessageType = MessageType::new(965);
/// Official `GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_RESULT` assignment.
pub const RECLAIM_ATTRIBUTE_RESULT: MessageType = MessageType::new(966);
/// Official `GNUNET_MESSAGE_TYPE_RECLAIM_ISSUE_TICKET` assignment.
pub const RECLAIM_ISSUE_TICKET: MessageType = MessageType::new(967);
/// Official `GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_RESULT` assignment.
pub const RECLAIM_TICKET_RESULT: MessageType = MessageType::new(968);
/// Official `GNUNET_MESSAGE_TYPE_RECLAIM_REVOKE_TICKET` assignment.
pub const RECLAIM_REVOKE_TICKET: MessageType = MessageType::new(969);
/// Official `GNUNET_MESSAGE_TYPE_RECLAIM_REVOKE_TICKET_RESULT` assignment.
pub const RECLAIM_REVOKE_TICKET_RESULT: MessageType = MessageType::new(970);
/// Official `GNUNET_MESSAGE_TYPE_RECLAIM_CONSUME_TICKET` assignment.
pub const RECLAIM_CONSUME_TICKET: MessageType = MessageType::new(971);
/// Official `GNUNET_MESSAGE_TYPE_RECLAIM_CONSUME_TICKET_RESULT` assignment.
pub const RECLAIM_CONSUME_TICKET_RESULT: MessageType = MessageType::new(972);
/// Official `GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_ITERATION_START` assignment.
pub const RECLAIM_TICKET_ITERATION_START: MessageType = MessageType::new(973);
/// Official `GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_ITERATION_STOP` assignment.
pub const RECLAIM_TICKET_ITERATION_STOP: MessageType = MessageType::new(974);
/// Official `GNUNET_MESSAGE_TYPE_RECLAIM_TICKET_ITERATION_NEXT` assignment.
pub const RECLAIM_TICKET_ITERATION_NEXT: MessageType = MessageType::new(975);
/// Official `GNUNET_MESSAGE_TYPE_RECLAIM_ATTRIBUTE_DELETE` assignment.
pub const RECLAIM_ATTRIBUTE_DELETE: MessageType = MessageType::new(976);
/// Official `GNUNET_MESSAGE_TYPE_RECLAIM_CREDENTIAL_STORE` assignment.
pub const RECLAIM_CREDENTIAL_STORE: MessageType = MessageType::new(977);
/// Official `GNUNET_MESSAGE_TYPE_RECLAIM_CREDENTIAL_DELETE` assignment.
pub const RECLAIM_CREDENTIAL_DELETE: MessageType = MessageType::new(978);
/// Official `GNUNET_MESSAGE_TYPE_RECLAIM_CREDENTIAL_RESULT` assignment.
pub const RECLAIM_CREDENTIAL_RESULT: MessageType = MessageType::new(979);
/// Official `GNUNET_MESSAGE_TYPE_RECLAIM_CREDENTIAL_ITERATION_START` assignment.
pub const RECLAIM_CREDENTIAL_ITERATION_START: MessageType = MessageType::new(980);
/// Official `GNUNET_MESSAGE_TYPE_RECLAIM_CREDENTIAL_ITERATION_STOP` assignment.
pub const RECLAIM_CREDENTIAL_ITERATION_STOP: MessageType = MessageType::new(981);
/// Official `GNUNET_MESSAGE_TYPE_RECLAIM_CREDENTIAL_ITERATION_NEXT` assignment.
pub const RECLAIM_CREDENTIAL_ITERATION_NEXT: MessageType = MessageType::new(982);
/// Official `GNUNET_MESSAGE_TYPE_ABD_VERIFY` assignment.
pub const ABD_VERIFY: MessageType = MessageType::new(991);
/// Official `GNUNET_MESSAGE_TYPE_ABD_VERIFY_RESULT` assignment.
pub const ABD_VERIFY_RESULT: MessageType = MessageType::new(992);
/// Official `GNUNET_MESSAGE_TYPE_ABD_COLLECT` assignment.
pub const ABD_COLLECT: MessageType = MessageType::new(993);
/// Official `GNUNET_MESSAGE_TYPE_ABD_COLLECT_RESULT` assignment.
pub const ABD_COLLECT_RESULT: MessageType = MessageType::new(994);
/// Official `GNUNET_MESSAGE_TYPE_ABD_INTERMEDIATE_RESULT` assignment.
pub const ABD_INTERMEDIATE_RESULT: MessageType = MessageType::new(995);
/// Official `GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE` assignment.
pub const CADET_CONNECTION_CREATE: MessageType = MessageType::new(1000);
/// Official `GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE_ACK` assignment.
pub const CADET_CONNECTION_CREATE_ACK: MessageType = MessageType::new(1001);
/// Official `GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN` assignment.
pub const CADET_CONNECTION_BROKEN: MessageType = MessageType::new(1002);
/// Official `GNUNET_MESSAGE_TYPE_CADET_CONNECTION_DESTROY` assignment.
pub const CADET_CONNECTION_DESTROY: MessageType = MessageType::new(1003);
/// Official `GNUNET_MESSAGE_TYPE_CADET_CONNECTION_PATH_CHANGED_UNIMPLEMENTED` assignment.
pub const CADET_CONNECTION_PATH_CHANGED_UNIMPLEMENTED: MessageType = MessageType::new(1004);
/// Official `GNUNET_MESSAGE_TYPE_CADET_CONNECTION_HOP_BY_HOP_ENCRYPTED_ACK` assignment.
pub const CADET_CONNECTION_HOP_BY_HOP_ENCRYPTED_ACK: MessageType = MessageType::new(1005);
/// Official `GNUNET_MESSAGE_TYPE_CADET_TUNNEL_ENCRYPTED_POLL` assignment.
pub const CADET_TUNNEL_ENCRYPTED_POLL: MessageType = MessageType::new(1006);
/// Official `GNUNET_MESSAGE_TYPE_CADET_TUNNEL_KX` assignment.
pub const CADET_TUNNEL_KX: MessageType = MessageType::new(1007);
/// Official `GNUNET_MESSAGE_TYPE_CADET_TUNNEL_ENCRYPTED` assignment.
pub const CADET_TUNNEL_ENCRYPTED: MessageType = MessageType::new(1008);
/// Official `GNUNET_MESSAGE_TYPE_CADET_TUNNEL_KX_AUTH` assignment.
pub const CADET_TUNNEL_KX_AUTH: MessageType = MessageType::new(1009);
/// Official `GNUNET_MESSAGE_TYPE_CADET_CHANNEL_APP_DATA` assignment.
pub const CADET_CHANNEL_APP_DATA: MessageType = MessageType::new(1010);
/// Official `GNUNET_MESSAGE_TYPE_CADET_CHANNEL_APP_DATA_ACK` assignment.
pub const CADET_CHANNEL_APP_DATA_ACK: MessageType = MessageType::new(1011);
/// Official `GNUNET_MESSAGE_TYPE_CADET_CHANNEL_KEEPALIVE` assignment.
pub const CADET_CHANNEL_KEEPALIVE: MessageType = MessageType::new(1012);
/// Official `GNUNET_MESSAGE_TYPE_CADET_CHANNEL_OPEN` assignment.
pub const CADET_CHANNEL_OPEN: MessageType = MessageType::new(1013);
/// Official `GNUNET_MESSAGE_TYPE_CADET_CHANNEL_DESTROY` assignment.
pub const CADET_CHANNEL_DESTROY: MessageType = MessageType::new(1014);
/// Official `GNUNET_MESSAGE_TYPE_CADET_CHANNEL_OPEN_ACK` assignment.
pub const CADET_CHANNEL_OPEN_ACK: MessageType = MessageType::new(1015);
/// Official `GNUNET_MESSAGE_TYPE_CADET_CHANNEL_OPEN_NACK_DEPRECATED` assignment.
pub const CADET_CHANNEL_OPEN_NACK_DEPRECATED: MessageType = MessageType::new(1016);
/// Official `GNUNET_MESSAGE_TYPE_CADET_LOCAL_DATA` assignment.
pub const CADET_LOCAL_DATA: MessageType = MessageType::new(1020);
/// Official `GNUNET_MESSAGE_TYPE_CADET_LOCAL_ACK` assignment.
pub const CADET_LOCAL_ACK: MessageType = MessageType::new(1021);
/// Official `GNUNET_MESSAGE_TYPE_CADET_LOCAL_PORT_OPEN` assignment.
pub const CADET_LOCAL_PORT_OPEN: MessageType = MessageType::new(1022);
/// Official `GNUNET_MESSAGE_TYPE_CADET_LOCAL_PORT_CLOSE` assignment.
pub const CADET_LOCAL_PORT_CLOSE: MessageType = MessageType::new(1023);
/// Official `GNUNET_MESSAGE_TYPE_CADET_LOCAL_CHANNEL_CREATE` assignment.
pub const CADET_LOCAL_CHANNEL_CREATE: MessageType = MessageType::new(1024);
/// Official `GNUNET_MESSAGE_TYPE_CADET_LOCAL_CHANNEL_DESTROY` assignment.
pub const CADET_LOCAL_CHANNEL_DESTROY: MessageType = MessageType::new(1025);
/// Official `GNUNET_MESSAGE_TYPE_CADET_LOCAL_REQUEST_INFO_CHANNEL` assignment.
pub const CADET_LOCAL_REQUEST_INFO_CHANNEL: MessageType = MessageType::new(1030);
/// Official `GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_CHANNEL` assignment.
pub const CADET_LOCAL_INFO_CHANNEL: MessageType = MessageType::new(1031);
/// Official `GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_CHANNEL_END` assignment.
pub const CADET_LOCAL_INFO_CHANNEL_END: MessageType = MessageType::new(1032);
/// Official `GNUNET_MESSAGE_TYPE_CADET_LOCAL_REQUEST_INFO_PEERS` assignment.
pub const CADET_LOCAL_REQUEST_INFO_PEERS: MessageType = MessageType::new(1033);
/// Official `GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEERS` assignment.
pub const CADET_LOCAL_INFO_PEERS: MessageType = MessageType::new(1034);
/// Official `GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PEERS_END` assignment.
pub const CADET_LOCAL_INFO_PEERS_END: MessageType = MessageType::new(1035);
/// Official `GNUNET_MESSAGE_TYPE_CADET_LOCAL_REQUEST_INFO_PATH` assignment.
pub const CADET_LOCAL_REQUEST_INFO_PATH: MessageType = MessageType::new(1036);
/// Official `GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PATH` assignment.
pub const CADET_LOCAL_INFO_PATH: MessageType = MessageType::new(1037);
/// Official `GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_PATH_END` assignment.
pub const CADET_LOCAL_INFO_PATH_END: MessageType = MessageType::new(1038);
/// Official `GNUNET_MESSAGE_TYPE_CADET_LOCAL_REQUEST_INFO_TUNNELS` assignment.
pub const CADET_LOCAL_REQUEST_INFO_TUNNELS: MessageType = MessageType::new(1039);
/// Official `GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNELS` assignment.
pub const CADET_LOCAL_INFO_TUNNELS: MessageType = MessageType::new(1040);
/// Official `GNUNET_MESSAGE_TYPE_CADET_LOCAL_INFO_TUNNELS_END` assignment.
pub const CADET_LOCAL_INFO_TUNNELS_END: MessageType = MessageType::new(1041);
/// Official `GNUNET_MESSAGE_TYPE_CADET_DROP_CADET_MESSAGE` assignment.
pub const CADET_DROP_CADET_MESSAGE: MessageType = MessageType::new(1042);
/// Official `GNUNET_MESSAGE_TYPE_CADET_CLI` assignment.
pub const CADET_CLI: MessageType = MessageType::new(1059);
/// Official `GNUNET_MESSAGE_TYPE_NAT_REGISTER` assignment.
pub const NAT_REGISTER: MessageType = MessageType::new(1060);
/// Official `GNUNET_MESSAGE_TYPE_NAT_HANDLE_STUN` assignment.
pub const NAT_HANDLE_STUN: MessageType = MessageType::new(1061);
/// Official `GNUNET_MESSAGE_TYPE_NAT_REQUEST_CONNECTION_REVERSAL` assignment.
pub const NAT_REQUEST_CONNECTION_REVERSAL: MessageType = MessageType::new(1062);
/// Official `GNUNET_MESSAGE_TYPE_NAT_CONNECTION_REVERSAL_REQUESTED` assignment.
pub const NAT_CONNECTION_REVERSAL_REQUESTED: MessageType = MessageType::new(1063);
/// Official `GNUNET_MESSAGE_TYPE_NAT_ADDRESS_CHANGE` assignment.
pub const NAT_ADDRESS_CHANGE: MessageType = MessageType::new(1064);
/// Official `GNUNET_MESSAGE_TYPE_NAT_ADD_GLOBAL_ADDRESS` assignment.
pub const NAT_ADD_GLOBAL_ADDRESS: MessageType = MessageType::new(1065);
/// Official `GNUNET_MESSAGE_TYPE_NAT_AUTO_REQUEST_CFG` assignment.
pub const NAT_AUTO_REQUEST_CFG: MessageType = MessageType::new(1067);
/// Official `GNUNET_MESSAGE_TYPE_NAT_AUTO_CFG_RESULT` assignment.
pub const NAT_AUTO_CFG_RESULT: MessageType = MessageType::new(1068);
/// Official `GNUNET_MESSAGE_TYPE_AUCTION_CLIENT_CREATE` assignment.
pub const AUCTION_CLIENT_CREATE: MessageType = MessageType::new(1110);
/// Official `GNUNET_MESSAGE_TYPE_AUCTION_CLIENT_JOIN` assignment.
pub const AUCTION_CLIENT_JOIN: MessageType = MessageType::new(1111);
/// Official `GNUNET_MESSAGE_TYPE_AUCTION_CLIENT_OUTCOME` assignment.
pub const AUCTION_CLIENT_OUTCOME: MessageType = MessageType::new(1112);
/// Official `GNUNET_MESSAGE_TYPE_RPS_CS_DEBUG_VIEW_REQUEST` assignment.
pub const RPS_CS_DEBUG_VIEW_REQUEST: MessageType = MessageType::new(1130);
/// Official `GNUNET_MESSAGE_TYPE_RPS_CS_DEBUG_VIEW_REPLY` assignment.
pub const RPS_CS_DEBUG_VIEW_REPLY: MessageType = MessageType::new(1131);
/// Official `GNUNET_MESSAGE_TYPE_RPS_CS_DEBUG_VIEW_CANCEL` assignment.
pub const RPS_CS_DEBUG_VIEW_CANCEL: MessageType = MessageType::new(1132);
/// Official `GNUNET_MESSAGE_TYPE_RPS_CS_DEBUG_STREAM_REQUEST` assignment.
pub const RPS_CS_DEBUG_STREAM_REQUEST: MessageType = MessageType::new(1133);
/// Official `GNUNET_MESSAGE_TYPE_RPS_CS_DEBUG_STREAM_REPLY` assignment.
pub const RPS_CS_DEBUG_STREAM_REPLY: MessageType = MessageType::new(1134);
/// Official `GNUNET_MESSAGE_TYPE_RPS_CS_DEBUG_STREAM_CANCEL` assignment.
pub const RPS_CS_DEBUG_STREAM_CANCEL: MessageType = MessageType::new(1135);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_ADD_ADDRESS` assignment.
pub const TRANSPORT_ADD_ADDRESS: MessageType = MessageType::new(1200);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_DEL_ADDRESS` assignment.
pub const TRANSPORT_DEL_ADDRESS: MessageType = MessageType::new(1201);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_INCOMING_MSG` assignment.
pub const TRANSPORT_INCOMING_MSG: MessageType = MessageType::new(1202);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_INCOMING_MSG_ACK` assignment.
pub const TRANSPORT_INCOMING_MSG_ACK: MessageType = MessageType::new(1203);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_SETUP` assignment.
pub const TRANSPORT_QUEUE_SETUP: MessageType = MessageType::new(1204);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_TEARDOWN` assignment.
pub const TRANSPORT_QUEUE_TEARDOWN: MessageType = MessageType::new(1205);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_CREATE` assignment.
pub const TRANSPORT_QUEUE_CREATE: MessageType = MessageType::new(1206);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_CREATE_OK` assignment.
pub const TRANSPORT_QUEUE_CREATE_OK: MessageType = MessageType::new(1207);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_CREATE_FAIL` assignment.
pub const TRANSPORT_QUEUE_CREATE_FAIL: MessageType = MessageType::new(1208);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_MSG` assignment.
pub const TRANSPORT_SEND_MSG: MessageType = MessageType::new(1209);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_SEND_MSG_ACK` assignment.
pub const TRANSPORT_SEND_MSG_ACK: MessageType = MessageType::new(1210);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_NEW_COMMUNICATOR` assignment.
pub const TRANSPORT_NEW_COMMUNICATOR: MessageType = MessageType::new(1211);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_COMMUNICATOR_BACKCHANNEL` assignment.
pub const TRANSPORT_COMMUNICATOR_BACKCHANNEL: MessageType = MessageType::new(1212);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_BACKCHANNEL_ENCAPSULATION` assignment.
pub const TRANSPORT_BACKCHANNEL_ENCAPSULATION: MessageType = MessageType::new(1213);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_FRAGMENT` assignment.
pub const TRANSPORT_FRAGMENT: MessageType = MessageType::new(1214);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_RELIABILITY_BOX` assignment.
pub const TRANSPORT_RELIABILITY_BOX: MessageType = MessageType::new(1216);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_RELIABILITY_ACK` assignment.
pub const TRANSPORT_RELIABILITY_ACK: MessageType = MessageType::new(1217);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_DV_LEARN` assignment.
pub const TRANSPORT_DV_LEARN: MessageType = MessageType::new(1218);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_DV_BOX` assignment.
pub const TRANSPORT_DV_BOX: MessageType = MessageType::new(1219);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_COMMUNICATOR_BACKCHANNEL_INCOMING` assignment.
pub const TRANSPORT_COMMUNICATOR_BACKCHANNEL_INCOMING: MessageType = MessageType::new(1220);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_FLOW_CONTROL` assignment.
pub const TRANSPORT_FLOW_CONTROL: MessageType = MessageType::new(1221);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_QUEUE_UPDATE` assignment.
pub const TRANSPORT_QUEUE_UPDATE: MessageType = MessageType::new(1222);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_START` assignment.
pub const TRANSPORT_MONITOR_START: MessageType = MessageType::new(1250);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_DATA` assignment.
pub const TRANSPORT_MONITOR_DATA: MessageType = MessageType::new(1251);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_END` assignment.
pub const TRANSPORT_MONITOR_END: MessageType = MessageType::new(1252);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_START_BURST` assignment.
pub const TRANSPORT_START_BURST: MessageType = MessageType::new(1253);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_BURST_FINISHED` assignment.
pub const TRANSPORT_BURST_FINISHED: MessageType = MessageType::new(1254);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_LINK_LIST_REQUEST` assignment.
pub const TRANSPORT_LINK_LIST_REQUEST: MessageType = MessageType::new(1255);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_LINK_LIST_RESPONSE` assignment.
pub const TRANSPORT_LINK_LIST_RESPONSE: MessageType = MessageType::new(1256);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_LINK_LIST_RESPONSE_END` assignment.
pub const TRANSPORT_LINK_LIST_RESPONSE_END: MessageType = MessageType::new(1257);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_COMMUNICATOR_KX_CONFIRMATION` assignment.
pub const TRANSPORT_COMMUNICATOR_KX_CONFIRMATION: MessageType = MessageType::new(1275);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_COMMUNICATOR_FC_LIMITS` assignment.
pub const TRANSPORT_COMMUNICATOR_FC_LIMITS: MessageType = MessageType::new(1276);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_SUGGEST` assignment.
pub const TRANSPORT_SUGGEST: MessageType = MessageType::new(1300);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_SUGGEST_CANCEL` assignment.
pub const TRANSPORT_SUGGEST_CANCEL: MessageType = MessageType::new(1301);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_REQUEST_HELLO_VALIDATION` assignment.
pub const TRANSPORT_REQUEST_HELLO_VALIDATION: MessageType = MessageType::new(1302);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_VALIDATION_CHALLENGE` assignment.
pub const TRANSPORT_ADDRESS_VALIDATION_CHALLENGE: MessageType = MessageType::new(1303);
/// Official `GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_VALIDATION_RESPONSE` assignment.
pub const TRANSPORT_ADDRESS_VALIDATION_RESPONSE: MessageType = MessageType::new(1304);
/// Official `GNUNET_MESSAGE_TYPE_ATS_SUGGEST` assignment.
pub const ATS_SUGGEST: MessageType = MessageType::new(1400);
/// Official `GNUNET_MESSAGE_TYPE_ATS_SUGGEST_CANCEL` assignment.
pub const ATS_SUGGEST_CANCEL: MessageType = MessageType::new(1401);
/// Official `GNUNET_MESSAGE_TYPE_ATS_SESSION_ADD` assignment.
pub const ATS_SESSION_ADD: MessageType = MessageType::new(1402);
/// Official `GNUNET_MESSAGE_TYPE_ATS_SESSION_ADD_INBOUND_ONLY` assignment.
pub const ATS_SESSION_ADD_INBOUND_ONLY: MessageType = MessageType::new(1403);
/// Official `GNUNET_MESSAGE_TYPE_ATS_SESSION_UPDATE` assignment.
pub const ATS_SESSION_UPDATE: MessageType = MessageType::new(1404);
/// Official `GNUNET_MESSAGE_TYPE_ATS_SESSION_DEL` assignment.
pub const ATS_SESSION_DEL: MessageType = MessageType::new(1405);
/// Official `GNUNET_MESSAGE_TYPE_ATS_SESSION_ALLOCATION` assignment.
pub const ATS_SESSION_ALLOCATION: MessageType = MessageType::new(1406);
/// Official `GNUNET_MESSAGE_TYPE_COMMUNICATOR_TCP_REKEY` assignment.
pub const COMMUNICATOR_TCP_REKEY: MessageType = MessageType::new(1450);
/// Official `GNUNET_MESSAGE_TYPE_COMMUNICATOR_TCP_BOX` assignment.
pub const COMMUNICATOR_TCP_BOX: MessageType = MessageType::new(1451);
/// Official `GNUNET_MESSAGE_TYPE_COMMUNICATOR_TCP_FINISH` assignment.
pub const COMMUNICATOR_TCP_FINISH: MessageType = MessageType::new(1452);
/// Official `GNUNET_MESSAGE_TYPE_COMMUNICATOR_TCP_CONFIRMATION_ACK` assignment.
pub const COMMUNICATOR_TCP_CONFIRMATION_ACK: MessageType = MessageType::new(1453);
/// Official `GNUNET_MESSAGE_TYPE_COMMUNICATOR_UDP_ACK` assignment.
pub const COMMUNICATOR_UDP_ACK: MessageType = MessageType::new(1460);
/// Official `GNUNET_MESSAGE_TYPE_COMMUNICATOR_UDP_PAD` assignment.
pub const COMMUNICATOR_UDP_PAD: MessageType = MessageType::new(1461);
/// Official `GNUNET_MESSAGE_TYPE_COMMUNICATOR_UDP_REKEY` assignment.
pub const COMMUNICATOR_UDP_REKEY: MessageType = MessageType::new(1462);
/// Official `GNUNET_MESSAGE_TYPE_RECLAIM_REFERENCE_DELETE` assignment.
pub const RECLAIM_REFERENCE_DELETE: MessageType = MessageType::new(1500);
/// Official `GNUNET_MESSAGE_TYPE_RECLAIM_REFERENCE_RESULT` assignment.
pub const RECLAIM_REFERENCE_RESULT: MessageType = MessageType::new(1501);
/// Official `GNUNET_MESSAGE_TYPE_MESSENGER_CONNECTION_CREATE` assignment.
pub const MESSENGER_CONNECTION_CREATE: MessageType = MessageType::new(1600);
/// Official `GNUNET_MESSAGE_TYPE_MESSENGER_CONNECTION_DESTROY` assignment.
pub const MESSENGER_CONNECTION_DESTROY: MessageType = MessageType::new(1601);
/// Official `GNUNET_MESSAGE_TYPE_MESSENGER_CONNECTION_MEMBER_ID` assignment.
pub const MESSENGER_CONNECTION_MEMBER_ID: MessageType = MessageType::new(1602);
/// Official `GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_OPEN` assignment.
pub const MESSENGER_ROOM_OPEN: MessageType = MessageType::new(1610);
/// Official `GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_ENTRY` assignment.
pub const MESSENGER_ROOM_ENTRY: MessageType = MessageType::new(1611);
/// Official `GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_CLOSE` assignment.
pub const MESSENGER_ROOM_CLOSE: MessageType = MessageType::new(1612);
/// Official `GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_SEND_MESSAGE` assignment.
pub const MESSENGER_ROOM_SEND_MESSAGE: MessageType = MessageType::new(1614);
/// Official `GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_RECV_MESSAGE` assignment.
pub const MESSENGER_ROOM_RECV_MESSAGE: MessageType = MessageType::new(1615);
/// Official `GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_GET_MESSAGE` assignment.
pub const MESSENGER_ROOM_GET_MESSAGE: MessageType = MessageType::new(1616);
/// Official `GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_SYNC` assignment.
pub const MESSENGER_ROOM_SYNC: MessageType = MessageType::new(1617);
/// Official `GNUNET_MESSAGE_TYPE_MESSENGER_ROOM_LINK` assignment.
pub const MESSENGER_ROOM_LINK: MessageType = MessageType::new(1618);
/// Official `GNUNET_MESSAGE_TYPE_CMDS_HELPER_INIT` assignment.
pub const CMDS_HELPER_INIT: MessageType = MessageType::new(1700);
/// Official `GNUNET_MESSAGE_TYPE_CMDS_HELPER_REPLY` assignment.
pub const CMDS_HELPER_REPLY: MessageType = MessageType::new(1701);
/// Official `GNUNET_MESSAGE_TYPE_CMDS_HELPER_PEER_STARTED` assignment.
pub const CMDS_HELPER_PEER_STARTED: MessageType = MessageType::new(1702);
/// Official `GNUNET_MESSAGE_TYPE_CMDS_HELPER_ALL_PEERS_STARTED` assignment.
pub const CMDS_HELPER_ALL_PEERS_STARTED: MessageType = MessageType::new(1703);
/// Official `GNUNET_MESSAGE_TYPE_CMDS_HELPER_LOCAL_TEST_PREPARED` assignment.
pub const CMDS_HELPER_LOCAL_TEST_PREPARED: MessageType = MessageType::new(1704);
/// Official `GNUNET_MESSAGE_TYPE_CMDS_HELPER_ALL_LOCAL_TESTS_PREPARED` assignment.
pub const CMDS_HELPER_ALL_LOCAL_TESTS_PREPARED: MessageType = MessageType::new(1705);
/// Official `GNUNET_MESSAGE_TYPE_CMDS_HELPER_LOCAL_FINISHED` assignment.
pub const CMDS_HELPER_LOCAL_FINISHED: MessageType = MessageType::new(1706);
/// Official `GNUNET_MESSAGE_TYPE_CMDS_HELPER_BARRIER_REACHED` assignment.
pub const CMDS_HELPER_BARRIER_REACHED: MessageType = MessageType::new(1707);
/// Official `GNUNET_MESSAGE_TYPE_CMDS_HELPER_BARRIER_ATTACH` assignment.
pub const CMDS_HELPER_BARRIER_ATTACH: MessageType = MessageType::new(1708);
/// Official `GNUNET_MESSAGE_TYPE_CMDS_HELPER_BARRIER_CROSSABLE` assignment.
pub const CMDS_HELPER_BARRIER_CROSSABLE: MessageType = MessageType::new(1709);
/// Official `GNUNET_MESSAGE_TYPE_CMDS_HELPER_BARRIER_ATTACHED` assignment.
pub const CMDS_HELPER_BARRIER_ATTACHED: MessageType = MessageType::new(1710);
/// Official `GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_SET_EDIT` assignment.
pub const NAMESTORE_RECORD_SET_EDIT: MessageType = MessageType::new(1750);
/// Official `GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_SET_EDIT_RESPONSE` assignment.
pub const NAMESTORE_RECORD_SET_EDIT_RESPONSE: MessageType = MessageType::new(1751);
/// Official `GNUNET_MESSAGE_TYPE_NAMESTORE_RECORD_SET_EDIT_CANCEL` assignment.
pub const NAMESTORE_RECORD_SET_EDIT_CANCEL: MessageType = MessageType::new(1752);
/// Official `GNUNET_MESSAGE_TYPE_CORE_PEER_ID` assignment.
pub const CORE_PEER_ID: MessageType = MessageType::new(1811);
/// Official `GNUNET_MESSAGE_TYPE_PILS_PEER_ID` assignment.
pub const PILS_PEER_ID: MessageType = MessageType::new(1831);
/// Official `GNUNET_MESSAGE_TYPE_PILS_SIGN_REQUEST` assignment.
pub const PILS_SIGN_REQUEST: MessageType = MessageType::new(1832);
/// Official `GNUNET_MESSAGE_TYPE_PILS_SIGN_RESULT` assignment.
pub const PILS_SIGN_RESULT: MessageType = MessageType::new(1833);
/// Official `GNUNET_MESSAGE_TYPE_PILS_FEED_ADDRESSES` assignment.
pub const PILS_FEED_ADDRESSES: MessageType = MessageType::new(1834);
/// Official `GNUNET_MESSAGE_TYPE_PILS_KEM_DECAPS` assignment.
pub const PILS_KEM_DECAPS: MessageType = MessageType::new(1835);
/// Official `GNUNET_MESSAGE_TYPE_PILS_DECAPS_RESULT` assignment.
pub const PILS_DECAPS_RESULT: MessageType = MessageType::new(1836);
/// Official `GNUNET_MESSAGE_TYPE_PILS_ECDH` assignment.
pub const PILS_ECDH: MessageType = MessageType::new(1837);
/// Official `GNUNET_MESSAGE_TYPE_PILS_ECDH_RESULT` assignment.
pub const PILS_ECDH_RESULT: MessageType = MessageType::new(1838);
/// Official `GNUNET_MESSAGE_TYPE_NAMECACHE_BLOCK_DELETE` assignment.
pub const NAMECACHE_BLOCK_DELETE: MessageType = MessageType::new(1850);
/// Official `GNUNET_MESSAGE_TYPE_NAMECACHE_BLOCK_DELETE_RESPONSE` assignment.
pub const NAMECACHE_BLOCK_DELETE_RESPONSE: MessageType = MessageType::new(1851);
/// Official `GNUNET_MESSAGE_TYPE_ALL` assignment.
pub const ALL: MessageType = MessageType::new(65535);

/// Every message name and numeric assignment in the pinned upstream registry.
/// Historical assignments are retained; this table makes no implementation claims.
pub const REGISTRY: &[(&str, MessageType)] = &[
    ("TEST", TEST),
    ("REQUEST_AGPL", REQUEST_AGPL),
    ("RESPONSE_AGPL", RESPONSE_AGPL),
    ("RESOLVER_REQUEST", RESOLVER_REQUEST),
    ("RESOLVER_RESPONSE", RESOLVER_RESPONSE),
    ("DUMMY", DUMMY),
    ("DUMMY2", DUMMY2),
    ("ARM_START", ARM_START),
    ("ARM_STOP", ARM_STOP),
    ("ARM_RESULT", ARM_RESULT),
    ("ARM_STATUS", ARM_STATUS),
    ("ARM_LIST", ARM_LIST),
    ("ARM_LIST_RESULT", ARM_LIST_RESULT),
    ("ARM_MONITOR", ARM_MONITOR),
    ("ARM_TEST", ARM_TEST),
    ("HELLO_URI", HELLO_URI),
    ("HELLO", HELLO),
    ("FRAGMENT", FRAGMENT),
    ("FRAGMENT_ACK", FRAGMENT_ACK),
    ("WLAN_DATA_TO_HELPER", WLAN_DATA_TO_HELPER),
    ("WLAN_DATA_FROM_HELPER", WLAN_DATA_FROM_HELPER),
    ("WLAN_HELPER_CONTROL", WLAN_HELPER_CONTROL),
    ("WLAN_ADVERTISEMENT", WLAN_ADVERTISEMENT),
    ("WLAN_DATA", WLAN_DATA),
    ("DV_RECV", DV_RECV),
    ("DV_SEND", DV_SEND),
    ("DV_SEND_ACK", DV_SEND_ACK),
    ("DV_ROUTE", DV_ROUTE),
    ("DV_START", DV_START),
    ("DV_CONNECT", DV_CONNECT),
    ("DV_DISCONNECT", DV_DISCONNECT),
    ("DV_SEND_NACK", DV_SEND_NACK),
    ("DV_DISTANCE_CHANGED", DV_DISTANCE_CHANGED),
    ("DV_BOX", DV_BOX),
    ("TRANSPORT_XU_MESSAGE", TRANSPORT_XU_MESSAGE),
    ("TRANSPORT_UDP_MESSAGE", TRANSPORT_UDP_MESSAGE),
    ("TRANSPORT_UDP_ACK", TRANSPORT_UDP_ACK),
    ("TRANSPORT_TCP_NAT_PROBE", TRANSPORT_TCP_NAT_PROBE),
    ("TRANSPORT_TCP_WELCOME", TRANSPORT_TCP_WELCOME),
    ("TRANSPORT_ATS", TRANSPORT_ATS),
    ("NAT_TEST", NAT_TEST),
    ("CORE_INIT", CORE_INIT),
    ("CORE_INIT_REPLY", CORE_INIT_REPLY),
    ("CORE_NOTIFY_CONNECT", CORE_NOTIFY_CONNECT),
    ("CORE_NOTIFY_DISCONNECT", CORE_NOTIFY_DISCONNECT),
    ("CORE_NOTIFY_STATUS_CHANGE", CORE_NOTIFY_STATUS_CHANGE),
    ("CORE_NOTIFY_INBOUND", CORE_NOTIFY_INBOUND),
    ("CORE_NOTIFY_OUTBOUND", CORE_NOTIFY_OUTBOUND),
    ("CORE_SEND_REQUEST", CORE_SEND_REQUEST),
    ("CORE_SEND_READY", CORE_SEND_READY),
    ("CORE_SEND", CORE_SEND),
    ("CORE_MONITOR_PEERS", CORE_MONITOR_PEERS),
    ("CORE_MONITOR_NOTIFY", CORE_MONITOR_NOTIFY),
    ("CORE_INITIATOR_HELLO", CORE_INITIATOR_HELLO),
    ("CORE_RESPONDER_HELLO", CORE_RESPONDER_HELLO),
    ("CORE_INITIATOR_DONE", CORE_INITIATOR_DONE),
    ("CORE_ENCRYPTED_MESSAGE_CAKE", CORE_ENCRYPTED_MESSAGE_CAKE),
    ("CORE_HEARTBEAT", CORE_HEARTBEAT),
    ("CORE_ACK", CORE_ACK),
    ("DATASTORE_RESERVE", DATASTORE_RESERVE),
    ("DATASTORE_RELEASE_RESERVE", DATASTORE_RELEASE_RESERVE),
    ("DATASTORE_STATUS", DATASTORE_STATUS),
    ("DATASTORE_PUT", DATASTORE_PUT),
    ("DATASTORE_GET", DATASTORE_GET),
    ("DATASTORE_GET_REPLICATION", DATASTORE_GET_REPLICATION),
    ("DATASTORE_GET_ZERO_ANONYMITY", DATASTORE_GET_ZERO_ANONYMITY),
    ("DATASTORE_DATA", DATASTORE_DATA),
    ("DATASTORE_DATA_END", DATASTORE_DATA_END),
    ("DATASTORE_REMOVE", DATASTORE_REMOVE),
    ("DATASTORE_DROP", DATASTORE_DROP),
    ("DATASTORE_GET_KEY", DATASTORE_GET_KEY),
    ("FS_REQUEST_LOC_SIGN", FS_REQUEST_LOC_SIGN),
    ("FS_REQUEST_LOC_SIGNATURE", FS_REQUEST_LOC_SIGNATURE),
    ("FS_INDEX_START", FS_INDEX_START),
    ("FS_INDEX_START_OK", FS_INDEX_START_OK),
    ("FS_INDEX_START_FAILED", FS_INDEX_START_FAILED),
    ("FS_INDEX_LIST_GET", FS_INDEX_LIST_GET),
    ("FS_INDEX_LIST_ENTRY", FS_INDEX_LIST_ENTRY),
    ("FS_INDEX_LIST_END", FS_INDEX_LIST_END),
    ("FS_UNINDEX", FS_UNINDEX),
    ("FS_UNINDEX_OK", FS_UNINDEX_OK),
    ("FS_START_SEARCH", FS_START_SEARCH),
    ("FS_GET", FS_GET),
    ("FS_PUT", FS_PUT),
    ("FS_MIGRATION_STOP", FS_MIGRATION_STOP),
    ("FS_CADET_QUERY", FS_CADET_QUERY),
    ("FS_CADET_REPLY", FS_CADET_REPLY),
    ("DHT_CLIENT_PUT", DHT_CLIENT_PUT),
    ("DHT_CLIENT_GET", DHT_CLIENT_GET),
    ("DHT_CLIENT_GET_STOP", DHT_CLIENT_GET_STOP),
    ("DHT_CLIENT_RESULT", DHT_CLIENT_RESULT),
    ("DHT_P2P_PUT", DHT_P2P_PUT),
    ("DHT_P2P_GET", DHT_P2P_GET),
    ("DHT_P2P_RESULT", DHT_P2P_RESULT),
    ("DHT_MONITOR_GET", DHT_MONITOR_GET),
    ("DHT_MONITOR_GET_RESP", DHT_MONITOR_GET_RESP),
    ("DHT_MONITOR_PUT", DHT_MONITOR_PUT),
    ("DHT_MONITOR_PUT_RESP", DHT_MONITOR_PUT_RESP),
    ("DHT_MONITOR_START", DHT_MONITOR_START),
    ("DHT_MONITOR_STOP", DHT_MONITOR_STOP),
    ("DHT_CLIENT_GET_RESULTS_KNOWN", DHT_CLIENT_GET_RESULTS_KNOWN),
    ("DHT_P2P_HELLO", DHT_P2P_HELLO),
    ("DHT_CORE", DHT_CORE),
    ("DHT_CLIENT_HELLO_URL", DHT_CLIENT_HELLO_URL),
    ("DHT_CLIENT_HELLO_GET", DHT_CLIENT_HELLO_GET),
    ("HOSTLIST_ADVERTISEMENT", HOSTLIST_ADVERTISEMENT),
    ("STATISTICS_SET", STATISTICS_SET),
    ("STATISTICS_GET", STATISTICS_GET),
    ("STATISTICS_VALUE", STATISTICS_VALUE),
    ("STATISTICS_END", STATISTICS_END),
    ("STATISTICS_WATCH", STATISTICS_WATCH),
    ("STATISTICS_WATCH_VALUE", STATISTICS_WATCH_VALUE),
    ("STATISTICS_DISCONNECT", STATISTICS_DISCONNECT),
    (
        "STATISTICS_DISCONNECT_CONFIRM",
        STATISTICS_DISCONNECT_CONFIRM,
    ),
    ("VPN_HELPER", VPN_HELPER),
    ("VPN_ICMP_TO_SERVICE", VPN_ICMP_TO_SERVICE),
    ("VPN_ICMP_TO_INTERNET", VPN_ICMP_TO_INTERNET),
    ("VPN_ICMP_TO_VPN", VPN_ICMP_TO_VPN),
    ("VPN_DNS_TO_INTERNET", VPN_DNS_TO_INTERNET),
    ("VPN_DNS_FROM_INTERNET", VPN_DNS_FROM_INTERNET),
    ("VPN_TCP_TO_SERVICE_START", VPN_TCP_TO_SERVICE_START),
    ("VPN_TCP_TO_INTERNET_START", VPN_TCP_TO_INTERNET_START),
    ("VPN_TCP_DATA_TO_EXIT", VPN_TCP_DATA_TO_EXIT),
    ("VPN_TCP_DATA_TO_VPN", VPN_TCP_DATA_TO_VPN),
    ("VPN_UDP_TO_SERVICE", VPN_UDP_TO_SERVICE),
    ("VPN_UDP_TO_INTERNET", VPN_UDP_TO_INTERNET),
    ("VPN_UDP_REPLY", VPN_UDP_REPLY),
    ("VPN_CLIENT_REDIRECT_TO_IP", VPN_CLIENT_REDIRECT_TO_IP),
    (
        "VPN_CLIENT_REDIRECT_TO_SERVICE",
        VPN_CLIENT_REDIRECT_TO_SERVICE,
    ),
    ("VPN_CLIENT_USE_IP", VPN_CLIENT_USE_IP),
    ("DNS_CLIENT_INIT", DNS_CLIENT_INIT),
    ("DNS_CLIENT_REQUEST", DNS_CLIENT_REQUEST),
    ("DNS_CLIENT_RESPONSE", DNS_CLIENT_RESPONSE),
    ("DNS_HELPER", DNS_HELPER),
    ("CHAT_JOIN_REQUEST", CHAT_JOIN_REQUEST),
    ("CHAT_JOIN_NOTIFICATION", CHAT_JOIN_NOTIFICATION),
    ("CHAT_LEAVE_NOTIFICATION", CHAT_LEAVE_NOTIFICATION),
    ("CHAT_MESSAGE_NOTIFICATION", CHAT_MESSAGE_NOTIFICATION),
    ("CHAT_TRANSMIT_REQUEST", CHAT_TRANSMIT_REQUEST),
    ("CHAT_CONFIRMATION_RECEIPT", CHAT_CONFIRMATION_RECEIPT),
    (
        "CHAT_CONFIRMATION_NOTIFICATION",
        CHAT_CONFIRMATION_NOTIFICATION,
    ),
    ("CHAT_P2P_JOIN_NOTIFICATION", CHAT_P2P_JOIN_NOTIFICATION),
    ("CHAT_P2P_LEAVE_NOTIFICATION", CHAT_P2P_LEAVE_NOTIFICATION),
    ("CHAT_P2P_SYNC_REQUEST", CHAT_P2P_SYNC_REQUEST),
    (
        "CHAT_P2P_MESSAGE_NOTIFICATION",
        CHAT_P2P_MESSAGE_NOTIFICATION,
    ),
    (
        "CHAT_P2P_CONFIRMATION_RECEIPT",
        CHAT_P2P_CONFIRMATION_RECEIPT,
    ),
    ("NSE_START", NSE_START),
    ("NSE_P2P_FLOOD", NSE_P2P_FLOOD),
    ("NSE_ESTIMATE", NSE_ESTIMATE),
    ("PEERINFO_GET", PEERINFO_GET),
    ("PEERINFO_GET_ALL", PEERINFO_GET_ALL),
    ("PEERINFO_INFO", PEERINFO_INFO),
    ("PEERINFO_INFO_END", PEERINFO_INFO_END),
    ("PEERINFO_NOTIFY", PEERINFO_NOTIFY),
    ("ATS_START", ATS_START),
    ("ATS_REQUEST_ADDRESS", ATS_REQUEST_ADDRESS),
    ("ATS_REQUEST_ADDRESS_CANCEL", ATS_REQUEST_ADDRESS_CANCEL),
    ("ATS_ADDRESS_UPDATE", ATS_ADDRESS_UPDATE),
    ("ATS_ADDRESS_DESTROYED", ATS_ADDRESS_DESTROYED),
    ("ATS_ADDRESS_SUGGESTION", ATS_ADDRESS_SUGGESTION),
    ("ATS_PEER_INFORMATION", ATS_PEER_INFORMATION),
    ("ATS_RESERVATION_REQUEST", ATS_RESERVATION_REQUEST),
    ("ATS_RESERVATION_RESULT", ATS_RESERVATION_RESULT),
    ("ATS_PREFERENCE_CHANGE", ATS_PREFERENCE_CHANGE),
    ("ATS_SESSION_RELEASE", ATS_SESSION_RELEASE),
    ("ATS_ADDRESS_ADD", ATS_ADDRESS_ADD),
    ("ATS_ADDRESSLIST_REQUEST", ATS_ADDRESSLIST_REQUEST),
    ("ATS_ADDRESSLIST_RESPONSE", ATS_ADDRESSLIST_RESPONSE),
    ("ATS_PREFERENCE_FEEDBACK", ATS_PREFERENCE_FEEDBACK),
    ("TRANSPORT_START", TRANSPORT_START),
    ("TRANSPORT_CONNECT", TRANSPORT_CONNECT),
    ("TRANSPORT_DISCONNECT", TRANSPORT_DISCONNECT),
    ("TRANSPORT_SEND", TRANSPORT_SEND),
    ("TRANSPORT_SEND_OK", TRANSPORT_SEND_OK),
    ("TRANSPORT_RECV", TRANSPORT_RECV),
    ("TRANSPORT_SET_QUOTA", TRANSPORT_SET_QUOTA),
    ("TRANSPORT_RECV_OK", TRANSPORT_RECV_OK),
    ("TRANSPORT_ADDRESS_TO_STRING", TRANSPORT_ADDRESS_TO_STRING),
    (
        "TRANSPORT_ADDRESS_TO_STRING_REPLY",
        TRANSPORT_ADDRESS_TO_STRING_REPLY,
    ),
    ("TRANSPORT_BLACKLIST_INIT", TRANSPORT_BLACKLIST_INIT),
    ("TRANSPORT_BLACKLIST_QUERY", TRANSPORT_BLACKLIST_QUERY),
    ("TRANSPORT_BLACKLIST_REPLY", TRANSPORT_BLACKLIST_REPLY),
    ("TRANSPORT_PING", TRANSPORT_PING),
    ("TRANSPORT_PONG", TRANSPORT_PONG),
    ("TRANSPORT_SESSION_SYN", TRANSPORT_SESSION_SYN),
    ("TRANSPORT_SESSION_SYN_ACK", TRANSPORT_SESSION_SYN_ACK),
    ("TRANSPORT_SESSION_ACK", TRANSPORT_SESSION_ACK),
    ("TRANSPORT_SESSION_DISCONNECT", TRANSPORT_SESSION_DISCONNECT),
    ("TRANSPORT_SESSION_QUOTA", TRANSPORT_SESSION_QUOTA),
    (
        "TRANSPORT_MONITOR_PEER_REQUEST",
        TRANSPORT_MONITOR_PEER_REQUEST,
    ),
    ("TRANSPORT_SESSION_KEEPALIVE", TRANSPORT_SESSION_KEEPALIVE),
    (
        "TRANSPORT_SESSION_KEEPALIVE_RESPONSE",
        TRANSPORT_SESSION_KEEPALIVE_RESPONSE,
    ),
    (
        "TRANSPORT_MONITOR_PEER_RESPONSE",
        TRANSPORT_MONITOR_PEER_RESPONSE,
    ),
    ("TRANSPORT_BROADCAST_BEACON", TRANSPORT_BROADCAST_BEACON),
    ("TRANSPORT_TRAFFIC_METRIC", TRANSPORT_TRAFFIC_METRIC),
    (
        "TRANSPORT_MONITOR_PLUGIN_START",
        TRANSPORT_MONITOR_PLUGIN_START,
    ),
    (
        "TRANSPORT_MONITOR_PLUGIN_EVENT",
        TRANSPORT_MONITOR_PLUGIN_EVENT,
    ),
    (
        "TRANSPORT_MONITOR_PLUGIN_SYNC",
        TRANSPORT_MONITOR_PLUGIN_SYNC,
    ),
    (
        "TRANSPORT_MONITOR_PEER_RESPONSE_END",
        TRANSPORT_MONITOR_PEER_RESPONSE_END,
    ),
    (
        "FS_PUBLISH_HELPER_PROGRESS_FILE",
        FS_PUBLISH_HELPER_PROGRESS_FILE,
    ),
    (
        "FS_PUBLISH_HELPER_PROGRESS_DIRECTORY",
        FS_PUBLISH_HELPER_PROGRESS_DIRECTORY,
    ),
    ("FS_PUBLISH_HELPER_ERROR", FS_PUBLISH_HELPER_ERROR),
    ("FS_PUBLISH_HELPER_SKIP_FILE", FS_PUBLISH_HELPER_SKIP_FILE),
    (
        "FS_PUBLISH_HELPER_COUNTING_DONE",
        FS_PUBLISH_HELPER_COUNTING_DONE,
    ),
    ("FS_PUBLISH_HELPER_META_DATA", FS_PUBLISH_HELPER_META_DATA),
    ("FS_PUBLISH_HELPER_FINISHED", FS_PUBLISH_HELPER_FINISHED),
    ("NAMECACHE_LOOKUP_BLOCK", NAMECACHE_LOOKUP_BLOCK),
    (
        "NAMECACHE_LOOKUP_BLOCK_RESPONSE",
        NAMECACHE_LOOKUP_BLOCK_RESPONSE,
    ),
    ("NAMECACHE_BLOCK_CACHE", NAMECACHE_BLOCK_CACHE),
    (
        "NAMECACHE_BLOCK_CACHE_RESPONSE",
        NAMECACHE_BLOCK_CACHE_RESPONSE,
    ),
    ("NAMESTORE_RECORD_STORE", NAMESTORE_RECORD_STORE),
    ("NAMESTORE_GENERIC_RESPONSE", NAMESTORE_GENERIC_RESPONSE),
    ("NAMESTORE_RECORD_LOOKUP", NAMESTORE_RECORD_LOOKUP),
    (
        "NAMESTORE_RECORD_LOOKUP_RESPONSE",
        NAMESTORE_RECORD_LOOKUP_RESPONSE,
    ),
    ("NAMESTORE_ZONE_TO_NAME", NAMESTORE_ZONE_TO_NAME),
    (
        "NAMESTORE_ZONE_TO_NAME_RESPONSE",
        NAMESTORE_ZONE_TO_NAME_RESPONSE,
    ),
    ("NAMESTORE_MONITOR_START", NAMESTORE_MONITOR_START),
    ("NAMESTORE_MONITOR_SYNC", NAMESTORE_MONITOR_SYNC),
    ("NAMESTORE_RECORD_RESULT", NAMESTORE_RECORD_RESULT),
    ("NAMESTORE_MONITOR_NEXT", NAMESTORE_MONITOR_NEXT),
    (
        "NAMESTORE_ZONE_ITERATION_START",
        NAMESTORE_ZONE_ITERATION_START,
    ),
    (
        "NAMESTORE_ZONE_ITERATION_NEXT",
        NAMESTORE_ZONE_ITERATION_NEXT,
    ),
    (
        "NAMESTORE_ZONE_ITERATION_STOP",
        NAMESTORE_ZONE_ITERATION_STOP,
    ),
    ("NAMESTORE_RECORD_RESULT_END", NAMESTORE_RECORD_RESULT_END),
    ("LOCKMANAGER_ACQUIRE", LOCKMANAGER_ACQUIRE),
    ("LOCKMANAGER_RELEASE", LOCKMANAGER_RELEASE),
    ("LOCKMANAGER_SUCCESS", LOCKMANAGER_SUCCESS),
    ("TESTBED_INIT", TESTBED_INIT),
    ("TESTBED_ADD_HOST", TESTBED_ADD_HOST),
    ("TESTBED_ADD_HOST_SUCCESS", TESTBED_ADD_HOST_SUCCESS),
    ("TESTBED_LINK_CONTROLLERS", TESTBED_LINK_CONTROLLERS),
    ("TESTBED_CREATE_PEER", TESTBED_CREATE_PEER),
    ("TESTBED_RECONFIGURE_PEER", TESTBED_RECONFIGURE_PEER),
    ("TESTBED_START_PEER", TESTBED_START_PEER),
    ("TESTBED_STOP_PEER", TESTBED_STOP_PEER),
    ("TESTBED_DESTROY_PEER", TESTBED_DESTROY_PEER),
    (
        "TESTBED_CONFIGURE_UNDERLAY_LINK",
        TESTBED_CONFIGURE_UNDERLAY_LINK,
    ),
    ("TESTBED_OVERLAY_CONNECT", TESTBED_OVERLAY_CONNECT),
    ("TESTBED_PEER_EVENT", TESTBED_PEER_EVENT),
    ("TESTBED_PEER_CONNECT_EVENT", TESTBED_PEER_CONNECT_EVENT),
    ("TESTBED_OPERATION_FAIL_EVENT", TESTBED_OPERATION_FAIL_EVENT),
    ("TESTBED_CREATE_PEER_SUCCESS", TESTBED_CREATE_PEER_SUCCESS),
    (
        "TESTBED_GENERIC_OPERATION_SUCCESS",
        TESTBED_GENERIC_OPERATION_SUCCESS,
    ),
    ("TESTBED_GET_PEER_INFORMATION", TESTBED_GET_PEER_INFORMATION),
    ("TESTBED_PEER_INFORMATION", TESTBED_PEER_INFORMATION),
    (
        "TESTBED_REMOTE_OVERLAY_CONNECT",
        TESTBED_REMOTE_OVERLAY_CONNECT,
    ),
    (
        "TESTBED_GET_SLAVE_CONFIGURATION",
        TESTBED_GET_SLAVE_CONFIGURATION,
    ),
    ("TESTBED_SLAVE_CONFIGURATION", TESTBED_SLAVE_CONFIGURATION),
    (
        "TESTBED_LINK_CONTROLLERS_RESULT",
        TESTBED_LINK_CONTROLLERS_RESULT,
    ),
    ("TESTBED_SHUTDOWN_PEERS", TESTBED_SHUTDOWN_PEERS),
    ("TESTBED_MANAGE_PEER_SERVICE", TESTBED_MANAGE_PEER_SERVICE),
    ("TESTBED_BARRIER_INIT", TESTBED_BARRIER_INIT),
    ("TESTBED_BARRIER_CANCEL", TESTBED_BARRIER_CANCEL),
    ("TESTBED_BARRIER_STATUS", TESTBED_BARRIER_STATUS),
    ("TESTBED_BARRIER_WAIT", TESTBED_BARRIER_WAIT),
    ("TESTBED_MAX", TESTBED_MAX),
    ("TESTBED_HELPER_INIT", TESTBED_HELPER_INIT),
    ("TESTBED_HELPER_REPLY", TESTBED_HELPER_REPLY),
    ("GNS_LOOKUP", GNS_LOOKUP),
    ("GNS_LOOKUP_RESULT", GNS_LOOKUP_RESULT),
    ("GNS_REVERSE_LOOKUP", GNS_REVERSE_LOOKUP),
    ("GNS_REVERSE_LOOKUP_RESULT", GNS_REVERSE_LOOKUP_RESULT),
    ("CONSENSUS_CLIENT_JOIN", CONSENSUS_CLIENT_JOIN),
    ("CONSENSUS_CLIENT_INSERT", CONSENSUS_CLIENT_INSERT),
    ("CONSENSUS_CLIENT_BEGIN", CONSENSUS_CLIENT_BEGIN),
    (
        "CONSENSUS_CLIENT_RECEIVED_ELEMENT",
        CONSENSUS_CLIENT_RECEIVED_ELEMENT,
    ),
    ("CONSENSUS_CLIENT_CONCLUDE", CONSENSUS_CLIENT_CONCLUDE),
    (
        "CONSENSUS_CLIENT_CONCLUDE_DONE",
        CONSENSUS_CLIENT_CONCLUDE_DONE,
    ),
    ("CONSENSUS_CLIENT_ACK", CONSENSUS_CLIENT_ACK),
    ("CONSENSUS_P2P_DELTA_ESTIMATE", CONSENSUS_P2P_DELTA_ESTIMATE),
    (
        "CONSENSUS_P2P_DIFFERENCE_DIGEST",
        CONSENSUS_P2P_DIFFERENCE_DIGEST,
    ),
    ("CONSENSUS_P2P_ELEMENTS", CONSENSUS_P2P_ELEMENTS),
    (
        "CONSENSUS_P2P_ELEMENTS_REQUEST",
        CONSENSUS_P2P_ELEMENTS_REQUEST,
    ),
    (
        "CONSENSUS_P2P_ELEMENTS_REPORT",
        CONSENSUS_P2P_ELEMENTS_REPORT,
    ),
    ("CONSENSUS_P2P_ROUND_CONTEXT", CONSENSUS_P2P_ROUND_CONTEXT),
    ("SETU_CANCEL", SETU_CANCEL),
    ("SETU_ADD", SETU_ADD),
    ("SETU_CREATE", SETU_CREATE),
    ("SETU_RESULT", SETU_RESULT),
    ("SETU_EVALUATE", SETU_EVALUATE),
    ("SETU_LISTEN", SETU_LISTEN),
    ("SETU_REJECT", SETU_REJECT),
    ("SETU_ACCEPT", SETU_ACCEPT),
    ("SETU_REQUEST", SETU_REQUEST),
    ("SETU_P2P_REQUEST_FULL", SETU_P2P_REQUEST_FULL),
    ("SETU_P2P_DEMAND", SETU_P2P_DEMAND),
    ("SETU_P2P_INQUIRY", SETU_P2P_INQUIRY),
    ("SETU_P2P_OFFER", SETU_P2P_OFFER),
    ("SETU_P2P_OPERATION_REQUEST", SETU_P2P_OPERATION_REQUEST),
    ("SETU_P2P_SE", SETU_P2P_SE),
    ("SETU_P2P_IBF", SETU_P2P_IBF),
    ("SETU_P2P_ELEMENTS", SETU_P2P_ELEMENTS),
    ("SETU_P2P_DONE", SETU_P2P_DONE),
    ("SETU_P2P_SEC", SETU_P2P_SEC),
    ("SETU_P2P_FULL_DONE", SETU_P2P_FULL_DONE),
    ("SETU_P2P_FULL_ELEMENT", SETU_P2P_FULL_ELEMENT),
    ("SETU_P2P_OVER", SETU_P2P_OVER),
    ("SETU_P2P_SEND_FULL", SETU_P2P_SEND_FULL),
    ("SETI_CANCEL", SETI_CANCEL),
    ("SETI_ADD", SETI_ADD),
    ("SETI_CREATE", SETI_CREATE),
    ("SETI_RESULT", SETI_RESULT),
    ("SETI_EVALUATE", SETI_EVALUATE),
    ("SETI_LISTEN", SETI_LISTEN),
    ("SETI_REJECT", SETI_REJECT),
    ("SETI_ACCEPT", SETI_ACCEPT),
    ("SETI_REQUEST", SETI_REQUEST),
    ("SETI_P2P_ELEMENT_INFO", SETI_P2P_ELEMENT_INFO),
    ("SETI_P2P_BF", SETI_P2P_BF),
    ("SETI_P2P_DONE", SETI_P2P_DONE),
    ("SETI_P2P_OPERATION_REQUEST", SETI_P2P_OPERATION_REQUEST),
    ("SET_UNION_P2P_REQUEST_FULL", SET_UNION_P2P_REQUEST_FULL),
    ("SET_UNION_P2P_DEMAND", SET_UNION_P2P_DEMAND),
    ("SET_UNION_P2P_INQUIRY", SET_UNION_P2P_INQUIRY),
    ("SET_UNION_P2P_OFFER", SET_UNION_P2P_OFFER),
    ("SET_REJECT", SET_REJECT),
    ("SET_CANCEL", SET_CANCEL),
    ("SET_ITER_ACK", SET_ITER_ACK),
    ("SET_RESULT", SET_RESULT),
    ("SET_ADD", SET_ADD),
    ("SET_REMOVE", SET_REMOVE),
    ("SET_LISTEN", SET_LISTEN),
    ("SET_ACCEPT", SET_ACCEPT),
    ("SET_EVALUATE", SET_EVALUATE),
    ("SET_CONCLUDE", SET_CONCLUDE),
    ("SET_REQUEST", SET_REQUEST),
    ("SET_CREATE", SET_CREATE),
    ("SET_P2P_OPERATION_REQUEST", SET_P2P_OPERATION_REQUEST),
    ("SET_UNION_P2P_SE", SET_UNION_P2P_SE),
    ("SET_UNION_P2P_IBF", SET_UNION_P2P_IBF),
    ("SET_P2P_ELEMENTS", SET_P2P_ELEMENTS),
    ("SET_UNION_P2P_DONE", SET_UNION_P2P_DONE),
    ("SET_ITER_REQUEST", SET_ITER_REQUEST),
    ("SET_ITER_ELEMENT", SET_ITER_ELEMENT),
    ("SET_ITER_DONE", SET_ITER_DONE),
    ("SET_UNION_P2P_SEC", SET_UNION_P2P_SEC),
    (
        "SET_INTERSECTION_P2P_ELEMENT_INFO",
        SET_INTERSECTION_P2P_ELEMENT_INFO,
    ),
    ("SET_INTERSECTION_P2P_BF", SET_INTERSECTION_P2P_BF),
    ("SET_INTERSECTION_P2P_DONE", SET_INTERSECTION_P2P_DONE),
    ("SET_COPY_LAZY_PREPARE", SET_COPY_LAZY_PREPARE),
    ("SET_COPY_LAZY_RESPONSE", SET_COPY_LAZY_RESPONSE),
    ("SET_COPY_LAZY_CONNECT", SET_COPY_LAZY_CONNECT),
    ("SET_UNION_P2P_FULL_DONE", SET_UNION_P2P_FULL_DONE),
    ("SET_UNION_P2P_FULL_ELEMENT", SET_UNION_P2P_FULL_ELEMENT),
    ("SET_UNION_P2P_OVER", SET_UNION_P2P_OVER),
    ("TESTBED_LOGGER_MSG", TESTBED_LOGGER_MSG),
    ("TESTBED_LOGGER_ACK", TESTBED_LOGGER_ACK),
    ("REGEX_ANNOUNCE", REGEX_ANNOUNCE),
    ("REGEX_SEARCH", REGEX_SEARCH),
    ("REGEX_RESULT", REGEX_RESULT),
    ("IDENTITY_START", IDENTITY_START),
    ("IDENTITY_RESULT_CODE", IDENTITY_RESULT_CODE),
    ("IDENTITY_UPDATE", IDENTITY_UPDATE),
    ("IDENTITY_CREATE", IDENTITY_CREATE),
    ("IDENTITY_RENAME", IDENTITY_RENAME),
    ("IDENTITY_DELETE", IDENTITY_DELETE),
    ("IDENTITY_LOOKUP", IDENTITY_LOOKUP),
    ("IDENTITY_LOOKUP_BY_SUFFIX", IDENTITY_LOOKUP_BY_SUFFIX),
    ("REVOCATION_QUERY", REVOCATION_QUERY),
    ("REVOCATION_QUERY_RESPONSE", REVOCATION_QUERY_RESPONSE),
    ("REVOCATION_REVOKE", REVOCATION_REVOKE),
    ("REVOCATION_REVOKE_RESPONSE", REVOCATION_REVOKE_RESPONSE),
    (
        "SCALARPRODUCT_CLIENT_TO_ALICE",
        SCALARPRODUCT_CLIENT_TO_ALICE,
    ),
    ("SCALARPRODUCT_CLIENT_TO_BOB", SCALARPRODUCT_CLIENT_TO_BOB),
    (
        "SCALARPRODUCT_CLIENT_MULTIPART_ALICE",
        SCALARPRODUCT_CLIENT_MULTIPART_ALICE,
    ),
    (
        "SCALARPRODUCT_CLIENT_MULTIPART_BOB",
        SCALARPRODUCT_CLIENT_MULTIPART_BOB,
    ),
    (
        "SCALARPRODUCT_SESSION_INITIALIZATION",
        SCALARPRODUCT_SESSION_INITIALIZATION,
    ),
    (
        "SCALARPRODUCT_ALICE_CRYPTODATA",
        SCALARPRODUCT_ALICE_CRYPTODATA,
    ),
    ("SCALARPRODUCT_BOB_CRYPTODATA", SCALARPRODUCT_BOB_CRYPTODATA),
    (
        "SCALARPRODUCT_BOB_CRYPTODATA_MULTIPART",
        SCALARPRODUCT_BOB_CRYPTODATA_MULTIPART,
    ),
    ("SCALARPRODUCT_RESULT", SCALARPRODUCT_RESULT),
    (
        "SCALARPRODUCT_ECC_SESSION_INITIALIZATION",
        SCALARPRODUCT_ECC_SESSION_INITIALIZATION,
    ),
    (
        "SCALARPRODUCT_ECC_ALICE_CRYPTODATA",
        SCALARPRODUCT_ECC_ALICE_CRYPTODATA,
    ),
    (
        "SCALARPRODUCT_ECC_BOB_CRYPTODATA",
        SCALARPRODUCT_ECC_BOB_CRYPTODATA,
    ),
    ("PSYCSTORE_MEMBERSHIP_STORE", PSYCSTORE_MEMBERSHIP_STORE),
    ("PSYCSTORE_MEMBERSHIP_TEST", PSYCSTORE_MEMBERSHIP_TEST),
    ("PSYCSTORE_FRAGMENT_STORE", PSYCSTORE_FRAGMENT_STORE),
    ("PSYCSTORE_FRAGMENT_GET", PSYCSTORE_FRAGMENT_GET),
    ("PSYCSTORE_MESSAGE_GET", PSYCSTORE_MESSAGE_GET),
    (
        "PSYCSTORE_MESSAGE_GET_FRAGMENT",
        PSYCSTORE_MESSAGE_GET_FRAGMENT,
    ),
    ("PSYCSTORE_COUNTERS_GET", PSYCSTORE_COUNTERS_GET),
    ("PSYCSTORE_STATE_MODIFY", PSYCSTORE_STATE_MODIFY),
    ("PSYCSTORE_STATE_SYNC", PSYCSTORE_STATE_SYNC),
    ("PSYCSTORE_STATE_RESET", PSYCSTORE_STATE_RESET),
    ("PSYCSTORE_STATE_HASH_UPDATE", PSYCSTORE_STATE_HASH_UPDATE),
    ("PSYCSTORE_STATE_GET", PSYCSTORE_STATE_GET),
    ("PSYCSTORE_STATE_GET_PREFIX", PSYCSTORE_STATE_GET_PREFIX),
    ("PSYCSTORE_RESULT_CODE", PSYCSTORE_RESULT_CODE),
    ("PSYCSTORE_RESULT_FRAGMENT", PSYCSTORE_RESULT_FRAGMENT),
    ("PSYCSTORE_RESULT_COUNTERS", PSYCSTORE_RESULT_COUNTERS),
    ("PSYCSTORE_RESULT_STATE", PSYCSTORE_RESULT_STATE),
    ("PSYC_RESULT_CODE", PSYC_RESULT_CODE),
    ("PSYC_MASTER_START", PSYC_MASTER_START),
    ("PSYC_MASTER_START_ACK", PSYC_MASTER_START_ACK),
    ("PSYC_SLAVE_JOIN", PSYC_SLAVE_JOIN),
    ("PSYC_SLAVE_JOIN_ACK", PSYC_SLAVE_JOIN_ACK),
    ("PSYC_PART_REQUEST", PSYC_PART_REQUEST),
    ("PSYC_PART_ACK", PSYC_PART_ACK),
    ("PSYC_JOIN_REQUEST", PSYC_JOIN_REQUEST),
    ("PSYC_JOIN_DECISION", PSYC_JOIN_DECISION),
    (
        "PSYC_CHANNEL_MEMBERSHIP_STORE",
        PSYC_CHANNEL_MEMBERSHIP_STORE,
    ),
    ("PSYC_MESSAGE", PSYC_MESSAGE),
    ("PSYC_MESSAGE_HEADER", PSYC_MESSAGE_HEADER),
    ("PSYC_MESSAGE_METHOD", PSYC_MESSAGE_METHOD),
    ("PSYC_MESSAGE_MODIFIER", PSYC_MESSAGE_MODIFIER),
    ("PSYC_MESSAGE_MOD_CONT", PSYC_MESSAGE_MOD_CONT),
    ("PSYC_MESSAGE_DATA", PSYC_MESSAGE_DATA),
    ("PSYC_MESSAGE_END", PSYC_MESSAGE_END),
    ("PSYC_MESSAGE_CANCEL", PSYC_MESSAGE_CANCEL),
    ("PSYC_MESSAGE_ACK", PSYC_MESSAGE_ACK),
    ("PSYC_HISTORY_REPLAY", PSYC_HISTORY_REPLAY),
    ("PSYC_HISTORY_RESULT", PSYC_HISTORY_RESULT),
    ("PSYC_STATE_GET", PSYC_STATE_GET),
    ("PSYC_STATE_GET_PREFIX", PSYC_STATE_GET_PREFIX),
    ("PSYC_STATE_RESULT", PSYC_STATE_RESULT),
    ("CONVERSATION_AUDIO", CONVERSATION_AUDIO),
    (
        "CONVERSATION_CS_PHONE_REGISTER",
        CONVERSATION_CS_PHONE_REGISTER,
    ),
    (
        "CONVERSATION_CS_PHONE_PICK_UP",
        CONVERSATION_CS_PHONE_PICK_UP,
    ),
    (
        "CONVERSATION_CS_PHONE_HANG_UP",
        CONVERSATION_CS_PHONE_HANG_UP,
    ),
    ("CONVERSATION_CS_PHONE_CALL", CONVERSATION_CS_PHONE_CALL),
    ("CONVERSATION_CS_PHONE_RING", CONVERSATION_CS_PHONE_RING),
    (
        "CONVERSATION_CS_PHONE_SUSPEND",
        CONVERSATION_CS_PHONE_SUSPEND,
    ),
    ("CONVERSATION_CS_PHONE_RESUME", CONVERSATION_CS_PHONE_RESUME),
    (
        "CONVERSATION_CS_PHONE_PICKED_UP",
        CONVERSATION_CS_PHONE_PICKED_UP,
    ),
    ("CONVERSATION_CS_AUDIO", CONVERSATION_CS_AUDIO),
    (
        "CONVERSATION_CADET_PHONE_RING",
        CONVERSATION_CADET_PHONE_RING,
    ),
    (
        "CONVERSATION_CADET_PHONE_HANG_UP",
        CONVERSATION_CADET_PHONE_HANG_UP,
    ),
    (
        "CONVERSATION_CADET_PHONE_PICK_UP",
        CONVERSATION_CADET_PHONE_PICK_UP,
    ),
    (
        "CONVERSATION_CADET_PHONE_SUSPEND",
        CONVERSATION_CADET_PHONE_SUSPEND,
    ),
    (
        "CONVERSATION_CADET_PHONE_RESUME",
        CONVERSATION_CADET_PHONE_RESUME,
    ),
    ("CONVERSATION_CADET_AUDIO", CONVERSATION_CADET_AUDIO),
    ("MULTICAST_ORIGIN_START", MULTICAST_ORIGIN_START),
    ("MULTICAST_MEMBER_JOIN", MULTICAST_MEMBER_JOIN),
    ("MULTICAST_JOIN_REQUEST", MULTICAST_JOIN_REQUEST),
    ("MULTICAST_JOIN_DECISION", MULTICAST_JOIN_DECISION),
    ("MULTICAST_PART_REQUEST", MULTICAST_PART_REQUEST),
    ("MULTICAST_PART_ACK", MULTICAST_PART_ACK),
    ("MULTICAST_GROUP_END", MULTICAST_GROUP_END),
    ("MULTICAST_MESSAGE", MULTICAST_MESSAGE),
    ("MULTICAST_REQUEST", MULTICAST_REQUEST),
    ("MULTICAST_FRAGMENT_ACK", MULTICAST_FRAGMENT_ACK),
    ("MULTICAST_REPLAY_REQUEST", MULTICAST_REPLAY_REQUEST),
    ("MULTICAST_REPLAY_RESPONSE", MULTICAST_REPLAY_RESPONSE),
    (
        "MULTICAST_REPLAY_RESPONSE_END",
        MULTICAST_REPLAY_RESPONSE_END,
    ),
    (
        "SECRETSHARING_CLIENT_GENERATE",
        SECRETSHARING_CLIENT_GENERATE,
    ),
    ("SECRETSHARING_CLIENT_DECRYPT", SECRETSHARING_CLIENT_DECRYPT),
    (
        "SECRETSHARING_CLIENT_DECRYPT_DONE",
        SECRETSHARING_CLIENT_DECRYPT_DONE,
    ),
    (
        "SECRETSHARING_CLIENT_SECRET_READY",
        SECRETSHARING_CLIENT_SECRET_READY,
    ),
    ("PEERSTORE_STORE", PEERSTORE_STORE),
    ("PEERSTORE_ITERATE_START", PEERSTORE_ITERATE_START),
    ("PEERSTORE_RECORD", PEERSTORE_RECORD),
    ("PEERSTORE_ITERATE_END", PEERSTORE_ITERATE_END),
    ("PEERSTORE_MONITOR_START", PEERSTORE_MONITOR_START),
    ("PEERSTORE_MONITOR_SYNC", PEERSTORE_MONITOR_SYNC),
    ("PEERSTORE_MONITOR_NEXT", PEERSTORE_MONITOR_NEXT),
    ("PEERSTORE_STORE_RESULT", PEERSTORE_STORE_RESULT),
    ("PEERSTORE_ITERATE_NEXT", PEERSTORE_ITERATE_NEXT),
    ("PEERSTORE_ITERATE_STOP", PEERSTORE_ITERATE_STOP),
    ("SOCIAL_RESULT_CODE", SOCIAL_RESULT_CODE),
    ("SOCIAL_HOST_ENTER", SOCIAL_HOST_ENTER),
    ("SOCIAL_HOST_ENTER_ACK", SOCIAL_HOST_ENTER_ACK),
    ("SOCIAL_GUEST_ENTER", SOCIAL_GUEST_ENTER),
    ("SOCIAL_GUEST_ENTER_BY_NAME", SOCIAL_GUEST_ENTER_BY_NAME),
    ("SOCIAL_GUEST_ENTER_ACK", SOCIAL_GUEST_ENTER_ACK),
    ("SOCIAL_ENTRY_REQUEST", SOCIAL_ENTRY_REQUEST),
    ("SOCIAL_ENTRY_DECISION", SOCIAL_ENTRY_DECISION),
    ("SOCIAL_PLACE_LEAVE", SOCIAL_PLACE_LEAVE),
    ("SOCIAL_PLACE_LEAVE_ACK", SOCIAL_PLACE_LEAVE_ACK),
    ("SOCIAL_ZONE_ADD_PLACE", SOCIAL_ZONE_ADD_PLACE),
    ("SOCIAL_ZONE_ADD_NYM", SOCIAL_ZONE_ADD_NYM),
    ("SOCIAL_APP_CONNECT", SOCIAL_APP_CONNECT),
    ("SOCIAL_APP_DETACH", SOCIAL_APP_DETACH),
    ("SOCIAL_APP_EGO", SOCIAL_APP_EGO),
    ("SOCIAL_APP_EGO_END", SOCIAL_APP_EGO_END),
    ("SOCIAL_APP_PLACE", SOCIAL_APP_PLACE),
    ("SOCIAL_APP_PLACE_END", SOCIAL_APP_PLACE_END),
    ("SOCIAL_MSG_PROC_SET", SOCIAL_MSG_PROC_SET),
    ("SOCIAL_MSG_PROC_CLEAR", SOCIAL_MSG_PROC_CLEAR),
    ("XDHT_P2P_TRAIL_SETUP", XDHT_P2P_TRAIL_SETUP),
    ("XDHT_P2P_TRAIL_SETUP_RESULT", XDHT_P2P_TRAIL_SETUP_RESULT),
    ("XDHT_P2P_VERIFY_SUCCESSOR", XDHT_P2P_VERIFY_SUCCESSOR),
    (
        "XDHT_P2P_NOTIFY_NEW_SUCCESSOR",
        XDHT_P2P_NOTIFY_NEW_SUCCESSOR,
    ),
    (
        "XDHT_P2P_VERIFY_SUCCESSOR_RESULT",
        XDHT_P2P_VERIFY_SUCCESSOR_RESULT,
    ),
    ("XDHT_P2P_GET_RESULT", XDHT_P2P_GET_RESULT),
    (
        "XDHT_P2P_TRAIL_SETUP_REJECTION",
        XDHT_P2P_TRAIL_SETUP_REJECTION,
    ),
    ("XDHT_P2P_TRAIL_TEARDOWN", XDHT_P2P_TRAIL_TEARDOWN),
    ("XDHT_P2P_ADD_TRAIL", XDHT_P2P_ADD_TRAIL),
    ("XDHT_P2P_PUT", XDHT_P2P_PUT),
    ("XDHT_P2P_GET", XDHT_P2P_GET),
    (
        "XDHT_P2P_NOTIFY_SUCCESSOR_CONFIRMATION",
        XDHT_P2P_NOTIFY_SUCCESSOR_CONFIRMATION,
    ),
    ("WDHT_RANDOM_WALK", WDHT_RANDOM_WALK),
    ("WDHT_RANDOM_WALK_RESPONSE", WDHT_RANDOM_WALK_RESPONSE),
    ("WDHT_TRAIL_DESTROY", WDHT_TRAIL_DESTROY),
    ("WDHT_TRAIL_ROUTE", WDHT_TRAIL_ROUTE),
    ("WDHT_SUCCESSOR_FIND", WDHT_SUCCESSOR_FIND),
    ("WDHT_GET", WDHT_GET),
    ("WDHT_PUT", WDHT_PUT),
    ("WDHT_GET_RESULT", WDHT_GET_RESULT),
    ("RPS_PP_CHECK_LIVE", RPS_PP_CHECK_LIVE),
    ("RPS_PP_PUSH", RPS_PP_PUSH),
    ("RPS_PP_PULL_REQUEST", RPS_PP_PULL_REQUEST),
    ("RPS_PP_PULL_REPLY", RPS_PP_PULL_REPLY),
    ("RPS_CS_SEED", RPS_CS_SEED),
    ("RPS_ACT_MALICIOUS", RPS_ACT_MALICIOUS),
    ("RPS_CS_SUB_START", RPS_CS_SUB_START),
    ("RPS_CS_SUB_STOP", RPS_CS_SUB_STOP),
    ("RECLAIM_ATTRIBUTE_STORE", RECLAIM_ATTRIBUTE_STORE),
    ("RECLAIM_SUCCESS_RESPONSE", RECLAIM_SUCCESS_RESPONSE),
    (
        "RECLAIM_ATTRIBUTE_ITERATION_START",
        RECLAIM_ATTRIBUTE_ITERATION_START,
    ),
    (
        "RECLAIM_ATTRIBUTE_ITERATION_STOP",
        RECLAIM_ATTRIBUTE_ITERATION_STOP,
    ),
    (
        "RECLAIM_ATTRIBUTE_ITERATION_NEXT",
        RECLAIM_ATTRIBUTE_ITERATION_NEXT,
    ),
    ("RECLAIM_ATTRIBUTE_RESULT", RECLAIM_ATTRIBUTE_RESULT),
    ("RECLAIM_ISSUE_TICKET", RECLAIM_ISSUE_TICKET),
    ("RECLAIM_TICKET_RESULT", RECLAIM_TICKET_RESULT),
    ("RECLAIM_REVOKE_TICKET", RECLAIM_REVOKE_TICKET),
    ("RECLAIM_REVOKE_TICKET_RESULT", RECLAIM_REVOKE_TICKET_RESULT),
    ("RECLAIM_CONSUME_TICKET", RECLAIM_CONSUME_TICKET),
    (
        "RECLAIM_CONSUME_TICKET_RESULT",
        RECLAIM_CONSUME_TICKET_RESULT,
    ),
    (
        "RECLAIM_TICKET_ITERATION_START",
        RECLAIM_TICKET_ITERATION_START,
    ),
    (
        "RECLAIM_TICKET_ITERATION_STOP",
        RECLAIM_TICKET_ITERATION_STOP,
    ),
    (
        "RECLAIM_TICKET_ITERATION_NEXT",
        RECLAIM_TICKET_ITERATION_NEXT,
    ),
    ("RECLAIM_ATTRIBUTE_DELETE", RECLAIM_ATTRIBUTE_DELETE),
    ("RECLAIM_CREDENTIAL_STORE", RECLAIM_CREDENTIAL_STORE),
    ("RECLAIM_CREDENTIAL_DELETE", RECLAIM_CREDENTIAL_DELETE),
    ("RECLAIM_CREDENTIAL_RESULT", RECLAIM_CREDENTIAL_RESULT),
    (
        "RECLAIM_CREDENTIAL_ITERATION_START",
        RECLAIM_CREDENTIAL_ITERATION_START,
    ),
    (
        "RECLAIM_CREDENTIAL_ITERATION_STOP",
        RECLAIM_CREDENTIAL_ITERATION_STOP,
    ),
    (
        "RECLAIM_CREDENTIAL_ITERATION_NEXT",
        RECLAIM_CREDENTIAL_ITERATION_NEXT,
    ),
    ("ABD_VERIFY", ABD_VERIFY),
    ("ABD_VERIFY_RESULT", ABD_VERIFY_RESULT),
    ("ABD_COLLECT", ABD_COLLECT),
    ("ABD_COLLECT_RESULT", ABD_COLLECT_RESULT),
    ("ABD_INTERMEDIATE_RESULT", ABD_INTERMEDIATE_RESULT),
    ("CADET_CONNECTION_CREATE", CADET_CONNECTION_CREATE),
    ("CADET_CONNECTION_CREATE_ACK", CADET_CONNECTION_CREATE_ACK),
    ("CADET_CONNECTION_BROKEN", CADET_CONNECTION_BROKEN),
    ("CADET_CONNECTION_DESTROY", CADET_CONNECTION_DESTROY),
    (
        "CADET_CONNECTION_PATH_CHANGED_UNIMPLEMENTED",
        CADET_CONNECTION_PATH_CHANGED_UNIMPLEMENTED,
    ),
    (
        "CADET_CONNECTION_HOP_BY_HOP_ENCRYPTED_ACK",
        CADET_CONNECTION_HOP_BY_HOP_ENCRYPTED_ACK,
    ),
    ("CADET_TUNNEL_ENCRYPTED_POLL", CADET_TUNNEL_ENCRYPTED_POLL),
    ("CADET_TUNNEL_KX", CADET_TUNNEL_KX),
    ("CADET_TUNNEL_ENCRYPTED", CADET_TUNNEL_ENCRYPTED),
    ("CADET_TUNNEL_KX_AUTH", CADET_TUNNEL_KX_AUTH),
    ("CADET_CHANNEL_APP_DATA", CADET_CHANNEL_APP_DATA),
    ("CADET_CHANNEL_APP_DATA_ACK", CADET_CHANNEL_APP_DATA_ACK),
    ("CADET_CHANNEL_KEEPALIVE", CADET_CHANNEL_KEEPALIVE),
    ("CADET_CHANNEL_OPEN", CADET_CHANNEL_OPEN),
    ("CADET_CHANNEL_DESTROY", CADET_CHANNEL_DESTROY),
    ("CADET_CHANNEL_OPEN_ACK", CADET_CHANNEL_OPEN_ACK),
    (
        "CADET_CHANNEL_OPEN_NACK_DEPRECATED",
        CADET_CHANNEL_OPEN_NACK_DEPRECATED,
    ),
    ("CADET_LOCAL_DATA", CADET_LOCAL_DATA),
    ("CADET_LOCAL_ACK", CADET_LOCAL_ACK),
    ("CADET_LOCAL_PORT_OPEN", CADET_LOCAL_PORT_OPEN),
    ("CADET_LOCAL_PORT_CLOSE", CADET_LOCAL_PORT_CLOSE),
    ("CADET_LOCAL_CHANNEL_CREATE", CADET_LOCAL_CHANNEL_CREATE),
    ("CADET_LOCAL_CHANNEL_DESTROY", CADET_LOCAL_CHANNEL_DESTROY),
    (
        "CADET_LOCAL_REQUEST_INFO_CHANNEL",
        CADET_LOCAL_REQUEST_INFO_CHANNEL,
    ),
    ("CADET_LOCAL_INFO_CHANNEL", CADET_LOCAL_INFO_CHANNEL),
    ("CADET_LOCAL_INFO_CHANNEL_END", CADET_LOCAL_INFO_CHANNEL_END),
    (
        "CADET_LOCAL_REQUEST_INFO_PEERS",
        CADET_LOCAL_REQUEST_INFO_PEERS,
    ),
    ("CADET_LOCAL_INFO_PEERS", CADET_LOCAL_INFO_PEERS),
    ("CADET_LOCAL_INFO_PEERS_END", CADET_LOCAL_INFO_PEERS_END),
    (
        "CADET_LOCAL_REQUEST_INFO_PATH",
        CADET_LOCAL_REQUEST_INFO_PATH,
    ),
    ("CADET_LOCAL_INFO_PATH", CADET_LOCAL_INFO_PATH),
    ("CADET_LOCAL_INFO_PATH_END", CADET_LOCAL_INFO_PATH_END),
    (
        "CADET_LOCAL_REQUEST_INFO_TUNNELS",
        CADET_LOCAL_REQUEST_INFO_TUNNELS,
    ),
    ("CADET_LOCAL_INFO_TUNNELS", CADET_LOCAL_INFO_TUNNELS),
    ("CADET_LOCAL_INFO_TUNNELS_END", CADET_LOCAL_INFO_TUNNELS_END),
    ("CADET_DROP_CADET_MESSAGE", CADET_DROP_CADET_MESSAGE),
    ("CADET_CLI", CADET_CLI),
    ("NAT_REGISTER", NAT_REGISTER),
    ("NAT_HANDLE_STUN", NAT_HANDLE_STUN),
    (
        "NAT_REQUEST_CONNECTION_REVERSAL",
        NAT_REQUEST_CONNECTION_REVERSAL,
    ),
    (
        "NAT_CONNECTION_REVERSAL_REQUESTED",
        NAT_CONNECTION_REVERSAL_REQUESTED,
    ),
    ("NAT_ADDRESS_CHANGE", NAT_ADDRESS_CHANGE),
    ("NAT_ADD_GLOBAL_ADDRESS", NAT_ADD_GLOBAL_ADDRESS),
    ("NAT_AUTO_REQUEST_CFG", NAT_AUTO_REQUEST_CFG),
    ("NAT_AUTO_CFG_RESULT", NAT_AUTO_CFG_RESULT),
    ("AUCTION_CLIENT_CREATE", AUCTION_CLIENT_CREATE),
    ("AUCTION_CLIENT_JOIN", AUCTION_CLIENT_JOIN),
    ("AUCTION_CLIENT_OUTCOME", AUCTION_CLIENT_OUTCOME),
    ("RPS_CS_DEBUG_VIEW_REQUEST", RPS_CS_DEBUG_VIEW_REQUEST),
    ("RPS_CS_DEBUG_VIEW_REPLY", RPS_CS_DEBUG_VIEW_REPLY),
    ("RPS_CS_DEBUG_VIEW_CANCEL", RPS_CS_DEBUG_VIEW_CANCEL),
    ("RPS_CS_DEBUG_STREAM_REQUEST", RPS_CS_DEBUG_STREAM_REQUEST),
    ("RPS_CS_DEBUG_STREAM_REPLY", RPS_CS_DEBUG_STREAM_REPLY),
    ("RPS_CS_DEBUG_STREAM_CANCEL", RPS_CS_DEBUG_STREAM_CANCEL),
    ("TRANSPORT_ADD_ADDRESS", TRANSPORT_ADD_ADDRESS),
    ("TRANSPORT_DEL_ADDRESS", TRANSPORT_DEL_ADDRESS),
    ("TRANSPORT_INCOMING_MSG", TRANSPORT_INCOMING_MSG),
    ("TRANSPORT_INCOMING_MSG_ACK", TRANSPORT_INCOMING_MSG_ACK),
    ("TRANSPORT_QUEUE_SETUP", TRANSPORT_QUEUE_SETUP),
    ("TRANSPORT_QUEUE_TEARDOWN", TRANSPORT_QUEUE_TEARDOWN),
    ("TRANSPORT_QUEUE_CREATE", TRANSPORT_QUEUE_CREATE),
    ("TRANSPORT_QUEUE_CREATE_OK", TRANSPORT_QUEUE_CREATE_OK),
    ("TRANSPORT_QUEUE_CREATE_FAIL", TRANSPORT_QUEUE_CREATE_FAIL),
    ("TRANSPORT_SEND_MSG", TRANSPORT_SEND_MSG),
    ("TRANSPORT_SEND_MSG_ACK", TRANSPORT_SEND_MSG_ACK),
    ("TRANSPORT_NEW_COMMUNICATOR", TRANSPORT_NEW_COMMUNICATOR),
    (
        "TRANSPORT_COMMUNICATOR_BACKCHANNEL",
        TRANSPORT_COMMUNICATOR_BACKCHANNEL,
    ),
    (
        "TRANSPORT_BACKCHANNEL_ENCAPSULATION",
        TRANSPORT_BACKCHANNEL_ENCAPSULATION,
    ),
    ("TRANSPORT_FRAGMENT", TRANSPORT_FRAGMENT),
    ("TRANSPORT_RELIABILITY_BOX", TRANSPORT_RELIABILITY_BOX),
    ("TRANSPORT_RELIABILITY_ACK", TRANSPORT_RELIABILITY_ACK),
    ("TRANSPORT_DV_LEARN", TRANSPORT_DV_LEARN),
    ("TRANSPORT_DV_BOX", TRANSPORT_DV_BOX),
    (
        "TRANSPORT_COMMUNICATOR_BACKCHANNEL_INCOMING",
        TRANSPORT_COMMUNICATOR_BACKCHANNEL_INCOMING,
    ),
    ("TRANSPORT_FLOW_CONTROL", TRANSPORT_FLOW_CONTROL),
    ("TRANSPORT_QUEUE_UPDATE", TRANSPORT_QUEUE_UPDATE),
    ("TRANSPORT_MONITOR_START", TRANSPORT_MONITOR_START),
    ("TRANSPORT_MONITOR_DATA", TRANSPORT_MONITOR_DATA),
    ("TRANSPORT_MONITOR_END", TRANSPORT_MONITOR_END),
    ("TRANSPORT_START_BURST", TRANSPORT_START_BURST),
    ("TRANSPORT_BURST_FINISHED", TRANSPORT_BURST_FINISHED),
    ("TRANSPORT_LINK_LIST_REQUEST", TRANSPORT_LINK_LIST_REQUEST),
    ("TRANSPORT_LINK_LIST_RESPONSE", TRANSPORT_LINK_LIST_RESPONSE),
    (
        "TRANSPORT_LINK_LIST_RESPONSE_END",
        TRANSPORT_LINK_LIST_RESPONSE_END,
    ),
    (
        "TRANSPORT_COMMUNICATOR_KX_CONFIRMATION",
        TRANSPORT_COMMUNICATOR_KX_CONFIRMATION,
    ),
    (
        "TRANSPORT_COMMUNICATOR_FC_LIMITS",
        TRANSPORT_COMMUNICATOR_FC_LIMITS,
    ),
    ("TRANSPORT_SUGGEST", TRANSPORT_SUGGEST),
    ("TRANSPORT_SUGGEST_CANCEL", TRANSPORT_SUGGEST_CANCEL),
    (
        "TRANSPORT_REQUEST_HELLO_VALIDATION",
        TRANSPORT_REQUEST_HELLO_VALIDATION,
    ),
    (
        "TRANSPORT_ADDRESS_VALIDATION_CHALLENGE",
        TRANSPORT_ADDRESS_VALIDATION_CHALLENGE,
    ),
    (
        "TRANSPORT_ADDRESS_VALIDATION_RESPONSE",
        TRANSPORT_ADDRESS_VALIDATION_RESPONSE,
    ),
    ("ATS_SUGGEST", ATS_SUGGEST),
    ("ATS_SUGGEST_CANCEL", ATS_SUGGEST_CANCEL),
    ("ATS_SESSION_ADD", ATS_SESSION_ADD),
    ("ATS_SESSION_ADD_INBOUND_ONLY", ATS_SESSION_ADD_INBOUND_ONLY),
    ("ATS_SESSION_UPDATE", ATS_SESSION_UPDATE),
    ("ATS_SESSION_DEL", ATS_SESSION_DEL),
    ("ATS_SESSION_ALLOCATION", ATS_SESSION_ALLOCATION),
    ("COMMUNICATOR_TCP_REKEY", COMMUNICATOR_TCP_REKEY),
    ("COMMUNICATOR_TCP_BOX", COMMUNICATOR_TCP_BOX),
    ("COMMUNICATOR_TCP_FINISH", COMMUNICATOR_TCP_FINISH),
    (
        "COMMUNICATOR_TCP_CONFIRMATION_ACK",
        COMMUNICATOR_TCP_CONFIRMATION_ACK,
    ),
    ("COMMUNICATOR_UDP_ACK", COMMUNICATOR_UDP_ACK),
    ("COMMUNICATOR_UDP_PAD", COMMUNICATOR_UDP_PAD),
    ("COMMUNICATOR_UDP_REKEY", COMMUNICATOR_UDP_REKEY),
    ("RECLAIM_REFERENCE_DELETE", RECLAIM_REFERENCE_DELETE),
    ("RECLAIM_REFERENCE_RESULT", RECLAIM_REFERENCE_RESULT),
    ("MESSENGER_CONNECTION_CREATE", MESSENGER_CONNECTION_CREATE),
    ("MESSENGER_CONNECTION_DESTROY", MESSENGER_CONNECTION_DESTROY),
    (
        "MESSENGER_CONNECTION_MEMBER_ID",
        MESSENGER_CONNECTION_MEMBER_ID,
    ),
    ("MESSENGER_ROOM_OPEN", MESSENGER_ROOM_OPEN),
    ("MESSENGER_ROOM_ENTRY", MESSENGER_ROOM_ENTRY),
    ("MESSENGER_ROOM_CLOSE", MESSENGER_ROOM_CLOSE),
    ("MESSENGER_ROOM_SEND_MESSAGE", MESSENGER_ROOM_SEND_MESSAGE),
    ("MESSENGER_ROOM_RECV_MESSAGE", MESSENGER_ROOM_RECV_MESSAGE),
    ("MESSENGER_ROOM_GET_MESSAGE", MESSENGER_ROOM_GET_MESSAGE),
    ("MESSENGER_ROOM_SYNC", MESSENGER_ROOM_SYNC),
    ("MESSENGER_ROOM_LINK", MESSENGER_ROOM_LINK),
    ("CMDS_HELPER_INIT", CMDS_HELPER_INIT),
    ("CMDS_HELPER_REPLY", CMDS_HELPER_REPLY),
    ("CMDS_HELPER_PEER_STARTED", CMDS_HELPER_PEER_STARTED),
    (
        "CMDS_HELPER_ALL_PEERS_STARTED",
        CMDS_HELPER_ALL_PEERS_STARTED,
    ),
    (
        "CMDS_HELPER_LOCAL_TEST_PREPARED",
        CMDS_HELPER_LOCAL_TEST_PREPARED,
    ),
    (
        "CMDS_HELPER_ALL_LOCAL_TESTS_PREPARED",
        CMDS_HELPER_ALL_LOCAL_TESTS_PREPARED,
    ),
    ("CMDS_HELPER_LOCAL_FINISHED", CMDS_HELPER_LOCAL_FINISHED),
    ("CMDS_HELPER_BARRIER_REACHED", CMDS_HELPER_BARRIER_REACHED),
    ("CMDS_HELPER_BARRIER_ATTACH", CMDS_HELPER_BARRIER_ATTACH),
    (
        "CMDS_HELPER_BARRIER_CROSSABLE",
        CMDS_HELPER_BARRIER_CROSSABLE,
    ),
    ("CMDS_HELPER_BARRIER_ATTACHED", CMDS_HELPER_BARRIER_ATTACHED),
    ("NAMESTORE_RECORD_SET_EDIT", NAMESTORE_RECORD_SET_EDIT),
    (
        "NAMESTORE_RECORD_SET_EDIT_RESPONSE",
        NAMESTORE_RECORD_SET_EDIT_RESPONSE,
    ),
    (
        "NAMESTORE_RECORD_SET_EDIT_CANCEL",
        NAMESTORE_RECORD_SET_EDIT_CANCEL,
    ),
    ("CORE_PEER_ID", CORE_PEER_ID),
    ("PILS_PEER_ID", PILS_PEER_ID),
    ("PILS_SIGN_REQUEST", PILS_SIGN_REQUEST),
    ("PILS_SIGN_RESULT", PILS_SIGN_RESULT),
    ("PILS_FEED_ADDRESSES", PILS_FEED_ADDRESSES),
    ("PILS_KEM_DECAPS", PILS_KEM_DECAPS),
    ("PILS_DECAPS_RESULT", PILS_DECAPS_RESULT),
    ("PILS_ECDH", PILS_ECDH),
    ("PILS_ECDH_RESULT", PILS_ECDH_RESULT),
    ("NAMECACHE_BLOCK_DELETE", NAMECACHE_BLOCK_DELETE),
    (
        "NAMECACHE_BLOCK_DELETE_RESPONSE",
        NAMECACHE_BLOCK_DELETE_RESPONSE,
    ),
    ("ALL", ALL),
];
