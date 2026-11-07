/* SPDX-License-Identifier: MPL-2.0 */
/*
 * Selected private three-node DV component. This is a caller of unchanged
 * official GNUnet libraries, not a peer, transport implementation or normal
 * installed GNUnet CLI. Expected reference: HEAD14698f19848af867f48a04521e274abd55972075.
 *
 * Suggest only the supplied middle peer. Send one official TEST0 frame through
 * the remote peer's public CORE MQ. TEST is the official type0 assignment.
 * Success requires both the original peer-MQ handoff and exact opposite payload
 * from the exact remote CORE identity. The handoff is only a local CORE-client
 * queue event, not proof of an IPC write, downstream admission or remote delivery.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gnunet_util_lib.h>
#include <gnunet_core_service.h>
#include <gnunet_transport_application_service.h>
#include <gnunet_protocols.h>

#define PAYLOAD_BYTES 16U
#define MAX_ORIGINAL_WINDOW_US UINT64_C(130000000)

struct TestMessage
{
  struct GNUNET_MessageHeader header;
  uint8_t payload[PAYLOAD_BYTES];
};

_Static_assert (20 == sizeof(struct TestMessage), "exact TEST0 frame extent");

struct PeerContext
{
  struct GNUNET_PeerIdentity peer;
  bool connected;
};

struct Application
{
  struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_CORE_Handle *core;
  struct GNUNET_TRANSPORT_ApplicationHandle *transport;
  struct GNUNET_TRANSPORT_ApplicationSuggestHandle *interest;
  struct GNUNET_SCHEDULER_Task *deadline_task;
  struct GNUNET_SCHEDULER_Task *stop_task;
  struct GNUNET_TIME_Absolute deadline;
  struct GNUNET_PeerIdentity local;
  struct GNUNET_PeerIdentity remote;
  struct GNUNET_PeerIdentity middle;
  struct PeerContext peers[3];
  struct GNUNET_MQ_MessageHandler handlers[2];
  char role;
  bool initialized;
  bool submitted;
  bool peer_mq_handoff;
  bool received;
  bool decision_pending;
  bool desired_success;
  bool cleaning;
  bool cleaned;
  bool stdout_failed;
  const char *reason;
  int exit_code;
};

static struct Application app;

static const uint8_t payload_a[PAYLOAD_BYTES] = {
  0x44, 0x56, 0x2d, 0x43, 0x4f, 0x52, 0x45, 0x2d,
  0x41, 0x00, 0x01, 0x7f, 0x80, 0xff, 0x03, 0x04
};

static const uint8_t payload_c[PAYLOAD_BYTES] = {
  0x44, 0x56, 0x2d, 0x43, 0x4f, 0x52, 0x45, 0x2d,
  0x43, 0x00, 0x02, 0x7f, 0x81, 0xfe, 0x05, 0x06
};

static const struct GNUNET_CORE_ServiceInfo service_info = {
  .service = GNUNET_CORE_SERVICE_TEST,
  .version = { 1, 0 },
  .version_max = { 1, 0 },
  .version_min = { 1, 0 }
};

static void request_finish (bool success, const char *reason);
static void event (const char *format, ...)
  __attribute__ ((format (printf, 1, 2)));

/* Every event is a bounded line of fixed text, public identities and counts.
 * No inner bytes, key material, private route state or synthetic ACK is logged.
 */
static void
event (const char *format, ...)
{
  va_list args;
  int result;

  if (app.stdout_failed)
    return;
  va_start (args, format);
  result = vfprintf (stdout, format, args);
  va_end (args);
  if ((result < 0) || (EOF == fputc ('\n', stdout)) || (0 != fflush (stdout)))
  {
    app.stdout_failed = true;
    app.exit_code = 1;
    if (! app.cleaning)
      request_finish (false, "stdout-failed");
  }
}

static bool
same_peer (const struct GNUNET_PeerIdentity *left,
           const struct GNUNET_PeerIdentity *right)
{
  return 0 == GNUNET_memcmp (left, right);
}

static void
stop_now (void *cls)
{
  (void) cls;
  app.stop_task = NULL;
  GNUNET_SCHEDULER_shutdown ();
}

static void
request_finish (bool success, const char *reason)
{
  if (app.decision_pending || app.cleaning)
    return;
  app.decision_pending = true;
  app.desired_success = success;
  app.reason = reason;
  /* In particular, never disconnect CORE from its startup callback. */
  app.stop_task = GNUNET_SCHEDULER_add_now (&stop_now, NULL);
}

static bool
within_original_deadline (void)
{
  if (GNUNET_TIME_absolute_get ().abs_value_us >= app.deadline.abs_value_us)
  {
    request_finish (false, "deadline");
    return false;
  }
  return true;
}

static bool
admit_callback_action (void)
{
  return (! app.decision_pending) && (! app.cleaning)
         && within_original_deadline ();
}

static void
maybe_complete (void)
{
  if ((! app.decision_pending) && app.peer_mq_handoff && app.received
      && within_original_deadline ())
    request_finish (true, "complete");
}

static void
peer_mq_handoff_complete (void *cls)
{
  (void) cls;
  if (app.cleaning)
    return;
  if ((! app.submitted) || app.peer_mq_handoff)
  {
    request_finish (false, "unexpected-peer-mq-handoff");
    return;
  }
  /* Keep this actual original callback even if an earlier terminal decision
   * is already pending. It cannot turn that decision into success. */
  app.peer_mq_handoff = true;
  event ("PEER_MQ_HANDOFF peer=%s bytes=16 assurance=core-client-queue-only",
         GNUNET_i2s_full (&app.remote));
  maybe_complete ();
}

static void
handle_test (void *cls, const struct TestMessage *message)
{
  const struct PeerContext *peer = cls;
  const uint8_t *expected = ('a' == app.role) ? payload_c : payload_a;

  if (app.cleaning)
    return;
  if ((NULL == peer) || (! peer->connected)
      || (! same_peer (&peer->peer, &app.remote)))
  {
    request_finish (false, "unexpected-sender");
    return;
  }
  if ((sizeof(*message) != ntohs (message->header.size))
      || (GNUNET_MESSAGE_TYPE_TEST != ntohs (message->header.type))
      || (0 != memcmp (message->payload, expected, PAYLOAD_BYTES)))
  {
    request_finish (false, "wrong-payload");
    return;
  }
  if (app.received)
  {
    event ("DUPLICATE_RECEIVE peer=%s bytes=16", GNUNET_i2s_full (&peer->peer));
    return;
  }
  app.received = true;
  event ("RECEIVE peer=%s bytes=16 matched=yes", GNUNET_i2s_full (&peer->peer));
  maybe_complete ();
}

static void
initialized (void *cls, const struct GNUNET_PeerIdentity *identity)
{
  (void) cls;
  if (! admit_callback_action ())
    return;
  if ((NULL == identity) || (! same_peer (identity, &app.local)))
  {
    request_finish (false, "local-identity-mismatch");
    return;
  }
  if (app.initialized)
  {
    event ("REINITIALIZED peer=%s", GNUNET_i2s_full (identity));
    request_finish (false, "core-reinitialized");
    return;
  }
  app.initialized = true;
  event ("INITIALIZED peer=%s matched=yes", GNUNET_i2s_full (identity));
}

static void *
connected (void *cls,
           const struct GNUNET_PeerIdentity *peer,
           struct GNUNET_MQ_Handle *mq,
           enum GNUNET_CORE_PeerClass peer_class)
{
  struct PeerContext *context = NULL;
  struct TestMessage *message;
  struct GNUNET_MQ_Envelope *envelope;

  (void) cls;
  (void) peer_class;
  if (! admit_callback_action ())
    return NULL;
  if ((! app.initialized) || (NULL == mq))
  {
    request_finish (false, "connection-before-init");
    return NULL;
  }
  for (size_t i = 0; i < 3; ++i)
    if (same_peer (peer, &app.peers[i].peer))
      context = &app.peers[i];
  if (NULL == context)
  {
    event ("UNEXPECTED_CONNECT peer=%s", GNUNET_i2s_full (peer));
    request_finish (false, "unexpected-peer");
    return NULL;
  }
  if (context->connected)
  {
    request_finish (false, "duplicate-peer-connect");
    return context;
  }
  context->connected = true;
  if (! same_peer (peer, &app.remote))
    return context;
  event ("TARGET peer=%s", GNUNET_i2s_full (peer));
  if (app.submitted)
  {
    request_finish (false, "target-reconnected");
    return context;
  }
  envelope = GNUNET_MQ_msg (message, GNUNET_MESSAGE_TYPE_TEST);
  memcpy (message->payload,
          ('a' == app.role) ? payload_a : payload_c,
          PAYLOAD_BYTES);
  app.submitted = true;
  GNUNET_MQ_notify_sent (envelope, &peer_mq_handoff_complete, NULL);
  GNUNET_MQ_send (mq, envelope);
  return context;
}

static void
disconnected (void *cls,
              const struct GNUNET_PeerIdentity *peer,
              void *peer_cls)
{
  struct PeerContext *context = peer_cls;

  (void) cls;
  if (app.cleaning)
    return;
  if ((NULL == context) || (! same_peer (&context->peer, peer)))
  {
    request_finish (false, "disconnect-context-mismatch");
    return;
  }
  context->connected = false;
  event ("DISCONNECTED peer=%s", GNUNET_i2s_full (peer));
  if (same_peer (peer, &app.local))
  {
    /* core_api does not call init again after reconnect. Its synthetic self
     * peer is therefore also our public source-loss observation. */
    request_finish (false, "core-source-disconnected");
    return;
  }
  if (same_peer (peer, &app.remote) && app.submitted)
    request_finish (false, "target-disconnected");
}

static void
deadline_reached (void *cls)
{
  (void) cls;
  app.deadline_task = NULL;
  request_finish (false, "deadline");
}

static void
cleanup (void *cls)
{
  bool passed;

  (void) cls;
  if (app.cleaned)
    return;
  app.cleaning = true;
  if (NULL != app.deadline_task)
  {
    GNUNET_SCHEDULER_cancel (app.deadline_task);
    app.deadline_task = NULL;
  }
  if (NULL != app.stop_task)
  {
    GNUNET_SCHEDULER_cancel (app.stop_task);
    app.stop_task = NULL;
  }
  if (NULL != app.core)
  {
    GNUNET_CORE_disconnect (app.core);
    app.core = NULL;
  }
  if (NULL != app.interest)
  {
    GNUNET_TRANSPORT_application_suggest_cancel (app.interest);
    app.interest = NULL;
  }
  if (NULL != app.transport)
  {
    GNUNET_TRANSPORT_application_done (app.transport);
    app.transport = NULL;
  }
  passed = app.decision_pending && app.desired_success && app.initialized
           && app.submitted && app.peer_mq_handoff && app.received
           && (! app.stdout_failed);
  app.exit_code = passed ? 0 : 1;
  event ("END passed=%s peer_mq_handoff=%s received=%s reason=%s",
         passed ? "yes" : "no",
         app.peer_mq_handoff ? "yes" : "no",
         app.received ? "yes" : "no",
         app.stdout_failed ? "stdout-failed" : app.reason);
  if (app.stdout_failed)
    app.exit_code = 1;
  app.cleaned = true;
}

static void
start (void *cls)
{
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth = { 0 };

  (void) cls;
  GNUNET_SCHEDULER_add_shutdown (&cleanup, NULL);
  event ("OPEN role=%c", app.role);
  now = GNUNET_TIME_absolute_get ();
  if ((app.deadline.abs_value_us <= now.abs_value_us)
      || (app.deadline.abs_value_us - now.abs_value_us > MAX_ORIGINAL_WINDOW_US))
  {
    request_finish (false, "invalid-deadline-window");
    return;
  }
  app.deadline_task = GNUNET_SCHEDULER_add_at (app.deadline,
                                             &deadline_reached,
                                             NULL);
  app.transport = GNUNET_TRANSPORT_application_init (app.cfg);
  if (NULL == app.transport)
  {
    request_finish (false, "transport-application-open");
    return;
  }
  app.interest = GNUNET_TRANSPORT_application_suggest (
    app.transport,
    &app.middle,
    GNUNET_MQ_PRIO_BACKGROUND,
    bandwidth);
  if (NULL == app.interest)
  {
    request_finish (false, "middle-interest-admission");
    return;
  }
  event ("MIDDLE_INTEREST peer=%s admission=local-only",
         GNUNET_i2s_full (&app.middle));
  app.handlers[0] = GNUNET_MQ_hd_fixed_size (test,
                                             GNUNET_MESSAGE_TYPE_TEST,
                                             struct TestMessage,
                                             NULL);
  app.handlers[1] = (struct GNUNET_MQ_MessageHandler) GNUNET_MQ_handler_end ();
  app.core = GNUNET_CORE_connect (app.cfg,
                                  NULL,
                                  &initialized,
                                  &connected,
                                  &disconnected,
                                  app.handlers,
                                  &service_info);
  if (NULL == app.core)
    request_finish (false, "core-open");
}

static bool
parse_peer (const char *text, struct GNUNET_PeerIdentity *peer)
{
  return (52 == strlen (text))
         && (GNUNET_OK == GNUNET_CRYPTO_eddsa_public_key_from_string (
               text, strlen (text), &peer->public_key));
}

int
main (int argc, char **argv)
{
  unsigned long long deadline;
  char *end;

  if ((10 != argc) || (0 != strcmp (argv[1], "-c"))
      || (0 != strcmp (argv[3], "-L")) || (1 != strlen (argv[5]))
      || (('a' != argv[5][0]) && ('c' != argv[5][0])))
  {
    fprintf (stderr,
             "usage: %s -c CONFIG -L LEVEL a|c LOCAL_PID52 REMOTE_PID52 MIDDLE_PID52 ABSOLUTE_DEADLINE_US\n",
             argv[0]);
    return 2;
  }
  if ((! parse_peer (argv[6], &app.local))
      || (! parse_peer (argv[7], &app.remote))
      || (! parse_peer (argv[8], &app.middle))
      || same_peer (&app.local, &app.remote)
      || same_peer (&app.local, &app.middle)
      || same_peer (&app.remote, &app.middle)
      || (argv[9][0] < '0') || (argv[9][0] > '9'))
    return 2;
  errno = 0;
  deadline = strtoull (argv[9], &end, 10);
  if ((ERANGE == errno) || ('\0' != *end) || (0 == deadline)
      || (deadline >= UINT64_MAX))
    return 2;
  app.role = argv[5][0];
  app.deadline.abs_value_us = (uint64_t) deadline;
  app.reason = "external-shutdown";
  app.exit_code = 1;
  app.peers[0].peer = app.local;
  app.peers[1].peer = app.remote;
  app.peers[2].peer = app.middle;
  if (0 != setvbuf (stdout, NULL, _IOLBF, 0))
    return 1;
  if (GNUNET_OK != GNUNET_log_setup ("dv-core-client", argv[4], NULL))
    return 2;
  app.cfg = GNUNET_CONFIGURATION_create (GNUNET_OS_project_data_gnunet ());
  if (GNUNET_OK != GNUNET_CONFIGURATION_load (app.cfg, argv[2]))
  {
    fprintf (stderr, "explicit configuration load failed\n");
    GNUNET_CONFIGURATION_destroy (app.cfg);
    return 1;
  }
  GNUNET_SCHEDULER_run (&start, NULL);
  GNUNET_CONFIGURATION_destroy (app.cfg);
  return app.cleaned ? app.exit_code : 1;
}
