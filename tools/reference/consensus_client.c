/* SPDX-License-Identifier: MPL-2.0 */
/* Four actual participants through unchanged official CONSENSUS public API.
 * This is a local C API caller, not a C peer algorithm or service launcher.
 * Reference: 14698f19848af867f48a04521e274abd55972075.
 * Type0 deliberately avoids the pinned API's missing INSERT type assignment
 * and missing RECEIVED type byte-order conversion. Neither is patched here.
 */
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <gnunet_util_lib.h>
#include <gnunet_consensus_service.h>
#include <gnunet_core_service.h>
#include <gnunet_transport_application_service.h>

#define PEERS 4U
#define ELEMENT_BYTES 16U
#define ORIGINAL_WINDOW_US UINT64_C(180000000)
#define NATIVE_WINDOW_US UINT64_C(200000000)

_Static_assert (64 == sizeof(struct GNUNET_HashCode), "complete session ID");
_Static_assert (32 == sizeof(struct GNUNET_PeerIdentity), "complete peer ID");

static const uint8_t common[ELEMENT_BYTES] = {
  0x43, 0x53, 0x2d, 0x43, 0x4f, 0x4d, 0x4d, 0x4f,
  0x4e, 0x00, 0x7f, 0x80, 0xff, 0x11, 0x22, 0x33
};
static const uint8_t own[PEERS][ELEMENT_BYTES] = {
  { 0x43, 0x53, 0x2d, 0x52, 0x4f, 0x4c, 0x45, 0x2d,
    0x00, 0x00, 0x01, 0x7f, 0x80, 0xff, 0x10, 0x20 },
  { 0x43, 0x53, 0x2d, 0x52, 0x4f, 0x4c, 0x45, 0x2d,
    0x01, 0x00, 0x02, 0x7f, 0x81, 0xfe, 0x11, 0x21 },
  { 0x43, 0x53, 0x2d, 0x52, 0x4f, 0x4c, 0x45, 0x2d,
    0x02, 0x00, 0x03, 0x7f, 0x82, 0xfd, 0x12, 0x22 },
  { 0x43, 0x53, 0x2d, 0x52, 0x4f, 0x4c, 0x45, 0x2d,
    0x03, 0x00, 0x04, 0x7f, 0x83, 0xfc, 0x13, 0x23 }
};

struct InsertContext
{
  unsigned int stage;
};
static struct InsertContext inserts[2] = { { 0 }, { 1 } };
struct PeerContext
{
  unsigned int role;
  bool live;
};
static const struct GNUNET_CORE_ServiceInfo service_info = {
  .service = GNUNET_CORE_SERVICE_TEST,
  .version = { 1, 0 },
  .version_max = { 1, 0 },
  .version_min = { 1, 0 }
};

static struct
{
  const struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_CORE_Handle *core;
  struct GNUNET_TRANSPORT_ApplicationHandle *transport;
  struct GNUNET_TRANSPORT_ApplicationSuggestHandle *interests[PEERS];
  struct GNUNET_MQ_MessageHandler handlers[1];
  struct PeerContext peer_contexts[PEERS];
  struct GNUNET_CONSENSUS_Handle *handle;
  struct GNUNET_SCHEDULER_Task *deadline_task;
  struct GNUNET_SCHEDULER_Task *start_task;
  struct GNUNET_SCHEDULER_Task *advance_task;
  struct GNUNET_SCHEDULER_Task *stop_task;
  struct GNUNET_PeerIdentity peers[PEERS];
  struct GNUNET_HashCode sid;
  struct GNUNET_TIME_Absolute start;
  struct GNUNET_TIME_Absolute deadline;
  char sid_text[129];
  uint64_t native_until;
  uint64_t duplicates;
  unsigned int role;
  unsigned int submitted;
  unsigned int completed;
  unsigned int seen;
  unsigned int live_peers;
  bool initialized;
  bool core_ready;
  bool insert_pending;
  bool conclude_requested;
  bool concluded;
  bool decision;
  bool success;
  bool cleaning;
  bool cleaned;
  bool stdout_failed;
  const char *reason;
  int status;
} app;
static volatile sig_atomic_t native_expired;
static volatile sig_atomic_t scheduler_ready;
static struct sigaction old_alarm;
static bool watchdog_installed;

static void finish (bool success, const char *reason);
static void advance (void *cls);
static void event (const char *format, ...)
  __attribute__ ((format (printf, 1, 2)));

static bool
native_now (uint64_t *value)
{
  struct timespec sample;
  if ((0 != clock_gettime (CLOCK_MONOTONIC, &sample)) || (sample.tv_sec < 0)
      || ((uint64_t) sample.tv_sec > (UINT64_MAX - UINT64_C(999999)) / UINT64_C(1000000)))
    return false;
  *value = (uint64_t) sample.tv_sec * UINT64_C(1000000)
           + (uint64_t) sample.tv_nsec / UINT64_C(1000);
  return true;
}

/* Armed once before PROGRAM preparation. The handler only uses signal-safe
 * operations; normal scheduler SIGTERM cleanup owns the actual API handle.
 * A supervisor must still stop/consume an uninterruptible native call.
 */
static void
native_alarm (int signum)
{
  const int saved_errno = errno;
  (void) signum;
  native_expired = 1;
  if (! scheduler_ready)
    _exit (124);
  (void) kill (getpid (), SIGTERM);
  errno = saved_errno;
}

static bool
arm_watchdog (void)
{
  struct itimerval previous;
  struct itimerval timer = { 0 };
  struct sigaction action = { 0 };
  uint64_t now;
  if ((0 != getitimer (ITIMER_REAL, &previous))
      || (0 != previous.it_value.tv_sec) || (0 != previous.it_value.tv_usec)
      || (0 != previous.it_interval.tv_sec) || (0 != previous.it_interval.tv_usec)
      || (! native_now (&now)) || (now >= app.native_until))
    return false;
  action.sa_handler = &native_alarm;
  if ((0 != sigemptyset (&action.sa_mask))
      || (0 != sigaction (SIGALRM, &action, &old_alarm)))
    return false;
  watchdog_installed = true;
  timer.it_value.tv_sec = (time_t) ((app.native_until - now) / UINT64_C(1000000));
  timer.it_value.tv_usec = (suseconds_t) ((app.native_until - now) % UINT64_C(1000000));
  return 0 == setitimer (ITIMER_REAL, &timer, NULL);
}

static bool
disarm_watchdog (void)
{
  struct itimerval timer = { 0 };
  bool ok = true;
  if (watchdog_installed)
  {
    ok = 0 == setitimer (ITIMER_REAL, &timer, NULL);
    if (0 != sigaction (SIGALRM, &old_alarm, NULL))
      ok = false;
    watchdog_installed = false;
  }
  return ok;
}

static bool
bounds_live (void)
{
  uint64_t now;
  return (! native_expired) && native_now (&now) && (now < app.native_until)
         && (GNUNET_TIME_absolute_get ().abs_value_us < app.deadline.abs_value_us);
}

static bool
admit (void)
{
  if (app.decision || app.cleaning)
    return false;
  if (! bounds_live ())
  {
    finish (false, native_expired ? "native-deadline" : "original-deadline");
    return false;
  }
  return true;
}

static bool
before_start (void)
{
  if (! admit ())
    return false;
  if (GNUNET_TIME_absolute_get ().abs_value_us >= app.start.abs_value_us)
  {
    finish (false, "start-before-conclude");
    return false;
  }
  return true;
}

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
    finish (false, "stdout-failed");
  }
}

static void
stop_now (void *cls)
{
  (void) cls;
  app.stop_task = NULL;
  GNUNET_SCHEDULER_shutdown ();
}

static void
finish (bool success, const char *reason)
{
  if (app.cleaning)
    return;
  if (app.decision)
  {
    /* A deferred successful stop cannot hide a late invalid/NULL callback or
     * output failure before the public handle is actually destroyed.
     */
    if ((! success) && app.success)
    {
      app.success = false;
      app.reason = reason;
    }
    return;
  }
  app.decision = true;
  app.success = success;
  app.reason = reason;
  app.stop_task = GNUNET_SCHEDULER_add_now (&stop_now, NULL);
}

static unsigned int
expected_mask (void)
{
  return ((1U << PEERS) - 1U) ^ (1U << app.role);
}

static unsigned int
unique_count (void)
{
  unsigned int count = 0;
  for (unsigned int role = 0; role < PEERS; ++role)
    if (0 != (app.seen & (1U << role)))
      ++count;
  return count;
}

static bool
peers_live (void)
{
  return app.initialized && ((app.live_peers & expected_mask ()) == expected_mask ());
}

static void
maybe_advance (void)
{
  if ((! app.decision) && (! app.cleaning) && (NULL == app.handle)
      && (NULL == app.advance_task) && peers_live ())
    app.advance_task = GNUNET_SCHEDULER_add_now (&advance, NULL);
}

static void
initialized (void *cls, const struct GNUNET_PeerIdentity *identity)
{
  (void) cls;
  if (app.cleaning)
    return;
  if (app.initialized)
  {
    finish (false, "core-reinitialized");
    return;
  }
  if (! admit ())
    return;
  if ((NULL == identity) || (0 != GNUNET_memcmp (identity, &app.peers[app.role])))
  {
    finish (false, "core-local-identity-mismatch");
    return;
  }
  app.initialized = true;
  event ("INITIALIZED role=%u id=%s matched=yes", app.role, GNUNET_i2s_full (identity));
  maybe_advance ();
}

static void *
connected (void *cls, const struct GNUNET_PeerIdentity *peer,
           struct GNUNET_MQ_Handle *mq, enum GNUNET_CORE_PeerClass peer_class)
{
  unsigned int role;
  struct PeerContext *context;
  (void) cls;
  (void) peer_class;
  if (app.cleaning)
    return NULL;
  if (app.concluded)
  {
    finish (false, "core-connect-after-conclusion");
    return NULL;
  }
  if (! admit ())
    return NULL;
  if ((! app.initialized) || (NULL == peer) || (NULL == mq))
  {
    finish (false, "core-connect-before-init");
    return NULL;
  }
  for (role = 0; role < PEERS; ++role)
    if (0 == GNUNET_memcmp (peer, &app.peers[role]))
      break;
  if (PEERS == role)
  {
    finish (false, "unexpected-core-peer");
    return NULL;
  }
  context = &app.peer_contexts[role];
  if (context->live)
  {
    finish (false, "duplicate-core-connect");
    return context;
  }
  context->live = true;
  app.live_peers |= 1U << role;
  if (app.role == role)
    event ("CORE_SELF role=%u id=%s scope=local-API", app.role, GNUNET_i2s_full (peer));
  else
    event ("CORE_CONNECT role=%u peer-role=%u id=%s", app.role, role, GNUNET_i2s_full (peer));
  maybe_advance ();
  return context;
}

static void
disconnected (void *cls, const struct GNUNET_PeerIdentity *peer, void *peer_cls)
{
  const struct PeerContext *context = peer_cls;
  unsigned int role;
  (void) cls;
  if (app.cleaning)
    return;
  if ((NULL == context) || (NULL == peer) || (context->role >= PEERS))
  {
    finish (false, "core-disconnect-context-mismatch");
    return;
  }
  role = context->role;
  if ((context != &app.peer_contexts[role]) || (! context->live)
      || (0 != GNUNET_memcmp (peer, &app.peers[role])))
  {
    finish (false, "core-disconnect-peer-mismatch");
    return;
  }
  app.peer_contexts[role].live = false;
  app.live_peers &= ~(1U << role);
  event ("CORE_DISCONNECT role=%u peer-role=%u id=%s", app.role, role, GNUNET_i2s_full (peer));
  if (app.role == role)
    finish (false, "core-source-disconnected");
  else if (NULL != app.handle)
    finish (false, "core-peer-disconnected-during-consensus");
}

static void
element_received (void *cls, const struct GNUNET_SET_Element *element)
{
  unsigned int role;
  (void) cls;
  if (app.cleaning)
    return;
  if (app.concluded)
  {
    finish (false, "element-after-conclusion");
    return;
  }
  if (! admit ())
    return;
  if (NULL == element)
  {
    finish (false, "null-element-callback");
    return;
  }
  if ((0 != element->element_type) || (ELEMENT_BYTES != element->size)
      || (NULL == element->data))
  {
    finish (false, "element-shape-mismatch");
    return;
  }
  if (0 == memcmp (element->data, common, ELEMENT_BYTES))
  {
    finish (false, "local-common-was-delivered");
    return;
  }
  for (role = 0; role < PEERS; ++role)
    if (0 == memcmp (element->data, own[role], ELEMENT_BYTES))
      break;
  if ((PEERS == role) || (app.role == role))
  {
    finish (false, (PEERS == role) ? "unexpected-element" : "local-own-was-delivered");
    return;
  }
  if (0 != (app.seen & (1U << role)))
  {
    if (UINT64_MAX == app.duplicates)
      finish (false, "duplicate-count-overflow");
    else
      ++app.duplicates;
    return; /* API permits duplicates; only the first exact value is logged. */
  }
  app.seen |= 1U << role;
  event ("ELEMENT role=%u from-role=%u type=0 bytes=16 matched=yes",
         app.role, role);
}

static void
concluded (void *cls)
{
  (void) cls;
  if (app.cleaning)
    return;
  if (app.concluded)
  {
    finish (false, "duplicate-conclude-callback");
    return;
  }
  app.concluded = true;
  /* The official callback has destroyed its MQ, but NOT its Handle. Retain
   * app.handle for deferred GNUNET_CONSENSUS_destroy after this callback.
   */
  if (! admit ())
    return;
  if ((! app.conclude_requested) || app.insert_pending || (2U != app.completed)
      || (3U != app.submitted) || (expected_mask () != app.seen)
      || (3U != unique_count ()) || (! peers_live ()) || (! app.core_ready))
  {
    finish (false, "incomplete-or-unexpected-conclusion");
    return;
  }
  event ("CONCLUDED role=%u unique=3 expected=3 matched=yes", app.role);
  if (admit ())
    finish (true, "complete");
}

static void
insert_done (void *cls, int success)
{
  const struct InsertContext *context = cls;
  if (app.cleaning)
    return;
  if (app.concluded)
  {
    finish (false, "insert-callback-after-conclusion");
    return;
  }
  if (! admit ())
    return;
  if ((GNUNET_OK != success) || (NULL == context) || (! app.insert_pending)
      || (context->stage != app.completed) || (app.completed >= 2U)
      || (0 == (app.submitted & (1U << context->stage))))
  {
    finish (false, "insert-handoff-mismatch");
    return;
  }
  app.insert_pending = false;
  ++app.completed;
  event ("CLIENT_QUEUE_HANDOFF role=%u element=%s type=0 bytes=16 assurance=local-API-only",
         app.role, (0 == context->stage) ? "common" : "own");
  if (admit ())
    app.advance_task = GNUNET_SCHEDULER_add_now (&advance, NULL);
}

static void
advance (void *cls)
{
  struct GNUNET_SET_Element element;
  (void) cls;
  app.advance_task = NULL;
  if (! before_start ())
    return;
  if ((NULL == app.handle) && (! peers_live ()))
    return; /* A pre-session disconnect can recover before the original start. */
  if (NULL == app.handle)
  {
    app.core_ready = true;
    event ("CORE_READY role=%u peers=3 identity=matched", app.role);
    if (! before_start ())
      return;
    app.handle = GNUNET_CONSENSUS_create (
      app.cfg, PEERS, app.peers, &app.sid, app.start, app.deadline, &element_received, NULL);
    if (NULL == app.handle)
    {
      finish (false, "session-open-failed");
      return;
    }
    event ("SESSION_OPEN role=%u peers=4 admission=local-API-only", app.role);
    if (! before_start ())
      return;
  }
  if (app.insert_pending || app.conclude_requested || (! peers_live ()))
  {
    finish (false, "unexpected-advance-state");
    return;
  }
  if (app.completed < 2U)
  {
    element.size = ELEMENT_BYTES;
    element.element_type = 0;
    element.data = (0 == app.completed) ? common : own[app.role];
    app.insert_pending = true;
    app.submitted |= 1U << app.completed;
    GNUNET_CONSENSUS_insert (app.handle, &element, &insert_done, &inserts[app.completed]);
    return;
  }
  app.conclude_requested = true;
  GNUNET_CONSENSUS_conclude (app.handle, &concluded, NULL);
  if (! before_start ())
    return;
  if (NULL != app.start_task)
  {
    GNUNET_SCHEDULER_cancel (app.start_task);
    app.start_task = NULL;
  }
  event ("CONCLUDE_SUBMITTED role=%u before-original-start=yes", app.role);
}

static void
start_reached (void *cls)
{
  (void) cls;
  app.start_task = NULL;
  if (! app.conclude_requested)
    finish (false, "start-before-conclude");
}

static void
deadline_reached (void *cls)
{
  (void) cls;
  app.deadline_task = NULL;
  finish (false, "absolute-deadline");
}

static void
cleanup (void *cls)
{
  bool passed;
  bool live;
  (void) cls;
  if (app.cleaned)
    return;
  app.cleaning = true;
  if (NULL != app.deadline_task)
    GNUNET_SCHEDULER_cancel (app.deadline_task);
  if (NULL != app.start_task)
    GNUNET_SCHEDULER_cancel (app.start_task);
  if (NULL != app.advance_task)
    GNUNET_SCHEDULER_cancel (app.advance_task);
  if (NULL != app.stop_task)
    GNUNET_SCHEDULER_cancel (app.stop_task);
  app.deadline_task = app.start_task = app.advance_task = app.stop_task = NULL;
  if (NULL != app.handle)
    GNUNET_CONSENSUS_destroy (app.handle);
  app.handle = NULL;
  if (NULL != app.core)
    GNUNET_CORE_disconnect (app.core);
  app.core = NULL;
  for (unsigned int role = 0; role < PEERS; ++role)
  {
    if (NULL != app.interests[role])
      GNUNET_TRANSPORT_application_suggest_cancel (app.interests[role]);
    app.interests[role] = NULL;
  }
  if (NULL != app.transport)
    GNUNET_TRANSPORT_application_done (app.transport);
  app.transport = NULL;
  live = bounds_live ();
  passed = app.decision && app.success && app.concluded && app.conclude_requested
           && (! app.insert_pending) && (2U == app.completed) && (3U == app.submitted)
           && (expected_mask () == app.seen) && (3U == unique_count ())
           && app.core_ready && peers_live () && (! app.stdout_failed) && live;
  event ("END role=%u passed=%s handoffs=%u unique=%u duplicates=%" PRIu64
         " concluded=%s reason=%s", app.role, passed ? "yes" : "no", app.completed,
         unique_count (), app.duplicates, app.concluded ? "yes" : "no",
         native_expired ? "native-deadline" : (! live) ? "original-deadline" : app.reason);
  app.status = passed && (! app.stdout_failed) ? 0 : 1;
  app.cleaned = true;
  scheduler_ready = 0;
}

static bool
parse_time (const char *text, uint64_t *result)
{
  unsigned long long value;
  char *end;
  if ((text[0] < '0') || (text[0] > '9'))
    return false;
  errno = 0;
  value = strtoull (text, &end, 10);
  if ((ERANGE == errno) || ('\0' != *end) || (value >= UINT64_MAX))
    return false;
  *result = (uint64_t) value;
  return true;
}

static int
hex_digit (char value)
{
  if ((value >= '0') && (value <= '9'))
    return value - '0';
  if ((value >= 'a') && (value <= 'f'))
    return value - 'a' + 10;
  if ((value >= 'A') && (value <= 'F'))
    return value - 'A' + 10;
  return -1;
}

static bool
parse_sid (const char *text)
{
  uint8_t *bytes = (uint8_t *) &app.sid;
  if (128 != strlen (text))
    return false;
  for (unsigned int i = 0; i < sizeof(app.sid); ++i)
  {
    const int high = hex_digit (text[2U * i]);
    const int low = hex_digit (text[2U * i + 1U]);
    if ((high < 0) || (low < 0))
      return false;
    bytes[i] = (uint8_t) ((unsigned int) high * 16U + (unsigned int) low);
  }
  memcpy (app.sid_text, text, sizeof(app.sid_text));
  return true;
}

static void
run (void *cls, char *const *args, const char *filename,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  uint64_t now;
  struct GNUNET_BANDWIDTH_Value32NBO bandwidth = { 0 };
  (void) cls;
  (void) filename;
  app.cfg = cfg;
  GNUNET_SCHEDULER_add_shutdown (&cleanup, NULL);
  scheduler_ready = 1;
  for (unsigned int i = 0; i < 8U; ++i)
    if (NULL == args[i])
    {
      finish (false, "missing-original-intent");
      return;
    }
  if ((NULL != args[8]) || (1 != strlen (args[0]))
      || (args[0][0] < '0') || (args[0][0] > '3'))
  {
    finish (false, "invalid-local-role");
    return;
  }
  app.role = (unsigned int) (args[0][0] - '0');
  for (unsigned int role = 0; role < PEERS; ++role)
  {
    app.peer_contexts[role].role = role;
    if ((52 != strlen (args[role + 1U]))
        || (GNUNET_OK != GNUNET_CRYPTO_eddsa_public_key_from_string (
              args[role + 1U], strlen (args[role + 1U]), &app.peers[role].public_key)))
    {
      finish (false, "invalid-public-peer");
      return;
    }
    for (unsigned int previous = 0; previous < role; ++previous)
      if (0 == GNUNET_memcmp (&app.peers[previous], &app.peers[role]))
      {
        finish (false, "duplicate-public-peer");
        return;
      }
  }
  now = GNUNET_TIME_absolute_get ().abs_value_us;
  if ((! parse_sid (args[5])) || (! parse_time (args[6], &app.start.abs_value_us))
      || (! parse_time (args[7], &app.deadline.abs_value_us))
      || (now >= app.start.abs_value_us)
      || (app.start.abs_value_us >= app.deadline.abs_value_us)
      || (app.deadline.abs_value_us - now > ORIGINAL_WINDOW_US) || (! before_start ()))
  {
    finish (false, "invalid-original-intent");
    return;
  }
  event ("OPEN role=%u peers=4 sid=%s start-us=%" PRIu64 " deadline-us=%" PRIu64,
         app.role, app.sid_text, app.start.abs_value_us, app.deadline.abs_value_us);
  for (unsigned int role = 0; role < PEERS; ++role)
    event ("PEER role=%u id=%s", role, GNUNET_i2s_full (&app.peers[role]));
  if (! before_start ())
    return;
  app.start_task = GNUNET_SCHEDULER_add_at (app.start, &start_reached, NULL);
  app.deadline_task = GNUNET_SCHEDULER_add_at (app.deadline, &deadline_reached, NULL);
  app.transport = GNUNET_TRANSPORT_application_init (cfg);
  if (NULL == app.transport)
  {
    finish (false, "transport-application-open-failed");
    return;
  }
  for (unsigned int role = 0; role < PEERS; ++role)
    if (app.role != role)
    {
      if (! before_start ())
        return;
      app.interests[role] = GNUNET_TRANSPORT_application_suggest (
        app.transport, &app.peers[role], GNUNET_MQ_PRIO_BACKGROUND, bandwidth);
      if (NULL == app.interests[role])
      {
        finish (false, "peer-interest-admission-failed");
        return;
      }
      event ("INTEREST role=%u peer-role=%u admission=local-only", app.role, role);
    }
  if (! before_start ())
    return;
  app.handlers[0] = (struct GNUNET_MQ_MessageHandler) GNUNET_MQ_handler_end ();
  app.core = GNUNET_CORE_connect (cfg, NULL, &initialized, &connected, &disconnected,
                                 app.handlers, &service_info);
  if (NULL == app.core)
    finish (false, "core-open-failed");
}

int
main (int argc, char **argv)
{
  const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  enum GNUNET_GenericReturnValue result;
  uint64_t now;
  if ((! native_now (&now)) || (now > UINT64_MAX - NATIVE_WINDOW_US))
    return 1;
  app.native_until = now + NATIVE_WINDOW_US;
  app.reason = "external-shutdown";
  app.status = 1;
  if ((13 != argc) || (0 != strcmp (argv[1], "-c")) || ('\0' == argv[2][0])
      || (0 != strcmp (argv[3], "-L")) || (0 != strcmp (argv[4], "ERROR")))
  {
    fprintf (stderr, "usage: %s -c CONFIG -L ERROR ROLE PID0_52 PID1_52 PID2_52 PID3_52 "
             "SID_HEX128 START_US DEADLINE_US\n", argv[0]);
    return 2;
  }
  if (! arm_watchdog ())
  {
    (void) disarm_watchdog ();
    return 1;
  }
  result = GNUNET_PROGRAM_run (
    GNUNET_OS_project_data_gnunet (), argc, argv, "consensus-client",
    "Actual four-participant type0 public CONSENSUS caller", options, &run, NULL);
  if (! disarm_watchdog ())
    return 1;
  return ((GNUNET_OK == result) && app.cleaned) ? app.status : 1;
}
