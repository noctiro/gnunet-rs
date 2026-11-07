/* SPDX-License-Identifier: MPL-2.0 */
/* Actual official-C public-API singleton780/783 -> encrypt ->781/782 caller.
 * No service startup, private Share input, replacement codec or FAIR claim.
 * Reference: 14698f19848af867f48a04521e274abd55972075.
 */
#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <gnunet_util_lib.h>
#include <gnunet_secretsharing_service.h>

#define ORIGINAL_WINDOW_US UINT64_C(60000000)
#define SINGLETON_SHARE_BYTES 426U
#define SHARE_PUBLIC_OFFSET 8U
#define SHARE_PEER_OFFSET 264U
#define SHARE_INDEX_OFFSET 424U

_Static_assert (128 == sizeof(struct GNUNET_SECRETSHARING_Plaintext),
                "complete official plaintext extent");
_Static_assert (128 == sizeof(struct GNUNET_SECRETSHARING_PublicKey),
                "complete official public-key extent");
_Static_assert (32 == sizeof(struct GNUNET_PeerIdentity),
                "complete official peer extent");

static struct
{
  const struct GNUNET_CONFIGURATION_Handle *cfg;
  struct GNUNET_SECRETSHARING_Session *session;
  struct GNUNET_SECRETSHARING_DecryptionHandle *decrypt;
  struct GNUNET_SECRETSHARING_Share *share;
  struct GNUNET_SCHEDULER_Task *deadline_task;
  struct GNUNET_SCHEDULER_Task *advance_task;
  struct GNUNET_SCHEDULER_Task *stop_task;
  struct GNUNET_PeerIdentity expected_peer;
  struct GNUNET_SECRETSHARING_PublicKey public_key;
  struct GNUNET_SECRETSHARING_Plaintext expected;
  struct GNUNET_SECRETSHARING_Ciphertext ciphertext;
  struct GNUNET_TIME_Absolute start;
  struct GNUNET_TIME_Absolute deadline;
  uint64_t native_until;
  bool generated;
  bool encrypted;
  bool decrypted;
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

/* The original elapsed-time alarm is armed once before PROGRAM preparation.
 * Its handler performs only async-signal-safe operations. Once the scheduler
 * is running, its ordinary SIGTERM path performs the registered cleanup.
 */
static void
native_alarm (int signum)
{
  const int saved_errno = errno;
  (void) signum;
  native_expired = 1;
  if (! scheduler_ready)
    _exit (124); /* preparation or completed cleanup; no live business handle */
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

static void
event (const char *line)
{
  if (app.stdout_failed)
    return;
  if ((EOF == puts (line)) || (0 != fflush (stdout)))
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
  if (app.decision || app.cleaning)
    return;
  app.decision = true;
  app.success = success;
  app.reason = reason;
  /* Return from API callbacks before their library-owned handles are freed. */
  app.stop_task = GNUNET_SCHEDULER_add_now (&stop_now, NULL);
}

static bool
check_share (const struct GNUNET_SECRETSHARING_PublicKey *public_key,
             unsigned int num_ready_peers)
{
  uint8_t serialized[SINGLETON_SHARE_BYTES] = { 0 };
  size_t needed = 0;
  size_t written = 0;
  bool ok = (NULL != public_key) && (1 == num_ready_peers)
            && (GNUNET_OK == GNUNET_SECRETSHARING_share_write (app.share, NULL, 0, &needed))
            && (sizeof(serialized) == needed)
            && (GNUNET_OK == GNUNET_SECRETSHARING_share_write (
                  app.share, serialized, sizeof(serialized), &written))
            && (sizeof(serialized) == written);
  if (ok)
    ok = (0 == serialized[0]) && (1 == serialized[1]) /* threshold */
         && (0 == serialized[2]) && (1 == serialized[3]) /* num_peers */
         && (0 == serialized[4]) && (0 == serialized[5]) /* my_peer */
         && (0 == memcmp (serialized + SHARE_PEER_OFFSET,
                           &app.expected_peer, sizeof(app.expected_peer)))
         && (0 == memcmp (serialized + SHARE_PUBLIC_OFFSET,
                           public_key, sizeof(*public_key)))
         && (0 == serialized[SHARE_INDEX_OFFSET])
         && (0 == serialized[SHARE_INDEX_OFFSET + 1]);
  GNUNET_CRYPTO_zero_keys (serialized, sizeof(serialized));
  return ok;
}

static void
decrypted (void *cls, const struct GNUNET_SECRETSHARING_Plaintext *plaintext)
{
  (void) cls;
  app.decrypt = NULL; /* the official API cancels this handle after callback */
  if (! admit ())
    return;
  if ((! app.encrypted) || app.decrypted || (NULL == plaintext)
      || (0 != memcmp (plaintext, &app.expected, sizeof(app.expected))))
  {
    finish (false, "decryption-result-mismatch");
    return;
  }
  app.decrypted = true;
  event ("DECRYPTED callback=782 bytes=128 matched=yes original-share=yes");
  if (admit ())
    finish (true, "complete");
}

static void
begin_decrypt (void *cls)
{
  (void) cls;
  app.advance_task = NULL;
  if (! admit ())
    return;
  if ((GNUNET_OK != GNUNET_SECRETSHARING_plaintext_generate_i (
         &app.expected, INT64_C(0x102030405060708))) || (! admit ()))
  {
    finish (false, "plaintext-generation-failed");
    return;
  }
  if ((GNUNET_OK != GNUNET_SECRETSHARING_encrypt (
         &app.public_key, &app.expected, &app.ciphertext)) || (! admit ()))
  {
    finish (false, "public-api-encryption-failed");
    return;
  }
  app.encrypted = true;
  event ("ENCRYPTED public-api=yes plaintext-bytes=128 ciphertext-bytes=256");
  if (! admit ())
    return;
  /* Both requests keep the exact same original absolute start/deadline. */
  app.decrypt = GNUNET_SECRETSHARING_decrypt (
    app.cfg, app.share, &app.ciphertext, app.start, app.deadline, &decrypted, NULL);
  if (NULL == app.decrypt)
    finish (false, "decrypt-open-failed");
}

static void
secret_ready (void *cls, struct GNUNET_SECRETSHARING_Share *share,
              struct GNUNET_SECRETSHARING_PublicKey *public_key,
              unsigned int num_ready_peers,
              const struct GNUNET_PeerIdentity *ready_peers)
{
  (void) cls;
  /* This pinned API passes the serialized header as ready_peers. Read actual
   * roster metadata through its public share_write API instead of that pointer.
   */
  (void) ready_peers;
  app.session = NULL; /* official API destroys it after either result callback */
  if (NULL != app.share)
  {
    if ((NULL != share) && (share != app.share))
      GNUNET_SECRETSHARING_share_destroy (share);
    finish (false, "duplicate-generation-callback");
    return;
  }
  app.share = share; /* callback transfers this Share to its caller */
  if (! admit ())
    return;
  if ((NULL == share) || (! check_share (public_key, num_ready_peers)) || app.generated)
  {
    finish (false, "generated-share-mismatch");
    return;
  }
  app.public_key = *public_key;
  app.generated = true;
  event ("GENERATED callback=783 threshold=1 peers=1 local=0 original-index=0 peer=matched");
  if (admit ())
    app.advance_task = GNUNET_SCHEDULER_add_now (&begin_decrypt, NULL);
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
  char line[256];
  bool passed;
  bool live;
  (void) cls;
  if (app.cleaned)
    return;
  app.cleaning = true;
  if (NULL != app.deadline_task)
    GNUNET_SCHEDULER_cancel (app.deadline_task);
  if (NULL != app.advance_task)
    GNUNET_SCHEDULER_cancel (app.advance_task);
  if (NULL != app.stop_task)
    GNUNET_SCHEDULER_cancel (app.stop_task);
  app.deadline_task = app.advance_task = app.stop_task = NULL;
  if (NULL != app.session)
    GNUNET_SECRETSHARING_session_destroy (app.session);
  if (NULL != app.decrypt)
    GNUNET_SECRETSHARING_decrypt_cancel (app.decrypt);
  if (NULL != app.share)
    GNUNET_SECRETSHARING_share_destroy (app.share);
  app.session = NULL;
  app.decrypt = NULL;
  app.share = NULL;
  live = bounds_live ();
  passed = app.decision && app.success && app.generated && app.encrypted
           && app.decrypted && (! app.stdout_failed) && live;
  GNUNET_CRYPTO_zero_keys (&app.expected, sizeof(app.expected));
  GNUNET_CRYPTO_zero_keys (&app.ciphertext, sizeof(app.ciphertext));
  (void) snprintf (line, sizeof(line),
                   "END passed=%s generated=%s encrypted=%s decrypted=%s reason=%s",
                   passed ? "yes" : "no", app.generated ? "yes" : "no",
                   app.encrypted ? "yes" : "no", app.decrypted ? "yes" : "no",
                   native_expired ? "native-deadline"
                   : (! live) ? "original-deadline" : app.reason);
  event (line);
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

static void
run (void *cls, char *const *args, const char *filename,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_HashCode session_id;
  const uint64_t now = GNUNET_TIME_absolute_get ().abs_value_us;
  char line[128];
  (void) cls;
  (void) filename;
  app.cfg = cfg;
  GNUNET_SCHEDULER_add_shutdown (&cleanup, NULL);
  scheduler_ready = 1;
  if ((NULL == args[0]) || (NULL == args[1]) || (NULL == args[2])
      || (NULL != args[3]) || (52 != strlen (args[0]))
      || (GNUNET_OK != GNUNET_CRYPTO_eddsa_public_key_from_string (
            args[0], strlen (args[0]), &app.expected_peer.public_key))
      || (! parse_time (args[1], &app.start.abs_value_us))
      || (! parse_time (args[2], &app.deadline.abs_value_us))
      || (app.start.abs_value_us >= app.deadline.abs_value_us)
      || (now >= app.deadline.abs_value_us)
      || (app.deadline.abs_value_us - now > ORIGINAL_WINDOW_US) || (! admit ()))
  {
    finish (false, "invalid-original-intent");
    return;
  }
  (void) snprintf (line, sizeof(line), "OPEN singleton peer=%s",
                   GNUNET_i2s_full (&app.expected_peer));
  event (line);
  if (! admit ())
    return;
  app.deadline_task = GNUNET_SCHEDULER_add_at (app.deadline, &deadline_reached, NULL);
  GNUNET_CRYPTO_random_block (&session_id, sizeof(session_id));
  if (! admit ())
    return;
  app.session = GNUNET_SECRETSHARING_create_session (
    cfg, 0, NULL, &session_id, app.start, app.deadline, 1, &secret_ready, NULL);
  if (NULL == app.session)
    finish (false, "generate-open-failed");
}

int
main (int argc, char **argv)
{
  const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  enum GNUNET_GenericReturnValue result;
  uint64_t now;
  if ((! native_now (&now)) || (now > UINT64_MAX - ORIGINAL_WINDOW_US))
    return 1;
  app.native_until = now + ORIGINAL_WINDOW_US;
  app.reason = "external-shutdown";
  app.status = 1;
  if ((8 != argc) || (0 != strcmp (argv[1], "-c")) || ('\0' == argv[2][0])
      || (0 != strcmp (argv[3], "-L")) || (0 != strcmp (argv[4], "ERROR")))
  {
    fprintf (stderr,
             "usage: %s -c CONFIG -L ERROR LOCAL_PID52 START_US DEADLINE_US\n", argv[0]);
    return 2;
  }
  if (! arm_watchdog ())
  {
    (void) disarm_watchdog ();
    return 1;
  }
  result = GNUNET_PROGRAM_run (
    GNUNET_OS_project_data_gnunet (), argc, argv, "ss-singleton-client",
    "Actual public-API singleton generation, encryption and decryption", options, &run, NULL);
  if (! disarm_watchdog ())
    return 1;
  return ((GNUNET_OK == result) && app.cleaned) ? app.status : 1;
}
