/* SPDX-License-Identifier: MPL-2.0 */
/* Public-API client for the unchanged official C Messenger library. It owns
 * no service, codec, port acknowledgement or peer algorithm. Only fixed probe
 * text is sent; stdout contains public identities and bounded event metadata.
 */
#include <gnunet_util_lib.h>
#include <gnunet_messenger_service.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static struct GNUNET_MESSENGER_Handle *handle;
static struct GNUNET_MESSENGER_Room *room;
static union GNUNET_MESSENGER_RoomKey key;
static struct GNUNET_PeerIdentity previous;
static struct GNUNET_SCHEDULER_Task *timeout_task;
static unsigned int peers;
static unsigned int texts;
static bool output_failed;
static bool cleaned;
static const char *const probes[] = {
  "messenger-identity-private-phase-1",
  "messenger-identity-private-phase-2",
  "messenger-identity-private-phase-3"
};

static void
cleanup (void *cls)
{
  (void) cls;
  if (timeout_task)
  {
    GNUNET_SCHEDULER_cancel (timeout_task);
    timeout_task = NULL;
  }
  if (handle)
  {
    GNUNET_MESSENGER_disconnect (handle);
    handle = NULL;
  }
  cleaned = true;
}

static void
timeout (void *cls)
{
  (void) cls;
  timeout_task = NULL;
  GNUNET_SCHEDULER_shutdown ();
}

static void
message (void *cls,
         struct GNUNET_MESSENGER_Room *actual_room,
         const struct GNUNET_MESSENGER_Contact *sender,
         const struct GNUNET_MESSENGER_Contact *recipient,
         const struct GNUNET_MESSENGER_Message *value,
         const struct GNUNET_HashCode *hash,
         enum GNUNET_MESSENGER_MessageFlags flags)
{
  (void) cls;
  (void) sender;
  (void) recipient;
  (void) hash;
  (void) flags;
  if (GNUNET_MESSENGER_KIND_PEER == value->header.kind)
  {
    const struct GNUNET_PeerIdentity *peer = &value->body.peer.peer;
    struct GNUNET_MESSENGER_Message text;
    if (peers && (0 == memcmp (&previous, peer, sizeof(previous))))
      return;
    if (peers >= 3)
    {
      GNUNET_SCHEDULER_shutdown ();
      return;
    }
    previous = *peer;
    peers++;
    if ((0 > printf ("PEER %u %s\n", peers, GNUNET_i2s_full (peer)))
        || (0 != fflush (stdout)))
      output_failed = true;
    if (peers > 1)
    {
      /* The public API always submits an OPEN, even for this same room handle.
       * Its normal reply is observed in the unchanged library's DEBUG handler.
       */
      if (GNUNET_MESSENGER_open_room (handle, &key) != actual_room)
      {
        GNUNET_SCHEDULER_shutdown ();
        return;
      }
      if ((0 > printf ("REOPEN_CALL %u\n", peers)) || (0 != fflush (stdout)))
        output_failed = true;
    }
    memset (&text, 0, sizeof(text));
    text.header.kind = GNUNET_MESSENGER_KIND_TEXT;
    text.body.text.text = (char *) probes[peers - 1];
    GNUNET_MESSENGER_send_message (actual_room, &text, NULL);
  }
  else if (GNUNET_MESSENGER_KIND_TEXT == value->header.kind)
  {
    for (unsigned int i = 0; i < 3; ++i)
      if ((0 == strcmp (value->body.text.text, probes[i]))
          && (! (texts & (1U << i))))
      {
        texts |= 1U << i;
        if ((0 > printf ("TEXT_CALLBACK %u\n", i + 1)) || (0 != fflush (stdout)))
          output_failed = true;
      }
  }
  else if (GNUNET_MESSENGER_KIND_MISS == value->header.kind)
  {
    if ((0 > printf ("MISS %s\n", GNUNET_i2s_full (&value->body.miss.peer)))
        || (0 != fflush (stdout)))
      output_failed = true;
  }
  if (output_failed)
    GNUNET_SCHEDULER_shutdown ();
}

static void
run (void *cls, char *const *args, const char *configfile,
     const struct GNUNET_CONFIGURATION_Handle *config)
{
  (void) cls;
  (void) configfile;
  GNUNET_SCHEDULER_add_shutdown (&cleanup, NULL);
  timeout_task = GNUNET_SCHEDULER_add_delayed (
    GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 25), &timeout, NULL);
  if (args[0])
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  GNUNET_MESSENGER_create_room_key (&key, "messenger-identity-port-lifecycle",
                                     GNUNET_YES, GNUNET_YES, GNUNET_NO);
  handle = GNUNET_MESSENGER_connect (config, NULL, NULL, NULL, &message, NULL);
  if (! handle)
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  room = GNUNET_MESSENGER_open_room (handle, &key);
  if (! room)
    GNUNET_SCHEDULER_shutdown ();
}

int
main (int argc, char **argv)
{
  const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  enum GNUNET_GenericReturnValue result = GNUNET_PROGRAM_run (
    GNUNET_OS_project_data_gnunet (), argc, argv, "messenger-identity-client",
    "Actual official C Messenger API over one original local MQ", options, &run, NULL);
  return ((GNUNET_OK == result) && cleaned && !output_failed
          && (3 == peers) && (7 == texts)) ? 0 : 1;
}
