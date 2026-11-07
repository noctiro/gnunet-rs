/* Normal public C library, unchanged. Only this test caller is compiled. */
#include "platform.h"
#include "gnunet_util_lib.h"
static const char *output;
static int tracked_fd = -1;
static const struct GNUNET_MQ_MessageHandler handlers[] = {
  GNUNET_MQ_handler_end ()
};
static void
trace (const char *event, int result)
{
  FILE *f = fopen (output, "a");
  if (! f)
    _exit (11);
  fprintf (f,
           "{\"event\":\"%s\",\"result\":%d,\"pid\":%d,"
           "\"tracked_fd_open\":%s,\"ids\":[%u,%u,%u,%u]}\n",
           event, result, (int) getpid (),
           ((tracked_fd >= 0) && (fcntl (tracked_fd, F_GETFD) >= 0))
           ? "true" : "false",
           (unsigned) getuid (), (unsigned) geteuid (),
           (unsigned) getgid (), (unsigned) getegid ());
  fclose (f);
}
static void
init (void *cls, const struct GNUNET_CONFIGURATION_Handle *cfg,
      struct GNUNET_SERVICE_Handle *service)
{
  (void) cls;
  (void) cfg;
  (void) service;
  trace ("init", 0);
  GNUNET_SCHEDULER_shutdown ();
}
int
main (int argc, char **argv)
{
  if (argc < 3)
    return 2;
  output = argv[1];
  const char *mode = argv[2];
  const char *declared = getenv ("LISTEN_FDNAMES");
  if (declared)
    tracked_fd = atoi (declared); /* Test caller only: fixture offers one fd. */
  if (0 == strcmp (mode, "box"))
  {
    if (argc != 4)
      return 2;
    int fd = atoi (argv[3]);
    struct GNUNET_NETWORK_Handle *h = GNUNET_NETWORK_socket_box_native (fd);
    if (! h)
    {
      trace ("box-refused", -1);
      return 3;
    }
    int ret = GNUNET_NETWORK_socket_close (h);
    trace ("box-closed", ret);
    return ret == GNUNET_OK ? 0 : 4;
  }
  if (argc < 4)
    return 2;
  trace ("before", 0);
  char *service_argv[5] = { argv[0], "-c", argv[3], NULL, NULL };
  int service_argc = 3;
  if ((argc > 4) && (0 == strcmp (argv[4], "daemon")))
  {
    service_argv[3] = "-d";
    service_argc = 4;
  }
  int ret = GNUNET_SERVICE_run_ (
    GNUNET_OS_project_data_gnunet (), service_argc, service_argv, "probe",
    ! strcmp (mode, "close") ? GNUNET_SERVICE_OPTION_CLOSE_LSOCKS
                            : GNUNET_SERVICE_OPTION_NONE,
    &init, NULL, NULL, NULL, handlers);
  trace ("returned", ret);
  return ret == 0 ? 0 : 10;
}
