/* SPDX-License-Identifier: MPL-2.0 */
/* Public configuration export component; expected official HEAD14698f19848a.
 * The parent binds the actual generated defaults, bootstrap and libraries.
 * No filename normalization, service request or environment mutation is used.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <jansson.h>
#include <gnunet_util_lib.h>

#define MAX_NAME 512U
#define MAX_VALUE 65535U
#define MAX_EXPANDED (1024U * 1024U)
#define MAX_SECTIONS 512U
#define MAX_ENTRIES 16384U
#define MAX_TEXT_BYTES (16U * 1024U * 1024U)
#define MAX_JSON_BYTES (64U * 1024U * 1024U)

struct Export
{
  const struct GNUNET_CONFIGURATION_Handle *cfg;
  json_t *sections;
  size_t entries;
  size_t text_bytes;
  size_t output_bytes;
  int failed;
};
static int status = 1;

static void
collect (void *cls, const char *section, const char *option, const char *value)
{
  struct Export *state = cls;
  json_t *object;
  json_t *string;
  char *expanded;
  size_t section_len, option_len, length, added;

  if (state->failed)
    return;
  section_len = strnlen (section, MAX_NAME + 1U);
  option_len = strnlen (option, MAX_NAME + 1U);
  if ((section_len > MAX_NAME) || (option_len > MAX_NAME)
      || (strnlen (value, MAX_VALUE + 1U) > MAX_VALUE)
      || (state->entries >= MAX_ENTRIES))
  {
    state->failed = 1;
    return;
  }
  expanded = GNUNET_CONFIGURATION_expand_dollar (state->cfg,
                                                 GNUNET_strdup (value));
  if (NULL == expanded)
  {
    state->failed = 1;
    return;
  }
  length = strnlen (expanded, MAX_EXPANDED + 1U);
  added = section_len + option_len + length;
  if ((length > MAX_EXPANDED)
      || (added > MAX_TEXT_BYTES - state->text_bytes))
  {
    GNUNET_free (expanded);
    state->failed = 1;
    return;
  }
  string = json_stringn (expanded, length);
  GNUNET_free (expanded);
  object = json_object_get (state->sections, section);
  if (NULL == object)
  {
    if ((json_object_size (state->sections) >= MAX_SECTIONS)
        || (NULL == (object = json_object ())))
      state->failed = 1;
    else
    {
      if (0 != json_object_set (state->sections, section, object))
        state->failed = 1;
      json_decref (object);
      object = json_object_get (state->sections, section);
    }
  }
  if ((NULL == string) || (NULL == object)
      || (NULL != json_object_get (object, option))
      || (0 != json_object_set (object, option, string)))
    state->failed = 1;
  json_decref (string);
  if (! state->failed)
  {
    ++state->entries;
    state->text_bytes += added;
  }
}

static int
write_json (const char *bytes, size_t length, void *cls)
{
  struct Export *state = cls;
  if ((length > MAX_JSON_BYTES - state->output_bytes)
      || (length != fwrite (bytes, 1, length, stdout)))
    return -1;
  state->output_bytes += length;
  return 0;
}

static void
run (void *cls, char *const *args, const char *filename,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct Export state = { .cfg = cfg, .sections = json_object () };
  (void) cls;
  (void) filename;
  if ((NULL != args[0]) || (NULL == state.sections))
    state.failed = 1;
  else
    GNUNET_CONFIGURATION_iterate (cfg, &collect, &state);
  if ((! state.failed) && (state.entries > 0)
      && (0 == json_dump_callback (state.sections, &write_json, &state,
                                   JSON_SORT_KEYS | JSON_COMPACT))
      && (EOF != fputc ('\n', stdout)) && (0 == fflush (stdout))
      && (! ferror (stdout)))
    status = 0;
  else
    fprintf (stderr, "configuration export failed or exceeded its bounds\n");
  json_decref (state.sections);
  GNUNET_SCHEDULER_shutdown ();
}

int
main (int argc, char **argv)
{
  const struct GNUNET_GETOPT_CommandLineOption options[] = {
    GNUNET_GETOPT_OPTION_END
  };
  if ((5 != argc) || (0 != strcmp (argv[1], "-c")) || ('\0' == argv[2][0])
      || (0 != strcmp (argv[3], "-L")) || (0 != strcmp (argv[4], "ERROR")))
    return 2;
  if (GNUNET_OK != GNUNET_PROGRAM_run (GNUNET_OS_project_data_gnunet (),
                                       argc, argv, "config-dump",
                                       "Export public expanded configuration",
                                       options, &run, NULL))
    return 1;
  return status;
}
