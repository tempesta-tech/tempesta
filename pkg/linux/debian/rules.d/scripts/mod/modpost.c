#include <elf.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "modpost-opts.h"

int main (int argc, char *argv[])
{
  char const *data, *class;
  char *list_name = NULL;
  char *name = NULL;
  char prog[1024];
  unsigned char ei[EI_NIDENT];
  int opt;
  FILE *file;

  while ((opt = getopt (argc, argv, GETOPT_OPTIONS)) != -1)
  { 
    switch(opt)
    {
      GETOPT_CASE
        break;
      case 'T':
        list_name = optarg;
        break;
      default:
        return EXIT_FAILURE;
    }
  }

  if (optind != argc)
  {
    name = argv[optind];
  }
  else if (list_name)
  {
    size_t name_len;
    int is_stdin = strcmp (list_name, "-") == 0;

    /* Read first line of list file */
    if (is_stdin)
    {
      file = stdin;
      setvbuf(stdin, NULL, _IONBF, 0); /* don't over-read */
    }
    else
    {
      file = fopen (list_name, "r");
      if (!file)
      {
        fprintf (stderr, "Can't open \"%s\"\n", list_name);
        return EXIT_FAILURE;
      }
    }
    if (getline (&name, &name_len, file) < 0)
    {
      if (errno)
      {
        fprintf (stderr, "Can't read \"%s\"\n", list_name);
        return EXIT_FAILURE;
      }
      else
      {
        /* Empty list */
        return EXIT_SUCCESS;
      }
    }
    if (!is_stdin)
      fclose(file);

    /* Remove new-line */
    name [strcspn (name, "\n")] = 0;

    /* If this came from stdin, we need to add the first name to the
     * arguments, because the upstream modpost can't read it again.
     */
    if (is_stdin)
    {
      char **new_argv = malloc (sizeof(*argv) * (argc + 2));
      memcpy(new_argv, argv, sizeof(*argv) * argc);
      new_argv [argc] = name;
      new_argv [argc + 1] = NULL;
      argv = new_argv;
    }
  }
  else
  {
    /* Empty list */
    return EXIT_SUCCESS;
  }

  if (!(file = fopen (name, "r")))
  {
    fprintf (stderr, "Can't open \"%s\"\n", name);
    return EXIT_FAILURE;
  }

  if (fread (ei, 1, EI_NIDENT, file) != EI_NIDENT)
  {
    fprintf (stderr, "Error: input truncated\n");
    return EXIT_FAILURE;
  }

  if (memcmp (ei, ELFMAG, SELFMAG) != 0)
  {
    fprintf (stderr, "Error: not ELF\n");
    return EXIT_FAILURE;
  }
  switch (ei[EI_DATA]) {
    case ELFDATA2LSB:
      data = "lsb";
      break;
    case ELFDATA2MSB:
      data = "msb";
      break;
    default:
      return EXIT_FAILURE;
  }
  switch (ei[EI_CLASS]) {
    case ELFCLASS32:
      class = "32";
      break;
    case ELFCLASS64:
      class = "64";
      break;
    default:
      return EXIT_FAILURE;
  }
  snprintf (prog, sizeof prog, "%s.real-%s-%s", argv[0], data, class);

  return execv (prog, argv);
}
