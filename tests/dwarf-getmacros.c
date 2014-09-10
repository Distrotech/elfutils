/* Test program for dwarf_getmacros and related
   Copyright (C) 2009, 2014 Red Hat, Inc.
   This file is part of elfutils.

   This file is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   elfutils is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include <config.h>
#include ELFUTILS_HEADER(dw)
#include <dwarf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>

static void include (Dwarf *dbg, Dwarf_Off macoff, ptrdiff_t token);

static int
mac (Dwarf_Macro *macro, void *dbg)
{
  static int level = 0;
  unsigned int version = -1U;
  dwarf_macro_version (macro, &version);
  assert (version != -1U);

  unsigned int opcode;
  dwarf_macro_opcode (macro, &opcode);

  if (version == 4 && opcode == DW_MACRO_GNU_transparent_include)
    {
      Dwarf_Attribute at;
      int r = dwarf_macro_param (macro, 0, &at);
      assert (r == 0);

      Dwarf_Word w;
      r = dwarf_formudata (&at, &w);
      assert (r == 0);

      printf ("%*sinclude %#" PRIx64 "\n", level, "", w);
      ++level;
      include (dbg, w, 0);
      --level;
      printf ("%*s/include\n", level, "");
    }
  else if ((version == 4 && opcode == DW_MACRO_GNU_define_indirect)
	   || (version == 0 && opcode == DW_MACINFO_define))
    {
      const char *value;
      dwarf_macro_param2 (macro, NULL, &value);
      printf ("%*s%s\n", level, "", value);
    }

  return DWARF_CB_ABORT;
}

static void
include (Dwarf *dbg, Dwarf_Off macoff, ptrdiff_t token)
{
  while ((token = dwarf_getmacros_off (dbg, macoff, mac, dbg, token)) != 0)
    if (token == -1)
      {
	puts (dwarf_errmsg (dwarf_errno ()));
	break;
      }
}

int
main (int argc __attribute__ ((unused)), char *argv[])
{
  const char *name = argv[1];
  ptrdiff_t cuoff = strtol (argv[2], NULL, 0);

  int fd = open (name, O_RDONLY);
  Dwarf *dbg = dwarf_begin (fd, DWARF_C_READ);

  Dwarf_Die cudie_mem, *cudie = dwarf_offdie (dbg, cuoff, &cudie_mem);

  {
    puts ("--dwarf_getmacros--");
    ptrdiff_t off = 0;
    while ((off = dwarf_getmacros (cudie, mac, dbg, off)) > 0)
      ;
  }

  puts ("--dwarf_getmacros_die w/o cache--");
  for (ptrdiff_t off = 0;
       (off = dwarf_getmacros_die (cudie, NULL, mac, dbg, off)); )
    if (off == -1)
      {
	puts (dwarf_errmsg (dwarf_errno ()));
	break;
      }

  puts ("--dwarf_getmacros_die w/ cache--");
  {
    Dwarf_Off macoff;
    ptrdiff_t off = dwarf_getmacros_die (cudie, &macoff, mac, dbg, 0);
    include (dbg, macoff, off);
  }

  return 0;
}
