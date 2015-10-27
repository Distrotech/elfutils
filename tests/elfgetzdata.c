/* Copyright (C) 2015 Red Hat, Inc.
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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libelf.h>
#include <gelf.h>
#include <stdio.h>
#include <unistd.h>


int
main (int argc, char *argv[])
{
  int result = 0;
  int cnt;

  elf_version (EV_CURRENT);

  for (cnt = 1; cnt < argc; ++cnt)
    {
      int fd = open (argv[cnt], O_RDONLY);

      Elf *elf = elf_begin (fd, ELF_C_READ, NULL);
      if (elf == NULL)
	{
	  printf ("%s not usable %s\n", argv[cnt], elf_errmsg (-1));
	  result = 1;
	  close (fd);
	  continue;
	}

      /* To get the section names.  */
      size_t strndx;
      elf_getshdrstrndx (elf, &strndx);

      Elf_Scn *scn = NULL;
      while ((scn = elf_nextscn (elf, scn)) != NULL)
	{
	  size_t idx = elf_ndxscn (scn);
	  GElf_Shdr mem;
	  GElf_Shdr *shdr = gelf_getshdr (scn, &mem);
	  const char *name = elf_strptr (elf, strndx, shdr->sh_name);
	  if ((shdr->sh_flags & SHF_COMPRESSED) != 0)
	    {
	      /* Real compressed section.  */
	      if (gelf_zscn_compress (scn, &mem, ELF_ZSCN_T_NONE, 0) == NULL)
		{
		  printf ("gelf_zscn_compress failed for section %zd: %s\n",
			  idx, elf_errmsg (-1));
		  return -1;
		}
	      Elf_Data *d = elf_getdata (scn, NULL);
	      printf ("%zd: %s, ELF compressed, size: %zx\n",
		      idx, name, d->d_size);
	    }
	  else
	    {
	      /* Maybe an old GNU compressed .z section?  */
	      if (name[0] == '.' && name[1] == 'z')
		{
		  if (gelf_zscn_compress (scn, &mem, ELF_ZSCN_T_NONE,
					  0) == NULL)
		    {
		      printf ("gelf_zscn_compress failed for section %zd: %s\n",
			      idx, elf_errmsg (-1));
		      return -1;
		    }
		  Elf_Data *d = elf_getdata (scn, NULL);
		  printf ("%zd: %s, GNU compressed, size: %zx\n",
			  idx, name, d->d_size);
		}
	      else
		{
		  /* Assume not compressed.  */
		  if (gelf_zscn_compress (scn, &mem, ELF_ZSCN_T_NONE,
					  0) != NULL)
		    printf ("%zd: %s, ERROR compressed\n",
			    idx, name);
		  else
		    printf ("%zd: %s, NOT compressed\n", idx, name);
		}
	    }
	}

      elf_end (elf);
      close (fd);
    }

  return result;
}
