/* Report modules by examining dynamic linker data structures.
   Copyright (C) 2008-2013 Red Hat, Inc.
   This file is part of elfutils.

   This file is free software; you can redistribute it and/or modify
   it under the terms of either

     * the GNU Lesser General Public License as published by the Free
       Software Foundation; either version 3 of the License, or (at
       your option) any later version

   or

     * the GNU General Public License as published by the Free
       Software Foundation; either version 2 of the License, or (at
       your option) any later version

   or both in parallel, as here.

   elfutils is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received copies of the GNU General Public License and
   the GNU Lesser General Public License along with this program.  If
   not, see <http://www.gnu.org/licenses/>.  */

#include <config.h>
#include "libdwflP.h"
#include "../libdw/memory-access.h"

#include <byteswap.h>
#include <endian.h>

/* This element is always provided and always has a constant value.
   This makes it an easy thing to scan for to discern the format.  */
#define PROBE_TYPE	AT_PHENT
#define PROBE_VAL32	sizeof (Elf32_Phdr)
#define PROBE_VAL64	sizeof (Elf64_Phdr)

#if BYTE_ORDER == BIG_ENDIAN
# define BE32(x)	(x)
# define BE64(x)	(x)
# define LE32(x)	bswap_32 (x)
# define LE64(x)	bswap_64 (x)
#else
# define LE32(x)	(x)
# define LE64(x)	(x)
# define BE32(x)	bswap_32 (x)
# define BE64(x)	bswap_64 (x)
#endif


/* Examine an auxv data block and determine its format.
   Return true iff we figured it out.  */
static bool
auxv_format_probe (const void *auxv, size_t size,
		   uint_fast8_t *elfclass, uint_fast8_t *elfdata)
{
  const union
  {
    char buf[size];
    Elf32_auxv_t a32[size / sizeof (Elf32_auxv_t)];
    Elf64_auxv_t a64[size / sizeof (Elf64_auxv_t)];
  } *u = auxv;

  inline bool check64 (size_t i)
  {
    /* The AUXV pointer might not even be naturally aligned for 64-bit
       data, because note payloads in a core file are not aligned.
       But we assume the data is 32-bit aligned.  */

    uint64_t type = read_8ubyte_unaligned_noncvt (&u->a64[i].a_type);
    uint64_t val = read_8ubyte_unaligned_noncvt (&u->a64[i].a_un.a_val);

    if (type == BE64 (PROBE_TYPE)
	&& val == BE64 (PROBE_VAL64))
      {
	*elfdata = ELFDATA2MSB;
	return true;
      }

    if (type == LE64 (PROBE_TYPE)
	&& val == LE64 (PROBE_VAL64))
      {
	*elfdata = ELFDATA2LSB;
	return true;
      }

    return false;
  }

  inline bool check32 (size_t i)
  {
    if (u->a32[i].a_type == BE32 (PROBE_TYPE)
	&& u->a32[i].a_un.a_val == BE32 (PROBE_VAL32))
      {
	*elfdata = ELFDATA2MSB;
	return true;
      }

    if (u->a32[i].a_type == LE32 (PROBE_TYPE)
	&& u->a32[i].a_un.a_val == LE32 (PROBE_VAL32))
      {
	*elfdata = ELFDATA2LSB;
	return true;
      }

    return false;
  }

  for (size_t i = 0; i < size / sizeof (Elf64_auxv_t); ++i)
    {
      if (check64 (i))
	{
	  *elfclass = ELFCLASS64;
	  return true;
	}

      if (check32 (i * 2) || check32 (i * 2 + 1))
	{
	  *elfclass = ELFCLASS32;
	  return true;
	}
    }

  return false;
}

/* This is a Dwfl_Memory_Callback that wraps another memory callback.
   If the underlying callback cannot fill the data, then this will
   fall back to fetching data from module files.  */

struct integrated_memory_callback
{
  Dwfl_Memory_Callback *memory_callback;
  void *memory_callback_arg;
  void *buffer;
};

static bool
integrated_memory_callback (Dwfl *dwfl, int ndx,
			       void **buffer, size_t *buffer_available,
			       GElf_Addr vaddr,
			       size_t minread,
			       void *arg)
{
  struct integrated_memory_callback *info = arg;

  if (ndx == -1)
    {
      /* Called for cleanup.  */
      if (info->buffer != NULL)
	{
	  /* The last probe buffer came from the underlying callback.
	     Let it do its cleanup.  */
	  assert (*buffer == info->buffer); /* XXX */
	  *buffer = info->buffer;
	  info->buffer = NULL;
	  return (*info->memory_callback) (dwfl, ndx, buffer, buffer_available,
					   vaddr, minread,
					   info->memory_callback_arg);
	}
      *buffer = NULL;
      *buffer_available = 0;
      return false;
    }

  if (*buffer != NULL)
    /* For a final-read request, we only use the underlying callback.  */
    return (*info->memory_callback) (dwfl, ndx, buffer, buffer_available,
				     vaddr, minread, info->memory_callback_arg);

  /* Let the underlying callback try to fill this request.  */
  if ((*info->memory_callback) (dwfl, ndx, &info->buffer, buffer_available,
				vaddr, minread, info->memory_callback_arg))
    {
      *buffer = info->buffer;
      return true;
    }

  /* Now look for module text covering this address.  */

  Dwfl_Module *mod;
  (void) INTUSE(dwfl_addrsegment) (dwfl, vaddr, &mod);
  if (mod == NULL)
    return false;

  Dwarf_Addr bias;
  Elf_Scn *scn = INTUSE(dwfl_module_address_section) (mod, &vaddr, &bias);
  if (unlikely (scn == NULL))
    {
#if 0 // XXX would have to handle ndx=-1 cleanup calls passed down.
      /* If we have no sections we can try to fill it from the module file
	 based on its phdr mappings.  */
      if (likely (mod->e_type != ET_REL) && mod->main.elf != NULL)
	return INTUSE(dwfl_elf_phdr_memory_callback)
	  (dwfl, 0, buffer, buffer_available,
	   vaddr - mod->main.bias, minread, mod->main.elf);
#endif
      return false;
    }

  Elf_Data *data = elf_rawdata (scn, NULL);
  if (unlikely (data == NULL))
    // XXX throw error?
    return false;

  if (unlikely (data->d_size < vaddr))
    return false;

  /* Provide as much data as we have.  */
  void *contents = data->d_buf + vaddr;
  size_t avail = data->d_size - vaddr;
  if (unlikely (avail < minread))
    return false;

  /* If probing for a string, make sure it's terminated.  */
  if (minread == 0 && unlikely (memchr (contents, '\0', avail) == NULL))
    return false;

  /* We have it! */
  *buffer = contents;
  *buffer_available = avail;
  return true;
}

static size_t
addrsize (uint_fast8_t elfclass)
{
  return elfclass * 4;
}

/* Report a module for each struct link_map in the linked list at r_map
   in the struct r_debug at R_DEBUG_VADDR.

   For each link_map entry, if an existing module resides at its address,
   this just modifies that module's name and suggested file name.  If
   no such module exists, this calls dwfl_report_elf on the l_name string.

   Returns the number of modules found, or -1 for errors.  */

static int
report_r_debug (uint_fast8_t elfclass, uint_fast8_t elfdata,
		Dwfl *dwfl, GElf_Addr r_debug_vaddr,
		Dwfl_Memory_Callback *memory_callback,
		void *memory_callback_arg)
{
  /* Skip r_version, to aligned r_map field.  */
  GElf_Addr read_vaddr = r_debug_vaddr + addrsize (elfclass);

  void *buffer = NULL;
  size_t buffer_available = 0;
  inline int release_buffer (int result)
  {
    if (buffer != NULL)
      (void) (*memory_callback) (dwfl, -1, &buffer, &buffer_available, 0, 0,
				 memory_callback_arg);
    return result;
  }

  GElf_Addr addrs[4];
  inline bool read_addrs (GElf_Addr vaddr, size_t n)
  {
    size_t nb = n * addrsize (elfclass); /* Address words -> bytes to read.  */

    /* Read a new buffer if the old one doesn't cover these words.  */
    if (buffer == NULL
	|| vaddr < read_vaddr
	|| vaddr - read_vaddr + nb > buffer_available)
      {
	release_buffer (0);

	read_vaddr = vaddr;
	int segndx = INTUSE(dwfl_addrsegment) (dwfl, vaddr, NULL);
	if (unlikely (segndx < 0)
	    || unlikely (! (*memory_callback) (dwfl, segndx,
					       &buffer, &buffer_available,
					       vaddr, nb, memory_callback_arg)))
	  return true;
      }

    const union
    {
      Elf32_Addr a32[n];
      Elf64_Addr a64[n];
    } *in = vaddr - read_vaddr + buffer;

    if (elfclass == ELFCLASS32)
      {
	if (elfdata == ELFDATA2MSB)
	  for (size_t i = 0; i < n; ++i)
	    addrs[i] = BE32 (in->a32[i]);
	else
	  for (size_t i = 0; i < n; ++i)
	    addrs[i] = LE32 (in->a32[i]);
      }
    else
      {
	if (elfdata == ELFDATA2MSB)
	  for (size_t i = 0; i < n; ++i)
	    addrs[i] = BE64 (in->a64[i]);
	else
	  for (size_t i = 0; i < n; ++i)
	    addrs[i] = LE64 (in->a64[i]);
      }

    return false;
  }

  if (unlikely (read_addrs (read_vaddr, 1)))
    return release_buffer (-1);

  GElf_Addr next = addrs[0];

  Dwfl_Module **lastmodp = &dwfl->modulelist;
  int result = 0;

  /* There can't be more elements in the link_map list than there are
     segments.  DWFL->lookup_elts is probably twice that number, so it
     is certainly above the upper bound.  If we iterate too many times,
     there must be a loop in the pointers due to link_map clobberation.  */
  size_t iterations = 0;
  while (next != 0 && ++iterations < dwfl->lookup_elts)
    {
      if (read_addrs (next, 4))
	return release_buffer (-1);

      GElf_Addr l_addr = addrs[0];
      GElf_Addr l_name = addrs[1];
      GElf_Addr l_ld = addrs[2];
      next = addrs[3];

      /* If a clobbered or truncated memory image has no useful pointer,
	 just skip this element.  */
      if (l_ld == 0)
	continue;

      /* Fetch the string at the l_name address.  */
      const char *name = NULL;
      if (buffer != NULL
	  && read_vaddr <= l_name
	  && l_name + 1 - read_vaddr < buffer_available
	  && memchr (l_name - read_vaddr + buffer, '\0',
		     buffer_available - (l_name - read_vaddr)) != NULL)
	name = l_name - read_vaddr + buffer;
      else
	{
	  release_buffer (0);
	  read_vaddr = l_name;
	  int segndx = INTUSE(dwfl_addrsegment) (dwfl, l_name, NULL);
	  if (likely (segndx >= 0)
	      && (*memory_callback) (dwfl, segndx,
				     &buffer, &buffer_available,
				     l_name, 0, memory_callback_arg))
	    name = buffer;
	}

      if (name != NULL && name[0] == '\0')
	name = NULL;

      /* If content-sniffing already reported a module covering
	 the same area, find that existing module to adjust.
	 The l_ld address is the only one we know for sure
	 to be within the module's own segments (its .dynamic).  */
      Dwfl_Module *mod = INTUSE(dwfl_addrmodule) (dwfl, l_ld);
      if (mod != NULL)
	{
	  /* We have a module.  We can give it a better name from l_name.  */
	  if (name != NULL && mod->name[0] == '[')
	    {
	      char *newname = strdup (basename (name));
	      if (newname != NULL)
		{
		  free (mod->name);
		  mod->name = newname;
		}
	    }

	  if (name == NULL && mod->name[0] == '/')
	    name = mod->name;

	  /* If we don't have a file for it already, we can pre-install
	     the full file name from l_name.  Opening the file by this
	     name will be the fallback when no build ID match is found.
	     XXX hook for sysroot */
	  if (name != NULL && mod->main.name == NULL)
	    mod->main.name = strdup (name);
	}
      else if (name != NULL)
	{
	  /* We have to find the file's phdrs to compute along with l_addr
	     what its runtime address boundaries are.  */

	  // XXX hook for sysroot
	  mod = INTUSE(dwfl_report_elf) (dwfl, basename (name),
					 name, -1, l_addr);
	}

      if (mod != NULL)
	{
	  ++result;

	  /* Move this module to the end of the list, so that we end
	     up with a list in the same order as the link_map chain.  */
	  if (mod->next != NULL)
	    {
	      if (*lastmodp != mod)
		{
		  lastmodp = &dwfl->modulelist;
		  while (*lastmodp != mod)
		    lastmodp = &(*lastmodp)->next;
		}
	      *lastmodp = mod->next;
	      mod->next = NULL;
	      while (*lastmodp != NULL)
		lastmodp = &(*lastmodp)->next;
	      *lastmodp = mod;
	    }

	  lastmodp = &mod->next;
	}
    }

  return release_buffer (result);
}

static GElf_Addr
consider_executable (Dwfl_Module *mod, GElf_Addr at_phdr, GElf_Addr at_entry,
		     uint_fast8_t *elfclass, uint_fast8_t *elfdata,
		     Dwfl_Memory_Callback *memory_callback,
		     void *memory_callback_arg)
{
  GElf_Ehdr ehdr;
  if (unlikely (gelf_getehdr (mod->main.elf, &ehdr) == NULL))
    return 0;

  if (at_entry != 0)
    {
      /* If we have an AT_ENTRY value, reject this executable if
	 its entry point address could not have supplied that.  */

      if (ehdr.e_entry == 0)
	return 0;

      if (mod->e_type == ET_EXEC)
	{
	  if (ehdr.e_entry != at_entry)
	    return 0;
	}
      else
	{
	  /* It could be a PIE.  */
	}
    }

  // XXX this could be saved in the file cache: phdr vaddr, DT_DEBUG d_val vaddr
  /* Find the vaddr of the DT_DEBUG's d_ptr.  This is the memory
     address where &r_debug was written at runtime.  */
  GElf_Xword align = mod->dwfl->segment_align;
  GElf_Addr d_val_vaddr = 0;
  for (uint_fast16_t i = 0; i < ehdr.e_phnum; ++i)
    {
      GElf_Phdr phdr_mem;
      GElf_Phdr *phdr = gelf_getphdr (mod->main.elf, i, &phdr_mem);
      if (phdr == NULL)
	break;

      if (phdr->p_align > 1 && (align == 0 || phdr->p_align < align))
	align = phdr->p_align;

      if (at_phdr != 0
	  && phdr->p_type == PT_LOAD
	  && (phdr->p_offset & -align) == (ehdr.e_phoff & -align))
	{
	  /* This is the segment that would map the phdrs.
	     If we have an AT_PHDR value, reject this executable
	     if its phdr mapping could not have supplied that.  */
	  if (mod->e_type == ET_EXEC)
	    {
	      if (ehdr.e_phoff - phdr->p_offset + phdr->p_vaddr != at_phdr)
		return 0;
	    }
	  else
	    {
	      /* It could be a PIE.  If the AT_PHDR value and our
		 phdr address don't match modulo ALIGN, then this
		 could not have been the right PIE.  */
	      if (((ehdr.e_phoff - phdr->p_offset + phdr->p_vaddr) & -align)
		  != (at_phdr & -align))
		return 0;

	      /* Calculate the bias applied to the PIE's p_vaddr values.  */
	      GElf_Addr bias = (at_phdr - (ehdr.e_phoff - phdr->p_offset
					   + phdr->p_vaddr));

	      /* Final sanity check: if we have an AT_ENTRY value,
		 reject this PIE unless its biased e_entry matches.  */
	      if (at_entry != 0 && at_entry != ehdr.e_entry + bias)
		return 0;

	      /* If we're changing the module's address range,
		 we've just invalidated the module lookup table.  */
	      GElf_Addr mod_bias = dwfl_adjusted_address (mod, 0);
	      if (bias != mod_bias)
		{
		  mod->low_addr -= mod_bias;
		  mod->high_addr -= mod_bias;
		  mod->low_addr += bias;
		  mod->high_addr += bias;

		  free (mod->dwfl->lookup_module);
		  mod->dwfl->lookup_module = NULL;
		}
	    }
	}

      if (phdr->p_type == PT_DYNAMIC)
	{
	  Elf_Data *data = elf_getdata_rawchunk (mod->main.elf, phdr->p_offset,
						 phdr->p_filesz, ELF_T_DYN);
	  if (data == NULL)
	    continue;
	  const size_t entsize = gelf_fsize (mod->main.elf,
					     ELF_T_DYN, 1, EV_CURRENT);
	  const size_t n = data->d_size / entsize;
	  for (size_t j = 0; j < n; ++j)
	    {
	      GElf_Dyn dyn_mem;
	      GElf_Dyn *dyn = gelf_getdyn (data, j, &dyn_mem);
	      if (dyn != NULL && dyn->d_tag == DT_DEBUG)
		{
		  d_val_vaddr = phdr->p_vaddr + entsize * j + entsize / 2;
		  break;
		}
	    }
	}
    }

  if (d_val_vaddr != 0)
    {
      /* Now we have the final address from which to read &r_debug.  */
      d_val_vaddr = dwfl_adjusted_address (mod, d_val_vaddr);

      void *buffer = NULL;
      size_t buffer_available = addrsize (ehdr.e_ident[EI_CLASS]);

      int segndx = INTUSE(dwfl_addrsegment) (mod->dwfl, d_val_vaddr, NULL);

      if ((*memory_callback) (mod->dwfl, segndx,
			      &buffer, &buffer_available,
			      d_val_vaddr, buffer_available,
			      memory_callback_arg))
	{
	  const union
	  {
	    Elf32_Addr a32;
	    Elf64_Addr a64;
	  } *u = buffer;

	  GElf_Addr vaddr;
	  if (ehdr.e_ident[EI_CLASS] == ELFCLASS32)
	    vaddr = (ehdr.e_ident[EI_DATA] == ELFDATA2MSB
		     ? BE32 (u->a32) : LE32 (u->a32));
	  else
	    vaddr = (ehdr.e_ident[EI_DATA] == ELFDATA2MSB
		     ? BE64 (u->a64) : LE64 (u->a64));

	  (*memory_callback) (mod->dwfl, -1, &buffer, &buffer_available, 0, 0,
			      memory_callback_arg);

	  if (*elfclass == ELFCLASSNONE)
	    *elfclass = ehdr.e_ident[EI_CLASS];
	  else if (*elfclass != ehdr.e_ident[EI_CLASS])
	    return 0;

	  if (*elfdata == ELFDATANONE)
	    *elfdata = ehdr.e_ident[EI_DATA];
	  else if (*elfdata != ehdr.e_ident[EI_DATA])
	    return 0;

	  return vaddr;
	}
    }

  return 0;
}

/* Try to find an existing executable module with a DT_DEBUG.  */
static GElf_Addr
find_executable (Dwfl *dwfl, GElf_Addr at_phdr, GElf_Addr at_entry,
		 uint_fast8_t *elfclass, uint_fast8_t *elfdata,
		 Dwfl_Memory_Callback *memory_callback,
		 void *memory_callback_arg)
{
  for (Dwfl_Module *mod = dwfl->modulelist; mod != NULL; mod = mod->next)
    if (mod->main.elf != NULL)
      {
	GElf_Addr r_debug_vaddr = consider_executable (mod, at_phdr, at_entry,
						       elfclass, elfdata,
						       memory_callback,
						       memory_callback_arg);
	if (r_debug_vaddr != 0)
	  return r_debug_vaddr;
      }

  return 0;
}


int
dwfl_link_map_report (Dwfl *dwfl, const void *auxv, size_t auxv_size,
		      Dwfl_Memory_Callback *memory_callback,
		      void *memory_callback_arg)
{
  GElf_Addr r_debug_vaddr = 0;

  uint_fast8_t elfclass = ELFCLASSNONE;
  uint_fast8_t elfdata = ELFDATANONE;
  if (likely (auxv != NULL)
      && likely (auxv_format_probe (auxv, auxv_size, &elfclass, &elfdata)))
    {
      GElf_Addr entry = 0;
      GElf_Addr phdr = 0;
      GElf_Xword phent = 0;
      GElf_Xword phnum = 0;

#define READ_AUXV32(ptr)	read_4ubyte_unaligned_noncvt (ptr)
#define READ_AUXV64(ptr)	read_8ubyte_unaligned_noncvt (ptr)
#define AUXV_SCAN(NN, BL) do                                            \
	{                                                               \
	  const Elf##NN##_auxv_t *av = auxv;                            \
	  for (size_t i = 0; i < auxv_size / sizeof av[0]; ++i)         \
	    {                                                           \
              uint##NN##_t type = READ_AUXV##NN (&av[i].a_type);        \
              uint##NN##_t val = BL##NN (READ_AUXV##NN (&av[i].a_un.a_val)); \
	      if (type == BL##NN (AT_ENTRY))                            \
		entry = val;                                            \
	      else if (type == BL##NN (AT_PHDR))                        \
		phdr = val;                                             \
	      else if (type == BL##NN (AT_PHNUM))                       \
		phnum = val;                                            \
	      else if (type == BL##NN (AT_PHENT))                       \
		phent = val;                                            \
	      else if (type == BL##NN (AT_PAGESZ))                      \
		{                                                       \
		  if (val > 1                                           \
		      && (dwfl->segment_align == 0                      \
			  || val < dwfl->segment_align))                \
		    dwfl->segment_align = val;                          \
		}                                                       \
	    }                                                           \
	}                                                               \
      while (0)

      if (elfclass == ELFCLASS32)
	{
	  if (elfdata == ELFDATA2MSB)
	    AUXV_SCAN (32, BE);
	  else
	    AUXV_SCAN (32, LE);
	}
      else
	{
	  if (elfdata == ELFDATA2MSB)
	    AUXV_SCAN (64, BE);
	  else
	    AUXV_SCAN (64, LE);
	}

      /* If we found the phdr dimensions, search phdrs for PT_DYNAMIC.  */
      GElf_Addr dyn_vaddr = 0;
      GElf_Xword dyn_filesz = 0;
      GElf_Addr dyn_bias = (GElf_Addr) -1;

      inline bool consider_phdr (GElf_Word type,
				 GElf_Addr vaddr, GElf_Xword filesz)
      {
	switch (type)
	  {
	  case PT_PHDR:
	    if (dyn_bias == (GElf_Addr) -1
		/* Do a sanity check on the putative address.  */
		&& ((vaddr & (dwfl->segment_align - 1))
		    == (phdr & (dwfl->segment_align - 1))))
	      {
		dyn_bias = phdr - vaddr;
		return dyn_vaddr != 0;
	      }
	    break;

	  case PT_DYNAMIC:
	    dyn_vaddr = vaddr;
	    dyn_filesz = filesz;
	    return dyn_bias != (GElf_Addr) -1;
	  }

	return false;
      }

      if (phdr != 0 && phnum != 0)
	{
	  Dwfl_Module *phdr_mod;
	  int phdr_segndx = INTUSE(dwfl_addrsegment) (dwfl, phdr, &phdr_mod);
	  Elf_Data in =
	    {
	      .d_type = ELF_T_PHDR,
	      .d_version = EV_CURRENT,
	      .d_size = phnum * phent,
	      .d_buf = NULL
	    };
	  if ((*memory_callback) (dwfl, phdr_segndx, &in.d_buf, &in.d_size,
				  phdr, phnum * phent, memory_callback_arg))
	    {
	      union
	      {
		Elf32_Phdr p32;
		Elf64_Phdr p64;
		char data[phnum * phent];
	      } buf;
	      Elf_Data out =
		{
		  .d_type = ELF_T_PHDR,
		  .d_version = EV_CURRENT,
		  .d_size = phnum * phent,
		  .d_buf = &buf
		};
	      in.d_size = out.d_size;
	      if (likely ((elfclass == ELFCLASS32
			   ? elf32_xlatetom : elf64_xlatetom)
			  (&out, &in, elfdata) != NULL))
		{
		  /* We are looking for PT_DYNAMIC.  */
		  const union
		  {
		    Elf32_Phdr p32[phnum];
		    Elf64_Phdr p64[phnum];
		  } *u = (void *) &buf;
		  if (elfclass == ELFCLASS32)
		    {
		      for (size_t i = 0; i < phnum; ++i)
			if (consider_phdr (u->p32[i].p_type,
					   u->p32[i].p_vaddr,
					   u->p32[i].p_filesz))
			  break;
		    }
		  else
		    {
		      for (size_t i = 0; i < phnum; ++i)
			if (consider_phdr (u->p64[i].p_type,
					   u->p64[i].p_vaddr,
					   u->p64[i].p_filesz))
			  break;
		    }
		}

	      (*memory_callback) (dwfl, -1, &in.d_buf, &in.d_size, 0, 0,
				  memory_callback_arg);
	    }
	  else
	    /* We could not read the executable's phdrs from the
	       memory image.  If we have a presupplied executable,
	       we can still use the AT_PHDR and AT_ENTRY values to
	       verify it, and to adjust its bias if it's a PIE.

	       If there was an ET_EXEC module presupplied that contains
	       the AT_PHDR address, then we only consider that one.
	       We'll either accept it if its phdr location and e_entry
	       make sense or reject it if they don't.  If there is no
	       presupplied ET_EXEC, then look for a presupplied module,
	       which might be a PIE (ET_DYN) that needs its bias adjusted.  */
	    r_debug_vaddr = ((phdr_mod == NULL
			      || phdr_mod->main.elf == NULL
			      || phdr_mod->e_type != ET_EXEC)
			     ? find_executable (dwfl, phdr, entry,
						&elfclass, &elfdata,
						memory_callback,
						memory_callback_arg)
			     : consider_executable (phdr_mod, phdr, entry,
						    &elfclass, &elfdata,
						    memory_callback,
						    memory_callback_arg));
	}

      /* If we found PT_DYNAMIC, search it for DT_DEBUG.  */
      if (dyn_filesz != 0)
	{
	  if (dyn_bias != (GElf_Addr) -1)
	    dyn_vaddr += dyn_bias;

	  Elf_Data in =
	    {
	      .d_type = ELF_T_DYN,
	      .d_version = EV_CURRENT,
	      .d_size = dyn_filesz,
	      .d_buf = NULL
	    };
	  int dyn_segndx = dwfl_addrsegment (dwfl, dyn_vaddr, NULL);
	  if ((*memory_callback) (dwfl, dyn_segndx, &in.d_buf, &in.d_size,
				  dyn_vaddr, dyn_filesz, memory_callback_arg))
	    {
	      union
	      {
		Elf32_Dyn d32;
		Elf64_Dyn d64;
		char data[dyn_filesz];
	      } buf;
	      Elf_Data out =
		{
		  .d_type = ELF_T_DYN,
		  .d_version = EV_CURRENT,
		  .d_size = dyn_filesz,
		  .d_buf = &buf
		};
	      in.d_size = out.d_size;
	      if (likely ((elfclass == ELFCLASS32
			   ? elf32_xlatetom : elf64_xlatetom)
			  (&out, &in, elfdata) != NULL))
		{
		  /* We are looking for DT_DEBUG.  */
		  const union
		  {
		    Elf32_Dyn d32[dyn_filesz / sizeof (Elf32_Dyn)];
		    Elf64_Dyn d64[dyn_filesz / sizeof (Elf64_Dyn)];
		  } *u = (void *) &buf;
		  if (elfclass == ELFCLASS32)
		    {
		      size_t n = dyn_filesz / sizeof (Elf32_Dyn);
		      for (size_t i = 0; i < n; ++i)
			if (u->d32[i].d_tag == DT_DEBUG)
			  {
			    r_debug_vaddr = u->d32[i].d_un.d_val;
			    break;
			  }
		    }
		  else
		    {
		      size_t n = dyn_filesz / sizeof (Elf64_Dyn);
		      for (size_t i = 0; i < n; ++i)
			if (u->d64[i].d_tag == DT_DEBUG)
			  {
			    r_debug_vaddr = u->d64[i].d_un.d_val;
			    break;
			  }
		    }
		}

	      (*memory_callback) (dwfl, -1, &in.d_buf, &in.d_size, 0, 0,
				  memory_callback_arg);
	    }
	}
    }
  else
    /* We have to look for a presupplied executable file to determine
       the vaddr of its dynamic section and DT_DEBUG therein.  */
    r_debug_vaddr = find_executable (dwfl, 0, 0, &elfclass, &elfdata,
				     memory_callback, memory_callback_arg);

  if (r_debug_vaddr == 0)
    return 0;

  /* For following pointers from struct link_map, we will use an
     integrated memory access callback that can consult module text
     elided from the core file.  This is necessary when the l_name
     pointer for the dynamic linker's own entry is a pointer into the
     executable's .interp section.  */
  struct integrated_memory_callback mcb =
    {
      .memory_callback = memory_callback,
      .memory_callback_arg = memory_callback_arg
    };

  /* Now we can follow the dynamic linker's library list.  */
  return report_r_debug (elfclass, elfdata, dwfl, r_debug_vaddr,
			 &integrated_memory_callback, &mcb);
}
INTDEF (dwfl_link_map_report)
