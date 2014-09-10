/* Get macro information.
   Copyright (C) 2002-2009, 2014 Red Hat, Inc.
   This file is part of elfutils.
   Written by Ulrich Drepper <drepper@redhat.com>, 2002.

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

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <dwarf.h>
#include <string.h>
#include <search.h>

#include <libdwP.h>

#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <stdlib.h>

static int
get_offset_from (Dwarf_Die *die, int name, Dwarf_Word *retp)
{
  /* Get the appropriate attribute.  */
  Dwarf_Attribute attr;
  if (INTUSE(dwarf_attr) (die, name, &attr) == NULL)
    return -1;

  /* Offset into the corresponding section.  */
  return INTUSE(dwarf_formudata) (&attr, retp);
}

static int
macro_op_compare (const void *p1, const void *p2)
{
  const Dwarf_Macro_Op_Table *t1 = (const Dwarf_Macro_Op_Table *) p1;
  const Dwarf_Macro_Op_Table *t2 = (const Dwarf_Macro_Op_Table *) p2;

  if (t1->offset < t2->offset)
    return -1;
  if (t1->offset > t2->offset + t2->read)
    return 1;

  return 0;
}

static void
build_table (Dwarf_Macro_Op_Table *table,
	     Dwarf_Macro_Op_Proto op_protos[static 255])
{
  unsigned ct = 0;
  for (unsigned i = 1; i < 256; ++i)
    if (op_protos[i - 1].forms != NULL)
      table->table[table->opcodes[i - 1] = ct++] = op_protos[i - 1];
    else
      table->opcodes[i] = 0xff;
}

#define MACRO_PROTO(NAME, ...)					\
  Dwarf_Macro_Op_Proto NAME = ({				\
      static const uint8_t proto[] = {__VA_ARGS__};		\
      (Dwarf_Macro_Op_Proto) {sizeof proto, proto};		\
    })

static Dwarf_Macro_Op_Table *
init_macinfo_table (void)
{
  MACRO_PROTO (p_udata_str, DW_FORM_udata, DW_FORM_string);
  MACRO_PROTO (p_udata_udata, DW_FORM_udata, DW_FORM_udata);
  MACRO_PROTO (p_none);

  Dwarf_Macro_Op_Proto op_protos[255] =
    {
      [DW_MACINFO_define - 1] = p_udata_str,
      [DW_MACINFO_undef - 1] = p_udata_str,
      [DW_MACINFO_vendor_ext - 1] = p_udata_str,
      [DW_MACINFO_start_file - 1] = p_udata_udata,
      [DW_MACINFO_end_file - 1] = p_none,
    };

  static Dwarf_Macro_Op_Table table;
  memset (&table, 0, sizeof table);

  build_table (&table, op_protos);
  return &table;
}

static inline Dwarf_Macro_Op_Table *
get_macinfo_table (void)
{
  static Dwarf_Macro_Op_Table *ret = NULL;
  if (unlikely (ret == NULL))
    ret = init_macinfo_table ();
  return ret;
}

static Dwarf_Macro_Op_Table *
get_table_for_offset (Dwarf *dbg, Dwarf_Word macoff,
		      const unsigned char *readp,
		      const unsigned char *const endp)
{
  Dwarf_Macro_Op_Table fake = { .offset = macoff };
  Dwarf_Macro_Op_Table **found = tfind (&fake, &dbg->macro_ops,
					macro_op_compare);
  if (found != NULL)
    return *found;

  const unsigned char *startp = readp;

  /* Request at least 3 bytes for header.  */
  if (readp + 3 > endp)
    {
    invalid_dwarf:
      __libdw_seterrno (DWARF_E_INVALID_DWARF);
      return NULL;
    }

  uint16_t version = read_2ubyte_unaligned_inc (dbg, readp);
  if (version != 4)
    {
      __libdw_seterrno (DWARF_E_INVALID_VERSION);
      return NULL;
    }

  uint8_t flags = *readp++;
  bool is_64bit = (flags & 0x1) != 0;

  Dwarf_Off line_offset = (Dwarf_Off) -1;
  if ((flags & 0x2) != 0)
    {
      line_offset = read_addr_unaligned_inc (is_64bit ? 8 : 4, dbg, readp);
      if (readp > endp)
	goto invalid_dwarf;
    }

  /* """The macinfo entry types defined in this standard may, but
     might not, be described in the table""".

     I.e. these may be present.  It's tempting to simply skip them,
     but it's probably more correct to tolerate that a producer tweaks
     the way certain opcodes are encoded, for whatever reasons.  */

  MACRO_PROTO (p_udata_str, DW_FORM_udata, DW_FORM_string);
  MACRO_PROTO (p_udata_strp, DW_FORM_udata, DW_FORM_strp);
  MACRO_PROTO (p_udata_udata, DW_FORM_udata, DW_FORM_udata);
  MACRO_PROTO (p_secoffset, DW_FORM_sec_offset);
  MACRO_PROTO (p_none);

  Dwarf_Macro_Op_Proto op_protos[255] =
    {
      [DW_MACRO_GNU_define - 1] = p_udata_str,
      [DW_MACRO_GNU_undef - 1] = p_udata_str,
      [DW_MACRO_GNU_define_indirect - 1] = p_udata_strp,
      [DW_MACRO_GNU_undef_indirect - 1] = p_udata_strp,
      [DW_MACRO_GNU_start_file - 1] = p_udata_udata,
      [DW_MACRO_GNU_end_file - 1] = p_none,
      [DW_MACRO_GNU_transparent_include - 1] = p_secoffset,
      /* N.B. DW_MACRO_undef_indirectx, DW_MACRO_define_indirectx
	 should be added when 130313.1 is supported.  */
    };

  if ((flags & 0x4) != 0)
    {
      unsigned count = *readp++;
      for (unsigned i = 0; i < count; ++i)
	{
	  unsigned opcode = *readp++;

	  Dwarf_Macro_Op_Proto e;
	  get_uleb128 (e.nforms, readp); // XXX checking
	  e.forms = readp;
	  op_protos[opcode] = e;

	  readp += e.nforms;
	  if (readp > endp)
	    {
	      __libdw_seterrno (DWARF_E_INVALID_DWARF);
	      return NULL;
	    }
	}
    }

  size_t ct = 0;
  for (unsigned i = 1; i < 256; ++i)
    if (op_protos[i - 1].forms != NULL)
      ++ct;

  /* We support at most 0xfe opcodes defined in the table, as 0xff is
     a value that means that given opcode is not stored at all.  But
     that should be fine, as opcode 0 is not allocated.  */
  assert (ct < 0xff);

  size_t macop_table_size = offsetof (Dwarf_Macro_Op_Table, table[ct]);

  Dwarf_Macro_Op_Table *table = libdw_alloc (dbg, Dwarf_Macro_Op_Table,
					     macop_table_size, 1);

  *table = (Dwarf_Macro_Op_Table) {
    .offset = macoff,
    .line_offset = line_offset,
    .header_len = readp - startp,
    .version = version,
    .is_64bit = is_64bit,
  };
  build_table (table, op_protos);

  Dwarf_Macro_Op_Table **ret = tsearch (table, &dbg->macro_ops,
					macro_op_compare);
  if (unlikely (ret == NULL))
    {
      __libdw_seterrno (DWARF_E_NOMEM);
      return NULL;
    }

  return *ret;
}

static ptrdiff_t
read_macros (Dwarf *dbg, Dwarf_Macro_Op_Table *table, int secindex,
	     Dwarf_Off macoff, int (*callback) (Dwarf_Macro *, void *),
	     void *arg, ptrdiff_t offset)
{
  Elf_Data *d = dbg->sectiondata[secindex];
  if (unlikely (d == NULL || d->d_buf == NULL))
    {
      __libdw_seterrno (DWARF_E_NO_ENTRY);
      return -1;
    }

  if (unlikely (macoff >= d->d_size))
    {
      __libdw_seterrno (DWARF_E_INVALID_DWARF);
      return -1;
    }

  const unsigned char *const startp = d->d_buf + macoff;
  const unsigned char *const endp = d->d_buf + d->d_size;

  if (table == NULL)
    {
      table = get_table_for_offset (dbg, macoff, startp, endp);
      if (table == NULL)
	return -1;
    }

  if (offset == 0)
    offset = table->header_len;

  assert (offset >= 0);
  assert (offset < endp - startp);
  const unsigned char *readp = startp + offset;

  while (readp < endp)
    {
      unsigned int opcode = *readp++;
      if (opcode == 0)
	/* Nothing more to do.  */
	return 0;

      unsigned int idx = table->opcodes[opcode - 1];
      if (idx == 0xff)
	{
	  __libdw_seterrno (DWARF_E_INVALID_OPCODE);
	  return -1;
	}

      Dwarf_Macro_Op_Proto *proto = &table->table[idx];

      /* A fake CU with bare minimum data to fool dwarf_formX into
	 doing the right thing with the attributes that we put
	 out.  */
      Dwarf_CU fake_cu = {
	.dbg = dbg,
	.version = 4,
	.offset_size = table->is_64bit ? 8 : 4,
      };

      Dwarf_Attribute attributes[proto->nforms];
      for (Dwarf_Word i = 0; i < proto->nforms; ++i)
	{
	  /* We pretend this is a DW_AT_GNU_macros attribute so that
	     DW_FORM_sec_offset forms get correctly interpreted as
	     offset into .debug_macro.  */
	  attributes[i].code = DW_AT_GNU_macros;
	  attributes[i].form = proto->forms[i];
	  attributes[i].valp = (void *) readp;
	  attributes[i].cu = &fake_cu;

	  readp += __libdw_form_val_len (dbg, &fake_cu,
					 proto->forms[i], readp);
	}

      Dwarf_Macro macro = {
	.line_offset = table->line_offset,
	.version = table->version,
	.opcode = opcode,
	.nargs = proto->nforms,
	.attributes = attributes,
      };

      Dwarf_Off nread = readp - startp;
      if (nread > table->read)
	table->read = nread;

      if (callback (&macro, arg) != DWARF_CB_OK)
	return readp - startp;
    }

  return 0;
}

static ptrdiff_t
gnu_macros_getmacros_off (Dwarf *dbg, Dwarf_Off macoff,
			  int (*callback) (Dwarf_Macro *, void *),
			  void *arg, ptrdiff_t token)
{
  assert (token <= 0);

  ptrdiff_t ret = read_macros (dbg, NULL, IDX_debug_macro,
			       macoff, callback, arg, -token);
  if (ret == -1)
    return -1;
  else
    return -ret;
}

static ptrdiff_t
macro_info_getmacros_off (Dwarf *dbg, Dwarf_Off macoff,
			  int (*callback) (Dwarf_Macro *, void *),
			  void *arg, ptrdiff_t token)
{
  assert (token >= 0);

  Dwarf_Macro_Op_Table *table = get_macinfo_table ();
  assert (table != NULL);

  return read_macros (dbg, table, IDX_debug_macinfo,
		      macoff, callback, arg, token);
}

ptrdiff_t
dwarf_getmacros_off (Dwarf *dbg, Dwarf_Off macoff,
		     int (*callback) (Dwarf_Macro *, void *),
		     void *arg, ptrdiff_t token)
{
  if (dbg == NULL)
    {
      __libdw_seterrno (DWARF_E_NO_DWARF);
      return -1;
    }

  /* We use token values > 0 for iteration through .debug_macinfo and
     values < 0 for iteration through .debug_macro.  Return value of
     -1 also signifies an error, but that's fine, because .debug_macro
     always contains at least three bytes of headers and after
     iterating one opcode, we should never see anything above -4.  */

  if (token > 0)
    /* A continuation call from DW_AT_macro_info iteration.  */
    return macro_info_getmacros_off (dbg, macoff, callback, arg, token);

  /* Either a DW_AT_GNU_macros continuation, or a fresh start
     thereof.  */
  return gnu_macros_getmacros_off (dbg, macoff, callback, arg, token);
}

ptrdiff_t
dwarf_getmacros_die (Dwarf_Die *cudie, Dwarf_Off *macoffp,
		     int (*callback) (Dwarf_Macro *, void *),
		     void *arg, ptrdiff_t token)
{
  if (cudie == NULL)
    {
      __libdw_seterrno (DWARF_E_NO_DWARF);
      return -1;
    }

  if (token > 0 && macoffp != NULL)
    /* A continuation call from DW_AT_macro_info iteration, meaning
       *MACOFF contains previously-cached offset.  */
    return macro_info_getmacros_off (cudie->cu->dbg, *macoffp,
				     callback, arg, token);

  /* A fresh start of DW_AT_macro_info iteration, or a continuation
     thereof without a cache.  */
  if (token > 0
      || (token == 0 && dwarf_hasattr (cudie, DW_AT_macro_info)))
    {
      Dwarf_Word macoff;
      if (macoffp == NULL)
	macoffp = &macoff;
      if (get_offset_from (cudie, DW_AT_macro_info, macoffp) != 0)
	return -1;
      return macro_info_getmacros_off (cudie->cu->dbg, *macoffp,
				       callback, arg, token);
    }

  if (token < 0 && macoffp != NULL)
    /* A continuation call from DW_AT_GNU_macros iteration.  */
    return gnu_macros_getmacros_off (cudie->cu->dbg, *macoffp,
				     callback, arg, token);

  /* Likewise without cache, or iteration start.  */
  Dwarf_Word macoff;
  if (macoffp == NULL)
    macoffp = &macoff;
  if (get_offset_from (cudie, DW_AT_GNU_macros, macoffp) != 0)
    return -1;
  return gnu_macros_getmacros_off (cudie->cu->dbg, *macoffp,
				   callback, arg, token);
}

ptrdiff_t
dwarf_getmacros (die, callback, arg, offset)
     Dwarf_Die *die;
     int (*callback) (Dwarf_Macro *, void *);
     void *arg;
     ptrdiff_t offset;
{
  if (die == NULL)
    return -1;

  if (offset == 0)
    {
      /* We can't support .debug_macro transparently by
	 dwarf_getmacros, because extant callers would think that the
	 returned macro opcodes come from DW_MACINFO_* domain and be
	 confused.  */
      if (unlikely (! dwarf_hasattr (die, DW_AT_macro_info)))
	{
	  __libdw_seterrno (DWARF_E_NO_ENTRY);
	  return -1;
	}

      /* DIE's with both DW_AT_GNU_macros and DW_AT_macro_info are
	 disallowed by the proposal that DW_AT_GNU_macros support is
	 based on, and this attribute would derail us above, so check
	 for it now.  */
      if (unlikely (dwarf_hasattr (die, DW_AT_GNU_macros)))
	{
	  __libdw_seterrno (DWARF_E_INVALID_DWARF);
	  return -1;
	}
    }
  else
    /* If non-zero, this ought to be a continuation from previous
       DW_AT_macro_info iteration, meaning offset can't be
       negative.  */
    assert (offset > 0);

  /* At this point we can safely piggy-back on existing new-style
     interfaces.  */
  return dwarf_getmacros_die (die, NULL, callback, arg, offset);
}
