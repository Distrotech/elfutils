/* Pedantic checking of DWARF files
   Copyright (C) 2010 Red Hat, Inc.
   This file is part of Red Hat elfutils.

   Red Hat elfutils is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by the
   Free Software Foundation; version 2 of the License.

   Red Hat elfutils is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with Red Hat elfutils; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301 USA.

   Red Hat elfutils is an included package of the Open Invention Network.
   An included package of the Open Invention Network is a package for which
   Open Invention Network licensees cross-license their patents.  No patent
   license is granted, either expressly or impliedly, by designation as an
   included package.  Should you wish to participate in the Open Invention
   Network licensing program, please visit www.openinventionnetwork.com
   <http://www.openinventionnetwork.com>.  */

#include "dwarf_version-imp.hh"
#include "dwarf_3.hh"
#include "dwarf_4.hh"
#include "../libdw/dwarf.h"

namespace
{
  struct dwarf_4_attributes
    : public attribute_table
  {
    dwarf_4_attributes ()
    {
      add (attribute (DW_AT_high_pc, dw_class_set (cl_address, cl_constant)));
      add (ref_attribute (DW_AT_namelist_item));
      add (ref_attribute (DW_AT_signature));
      add (flag_attribute (DW_AT_main_subprogram));
      add (const_attribute (DW_AT_data_bit_offset));
      add (flag_attribute (DW_AT_const_expr));
      add (flag_attribute (DW_AT_enum_class));
      add (string_attribute (DW_AT_linkage_name));
    }
  };

  struct exprloc_form
    : public preset_form<sc_block, cl_exprloc>
  {
    exprloc_form (int a_name)
      : preset_form<sc_block, cl_exprloc> (a_name, fw_uleb)
    {}
  };

  struct dwarf_4_forms
    : public form_table
  {
    dwarf_4_forms ()
    {
      add (const_form (DW_FORM_data4, fw_4));
      add (const_form (DW_FORM_data8, fw_8));
      add (offset_form (DW_FORM_sec_offset,
			dw_class_set (cl_lineptr, cl_loclistptr,
				      cl_macptr, cl_rangelistptr)));
      add (exprloc_form (DW_FORM_exprloc));
      add (flag_form (DW_FORM_flag_present, fw_0));
      add (ref_form (DW_FORM_ref_sig8, fw_8));

      // In DWARF 2 we claim that blocks are exprloc forms (see
      // comment there).  Revert back to pure blocks now that we have
      // proper support for cl_exprloc.
      add (block_form (DW_FORM_block, fw_uleb));
      add (block_form (DW_FORM_block1, fw_1));
      add (block_form (DW_FORM_block2, fw_2));
      add (block_form (DW_FORM_block4, fw_4));
    }
  };

  struct dwarf_4_ext_t
    : public std_dwarf
  {
    dwarf_4_ext_t ()
      : std_dwarf (dwarf_4_attributes (), dwarf_4_forms ())
    {}
  };
}

dwarf_version const *
dwarf_4_ext ()
{
  static dwarf_4_ext_t dw;
  return &dw;
}

dwarf_version const *
dwarf_4 ()
{
  static dwarf_version const *dw =
    dwarf_version::extend (dwarf_3 (), dwarf_4_ext ());
  return dw;
}
