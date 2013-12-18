#! /bin/bash
# Copyright (C) 2013 Red Hat, Inc.
# This file is part of elfutils.
#
# This file is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# elfutils is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

. $srcdir/test-subr.sh

# Linux kernel 3.11.10 permits map_files/ access only for root.
if head -qc0 /proc/self/map_files/* 2>&1 | grep -w 'Operation not permitted'; then
  exit 77
fi

tempfiles deleted deleted-lib.so
cp -p ${abs_builddir}/deleted ${abs_builddir}/deleted-lib.so .
pid=$(testrun ${abs_builddir}/deleted)
sleep 1
tempfiles bt
testrun ${abs_top_builddir}/src/stack -p $pid >bt
kill -9 $pid
wait
grep -w libfunc bt
grep -w main bt
