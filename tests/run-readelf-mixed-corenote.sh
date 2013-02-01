#! /bin/sh
# Copyright (C) 2012 Red Hat, Inc.
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

testfiles testfile63

testrun_compare ../src/readelf -n testfile63 <<\EOF

Note segment of 892 bytes at offset 0x274:
  Owner          Data size  Type
  CORE                 148  PRSTATUS
    info.si_signo: 11, info.si_code: 0, info.si_errno: 0, cursig: 11
    sigpend: <>
    sighold: <>
    pid: 11087, ppid: 11063, pgrp: 11087, sid: 11063
    utime: 0.000000, stime: 0.010000, cutime: 0.000000, cstime: 0.000000
    orig_r0: -1, fpvalid: 1
    r0:             1  r1:   -1091672508  r2:   -1091672500
    r3:             0  r4:             0  r5:             0
    r6:         33728  r7:             0  r8:             0
    r9:             0  r10:  -1225703496  r11:  -1091672844
    r12:            0  sp:    0xbeee64f4  lr:    0xb6dc3f48
    pc:    0x00008500  spsr:  0x60000010
  CORE                 124  PRPSINFO
    state: 0, sname: R, zomb: 0, nice: 0, flag: 0x00400500
    uid: 0, gid: 0, pid: 11087, ppid: 11063, pgrp: 11087, sid: 11063
    fname: a.out, psargs: ./a.out 
  CORE                 144  AUXV
    HWCAP: 0xe8d7  <swp half thumb fast-mult vfp edsp>
    PAGESZ: 4096
    CLKTCK: 100
    PHDR: 0x8034
    PHENT: 32
    PHNUM: 8
    BASE: 0xb6eee000
    FLAGS: 0
    ENTRY: 0x83c0
    UID: 0
    EUID: 0
    GID: 0
    EGID: 0
    SECURE: 0
    RANDOM: 0xbeee674e
    EXECFN: 0xbeee6ff4
    PLATFORM: 0xbeee675e
    NULL
  CORE                 116  FPREGSET
    f0: 0x000000000000000000000000  f1: 0x000000000000000000000000
    f2: 0x000000000000000000000000  f3: 0x000000000000000000000000
    f4: 0x000000000000000000000000  f5: 0x000000000000000000000000
    f6: 0x000000000000000000000000  f7: 0x000000000000000000000000
  LINUX                260  ARM_VFP
    fpscr: 0x00000000
    d0:  0x0000000000000000  d1:  0x0000000000000000
    d2:  0x0000000000000000  d3:  0x0000000000000000
    d4:  0x0000000000000000  d5:  0x0000000000000000
    d6:  0x0000000000000000  d7:  0x0000000000000000
    d8:  0x0000000000000000  d9:  0x0000000000000000
    d10: 0x0000000000000000  d11: 0x0000000000000000
    d12: 0x0000000000000000  d13: 0x0000000000000000
    d14: 0x0000000000000000  d15: 0x0000000000000000
    d16: 0x0000000000000000  d17: 0x0000000000000000
    d18: 0x0000000000000000  d19: 0x0000000000000000
    d20: 0x0000000000000000  d21: 0x0000000000000000
    d22: 0x0000000000000000  d23: 0x0000000000000000
    d24: 0x0000000000000000  d25: 0x0000000000000000
    d26: 0x0000000000000000  d27: 0x0000000000000000
    d28: 0x0000000000000000  d29: 0x0000000000000000
    d30: 0x0000000000000000  d31: 0x0000000000000000
EOF

testfiles testfile67
testrun_compare ../src/readelf -n testfile67 <<\EOF

Note segment of 1044 bytes at offset 0xe8:
  Owner          Data size  Type
  CORE                 336  PRSTATUS
    info.si_signo: 4, info.si_code: 0, info.si_errno: 0, cursig: 4
    sigpend: <>
    sighold: <>
    pid: 805, ppid: 804, pgrp: 804, sid: 699
    utime: 0.000042, stime: 0.000103, cutime: 0.000000, cstime: 0.000000
    orig_r2: 2571552016, fpvalid: 1
    pswm:   0x0705c00180000000  pswa:   0x00000000800000d6
    r0:         4393751543808  r1:         4398002544388
    r2:                    11  r3:            2571578208
    r4:            2571702016  r5:         4398003235624
    r6:            2571580768  r7:            2571702016
    r8:            2571578208  r9:            2571552016
    r10:           2571552016  r11:                    0
    r12:        4398003499008  r13:           2148274656
    r14:                    0  r15:        4398040761216
    a0:   0x000003ff  a1:   0xfd54a6f0  a2:   0x00000000  a3:   0x00000000
    a4:   0x00000000  a5:   0x00000000  a6:   0x00000000  a7:   0x00000000
    a8:   0x00000000  a9:   0x00000000  a10:  0x00000000  a11:  0x00000000
    a12:  0x00000000  a13:  0x00000000  a14:  0x00000000  a15:  0x00000000
  CORE                 136  PRPSINFO
    state: 0, sname: R, zomb: 0, nice: 0, flag: 0x0000000000400400
    uid: 0, gid: 0, pid: 805, ppid: 804, pgrp: 804, sid: 699
    fname: 1, psargs: ./1 
  CORE                 304  AUXV
    SYSINFO_EHDR: 0
    HWCAP: 0x37f
    PAGESZ: 4096
    CLKTCK: 100
    PHDR: 0x80000040
    PHENT: 56
    PHNUM: 2
    BASE: 0
    FLAGS: 0
    ENTRY: 0x800000d4
    UID: 0
    EUID: 0
    GID: 0
    EGID: 0
    SECURE: 0
    RANDOM: 0x3ffffa8463c
    EXECFN: 0x3ffffa85ff4
    PLATFORM: 0x3ffffa8464c
    NULL
  CORE                 136  FPREGSET
    fpc: 0x00000000
    f0:  0x0000000000000040  f1:  0x4b00000000000000
    f2:  0x0000000000000041  f3:  0x3ad50b5555555600
    f4:  0x0000000000000000  f5:  0x0000000000000000
    f6:  0x0000000000000000  f7:  0x0000000000000000
    f8:  0x0000000000000000  f9:  0x0000000000000000
    f10: 0x0000000000000000  f11: 0x0000000000000000
    f12: 0x0000000000000000  f13: 0x0000000000000000
    f14: 0x0000000000000000  f15: 0x0000000000000000
  LINUX                  8  S390_LAST_BREAK
    last_break: 0x000003fffd75ccbe
  LINUX                  4  S390_SYSTEM_CALL
    system_call: 0
EOF

testfiles testfile68
testrun_compare ../src/readelf -n testfile68 <<\EOF

Note segment of 852 bytes at offset 0x94:
  Owner          Data size  Type
  CORE                 224  PRSTATUS
    info.si_signo: 4, info.si_code: 0, info.si_errno: 0, cursig: 4
    sigpend: <>
    sighold: <>
    pid: 839, ppid: 838, pgrp: 838, sid: 699
    utime: 0.000043, stime: 0.000102, cutime: 0.000000, cstime: 0.000000
    orig_r2: -1723388288, fpvalid: 1
    pswm:  0x070dc000  pswa:  0x8040009a
    r0:            0  r1:    -43966716  r2:           11  r3:  -1723238816
    r4:  -1723265280  r5:    -43275480  r6:  -1723245280  r7:  -1723265280
    r8:  -1723238816  r9:  -1723388288  r10: -1723388288  r11:           0
    r12:   -43012096  r13: -2146692640  r14:           0  r15:  2139883440
    a0:   0x000003ff  a1:   0xfd54a6f0  a2:   0x00000000  a3:   0x00000000
    a4:   0x00000000  a5:   0x00000000  a6:   0x00000000  a7:   0x00000000
    a8:   0x00000000  a9:   0x00000000  a10:  0x00000000  a11:  0x00000000
    a12:  0x00000000  a13:  0x00000000  a14:  0x00000000  a15:  0x00000000
  CORE                 124  PRPSINFO
    state: 0, sname: R, zomb: 0, nice: 0, flag: 0x00400400
    uid: 0, gid: 0, pid: 839, ppid: 838, pgrp: 838, sid: 699
    fname: 2, psargs: ./2 
  CORE                 152  AUXV
    SYSINFO_EHDR: 0
    HWCAP: 0x37f
    PAGESZ: 4096
    CLKTCK: 100
    PHDR: 0x400034
    PHENT: 32
    PHNUM: 2
    BASE: 0
    FLAGS: 0
    ENTRY: 0x400098
    UID: 0
    EUID: 0
    GID: 0
    EGID: 0
    SECURE: 0
    RANDOM: 0x7f8c090c
    EXECFN: 0x7f8c1ff4
    PLATFORM: 0x7f8c091c
    NULL
  CORE                 136  FPREGSET
    fpc: 0x00000000
    f0:  0x0000000000000040  f1:  0x4b00000000000000
    f2:  0x0000000000000041  f3:  0x3ad50b5555555600
    f4:  0x0000000000000000  f5:  0x0000000000000000
    f6:  0x0000000000000000  f7:  0x0000000000000000
    f8:  0x0000000000000000  f9:  0x0000000000000000
    f10: 0x0000000000000000  f11: 0x0000000000000000
    f12: 0x0000000000000000  f13: 0x0000000000000000
    f14: 0x0000000000000000  f15: 0x0000000000000000
  LINUX                  8  S390_LAST_BREAK
    last_break: 0xfd75ccbe
  LINUX                  4  S390_SYSTEM_CALL
    system_call: 0
  LINUX                 64  S390_HIGH_GPRS
    high_r0: 0x000003ff, high_r1: 0x000003ff, high_r2: 0x00000000
    high_r3: 0x00000000, high_r4: 0x00000000, high_r5: 0x000003ff
    high_r6: 0x00000000, high_r7: 0x00000000, high_r8: 0x00000000
    high_r9: 0x00000000, high_r10: 0x00000000, high_r11: 0x00000000
    high_r12: 0x000003ff, high_r13: 0x00000000, high_r14: 0x00000000
    high_r15: 0x00000000
EOF

exit 0
