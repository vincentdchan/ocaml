#!/bin/sh

#**************************************************************************
#*                                                                        *
#*                                 OCaml                                  *
#*                                                                        *
#*            Xavier Leroy, projet Cristal, INRIA Rocquencourt            *
#*                                                                        *
#*   Copyright 1999 Institut National de Recherche en Informatique et     *
#*     en Automatique.                                                    *
#*                                                                        *
#*   All rights reserved.  This file is distributed under the terms of    *
#*   the GNU Lesser General Public License version 2.1, with the          *
#*   special exception on linking described in the file LICENSE.          *
#*                                                                        *
#**************************************************************************

# duplicated from $(ROOTDIR)/runtime/Makefile

# #8985: the meaning of character range a-z depends on the locale, so force C
#        locale throughout.

extra_name='
integers_uint32_of_int32\n
integers_int32_of_uint32\n
integers_uint64_of_int64\n
integers_uint64_to_int64\n
integers_uint64_of_uint32\n
integers_uint32_of_uint64\n
integers_uint32_of_int32\n
integers_int32_of_uint32\n
integers_uint64_of_int64\n
integers_uint64_to_int64\n
integers_uint64_of_uint32\n
integers_uint32_of_uint64\n
integers_uint64_add\n
integers_uint64_sub\n
integers_uint64_mul\n
integers_uint64_div\n
integers_uint64_rem\n
integers_uint64_logand\n
integers_uint64_logor\n
integers_uint64_logxor\n
integers_uint64_shift_left\n
integers_uint64_shift_right\n
integers_uint64_of_int\n
integers_uint64_to_int\n
integers_uint64_of_string\n
integers_uint64_to_string\n
integers_uint32_add\n
integers_uint32_sub\n
integers_uint32_mul\n
integers_uint32_div\n
integers_uint32_rem\n
integers_uint32_logand\n
integers_uint32_logor\n
integers_uint32_logxor\n
integers_uint32_shift_left\n
integers_uint32_shift_right\n
integers_uint32_of_int\n
integers_uint32_to_int\n
integers_uint32_of_int64\n
integers_uint32_to_int64\n
integers_uint32_of_string\n
integers_uint32_to_string\n
integers_uint16_of_string\n
integers_uint8_of_string\n
integers_unsigned_init\n
integers_uint32_max\n
integers_uint64_max\n
integers_size_t_size\n
integers_ushort_size\n
integers_uint_size\n
integers_ulong_size\n
integers_ulonglong_size\n
'

export LC_ALL=C
(
  for prim in \
      alloc array compare extern floats gc_ctrl hash intern interp ints io \
      lexing md5 meta memprof obj parsing signals str sys callback weak \
      finalise stacks dynlink backtrace_byt backtrace afl \
      bigarray eventlog unix_lib systhreads_lib integers_lib
  do
      sed -n -e 's/^CAMLprim value \([a-z0-9_][a-z0-9_]*\).*/\1/p' "$prim.c"
  done
  sed -n -e 's/^CAMLprim_int64_[0-9](\([a-z0-9_][a-z0-9_]*\)).*/caml_int64_\1\
caml_int64_\1_native/p' ints.c
  echo $extra_name | sed '/^[[:space:]]*$/d' | tr -d ' '
) | sort | uniq
