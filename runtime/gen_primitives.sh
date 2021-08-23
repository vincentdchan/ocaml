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
integers_intptr_t_size\n
integers_uintptr_t_size\n
integers_ptrdiff_t_size\n
ctypes_ldouble_to_float\n
ctypes_ldouble_of_float\n
ctypes_ldouble_to_int\n
ctypes_ldouble_of_int\n
ctypes_ldouble_of_string\n
ctypes_ldouble_add\n
ctypes_ldouble_sub\n
ctypes_ldouble_mul\n
ctypes_ldouble_div\n
ctypes_ldouble_neg\n
ctypes_ldouble_powl\n
ctypes_ldouble_sqrtl\n
ctypes_ldouble_expl\n
ctypes_ldouble_logl\n
ctypes_ldouble_log10l\n
ctypes_ldouble_expm1l\n
ctypes_ldouble_log1pl\n
ctypes_ldouble_cosl\n
ctypes_ldouble_sinl\n
ctypes_ldouble_tanl\n
ctypes_ldouble_acosl\n
ctypes_ldouble_asinl\n
ctypes_ldouble_atanl\n
ctypes_ldouble_atan2l\n
ctypes_ldouble_hypotl\n
ctypes_ldouble_coshl\n
ctypes_ldouble_sinhl\n
ctypes_ldouble_tanhl\n
ctypes_ldouble_acoshl\n
ctypes_ldouble_asinhl\n
ctypes_ldouble_atanhl\n
ctypes_ldouble_ceill\n
ctypes_ldouble_floorl\n
ctypes_ldouble_fabsl\n
ctypes_ldouble_remainderl\n
ctypes_ldouble_copysignl\n
ctypes_ldouble_frexp\n
ctypes_ldouble_ldexp\n
ctypes_ldouble_modf\n
ctypes_ldouble_classify\n
ctypes_ldouble_format\n
ctypes_ldouble_complex_conjl\n
ctypes_ldouble_complex_real\n
ctypes_ldouble_complex_imag\n
ctypes_ldouble_complex_neg\n
ctypes_ldouble_complex_conjl\n
ctypes_ldouble_complex_add\n
ctypes_ldouble_complex_sub\n
ctypes_ldouble_complex_mul\n
ctypes_ldouble_complex_div\n
ctypes_ldouble_complex_csqrtl\n
ctypes_ldouble_complex_cargl\n
ctypes_ldouble_complex_cexpl\n
ctypes_ldouble_complex_clogl\n
ctypes_ldouble_complex_cpowl\n
ctypes_typeof_clock_t\n
ctypes_typeof_dev_t\n
ctypes_typeof_ino_t\n
ctypes_typeof_mode_t\n
ctypes_typeof_nlink_t\n
ctypes_typeof_off_t\n
ctypes_typeof_pid_t\n
ctypes_typeof_ssize_t\n
ctypes_typeof_time_t\n
ctypes_typeof_useconds_t\n
ctypes_alignmentof_sigset_t\n
ctypes_sizeof_sigset_t\n
Base_am_testing\n
'

export LC_ALL=C
(
  for prim in \
      alloc array compare extern floats gc_ctrl hash intern interp ints io \
      lexing md5 meta memprof obj parsing signals str sys callback weak \
      finalise stacks dynlink backtrace_byt backtrace afl \
      bigarray eventlog unix_lib systhreads_lib integers_lib core_kernel_lib \
      blit_lib ctypes_lib base_lib b
  do
      sed -n -e 's/^CAMLprim value \([A-Za-z0-9_][A-Za-z0-9_]*\).*/\1/p' "$prim.c"
  done
  sed -n -e 's/^CAMLprim_int64_[0-9](\([a-z0-9_][a-z0-9_]*\)).*/caml_int64_\1\
caml_int64_\1_native/p' ints.c
  echo $extra_name | sed '/^[[:space:]]*$/d' | tr -d ' '
) | sort | uniq
