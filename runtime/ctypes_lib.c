/*
 * Copyright (c) 2016 Andy Ray.
 *
 * This file is distributed under the terms of the MIT License.
 * See the file LICENSE for details.
 */

#if !__USE_MINGW_ANSI_STDIO && (defined(__MINGW32__) || defined(__MINGW64__))
#define __USE_MINGW_ANSI_STDIO 1
#endif

#include "caml/mlvalues.h"
#include "caml/custom.h"
#include "caml/alloc.h"
#include "caml/intext.h"
#include "caml/fail.h"
#include "caml/hash.h"
#include "caml/memory.h"
#include "caml/bigarray.h"

#include <stdio.h>
#include <stdint.h>
#include <float.h>
#include <math.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <assert.h>

#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#if (!defined _WIN32 || defined __CYGWIN__) && !defined MINIOS
#include <pthread.h>
#endif
#include <time.h>

#include "ocaml_integers.h"
#include "ctypes_primitives.h"
#include "ctypes_raw_pointer.h"
#include "ctypes_ldouble_stubs.h"
#include "ctypes_complex_compatibility.h"
#include "ctypes_managed_buffer_stubs.h"

/*********************** long double *************************/

/*
 * long double comes in various different flavours on different
 * platforms/architectures.
 *
 * 8 byte double - arm, msvc
 * 10 byte extended - intel gcc.  can be packed into 12 or 16 bytes.
 * 16 byte - powerpc, either IEEE quad float or __ibm128 double double
 *
 * We make a best guess as to the format based on LDBL_MANT_DIG.
 * This only affects the operation of hashing and serialization.
 *
 * For deserialization we consider it an error if the stored
 * value is a different format.  Doing such conversions would
 * get very complicated.
 *
 * Regarding endianness - the 8 and 16 byte formats should
 * interwork between big and little endian systems.  The
 * intel extended 10 byte format only seems to occurs on
 * x86 so we dont need to consider endianness.
 *
 * In case a format is encountered that we do not understand,
 * then we fall back to casting the value to a double.
 *
 */

#define LDOUBLE_STORAGE_BYTES sizeof(long double)
#if (LDBL_MANT_DIG == 53)      // 64 bit - same as double
#define LDOUBLE_VALUE_BYTES 8
#elif (LDBL_MANT_DIG == 64)    // intel 80 bit extended
#define LDOUBLE_VALUE_BYTES 10
#elif (LDBL_MANT_DIG == 106)   // __ibm128 (pair of doubles)
#define LDOUBLE_VALUE_BYTES 16
#elif (LDBL_MANT_DIG == 113)   // ieee __float128
#define LDOUBLE_VALUE_BYTES 16
#else
#define LDOUBLE_VALUE_BYTES LDOUBLE_STORAGE_BYTES
#endif

static inline long double ldouble_custom_val(value v) {
  long double r;
  memcpy(&r, Data_custom_val(v), sizeof(r));
  return r;
}

// initialized in ldouble_init
static long double nan_;

static long double norm(long double x) {
  switch (fpclassify(x)){
  case FP_ZERO      : return 0.0L; // if -0 force to +0.
  case FP_NAN       : return nan_;  // cannonical nan
  default           : return x;
  }
}

static int ldouble_cmp(long double u1, long double u2) {
  if (u1 < u2) return -1;
  if (u1 > u2) return 1;
  if (u1 != u2) {
    caml_compare_unordered = 1;
    if (u1 == u1) return 1;  // u2 is nan
    if (u2 == u2) return -1; // u1 is nan
    // both nan ==> equal
  }
  return 0;
}

static int ldouble_cmp_val(value v1, value v2)
{
  long double u1 = ldouble_custom_val(v1);
  long double u2 = ldouble_custom_val(v2);
  return ldouble_cmp(u1, u2);
}

static uint32_t ldouble_mix_hash(uint32_t hash, long double d) {
  union {
    long double d;
    uint32_t a[(LDOUBLE_STORAGE_BYTES+3)/4];
  } u;
  u.d = norm(d);

  if (LDOUBLE_VALUE_BYTES == 16) {
    // ieee quad or __ibm128
#ifdef ARCH_BIG_ENDIAN
    hash = caml_hash_mix_uint32(hash, u.a[0]);
    hash = caml_hash_mix_uint32(hash, u.a[1]);
    hash = caml_hash_mix_uint32(hash, u.a[2]);
    hash = caml_hash_mix_uint32(hash, u.a[3]);
#else
    hash = caml_hash_mix_uint32(hash, u.a[1]);
    hash = caml_hash_mix_uint32(hash, u.a[0]);
    hash = caml_hash_mix_uint32(hash, u.a[3]);
    hash = caml_hash_mix_uint32(hash, u.a[2]);
#endif
  } else if (LDOUBLE_VALUE_BYTES == 10) {
    // intel extended
    hash = caml_hash_mix_uint32(hash, u.a[0]);
    hash = caml_hash_mix_uint32(hash, u.a[1]);
    hash = caml_hash_mix_uint32(hash, u.a[2] & 0xFFFF);
  } else {
    // either LDOUBLE_VALUE_BYTES == 8, or we dont know what else to do.
    hash = caml_hash_mix_double(hash,  (double) d);
  }
  return hash;

}

static intnat ldouble_hash(value v) {
  return ldouble_mix_hash(0, ldouble_custom_val(v));
}

static void ldouble_serialize_data(long double *q) {
  unsigned char *p = (unsigned char *)q;
  if (LDOUBLE_VALUE_BYTES == 16) {
    caml_serialize_block_8(p, 2);
  } else if (LDOUBLE_VALUE_BYTES == 10) {
    caml_serialize_block_8(p, 1);
    caml_serialize_block_2(p+8, 1);
  } else {
    double d = (double) *q;
    if (sizeof(double) == 4) caml_serialize_float_4(d);
    else caml_serialize_float_8(d);
  }
}

static void ldouble_serialize(value v, uintnat *wsize_32, uintnat *wsize_64) {
  long double p = norm(ldouble_custom_val(v));
  caml_serialize_int_1(LDBL_MANT_DIG);
  ldouble_serialize_data(&p);
  *wsize_32 = *wsize_64 = sizeof(long double);
}

static void ldouble_deserialize_data(long double *q) {
  unsigned char *p = (unsigned char *)q;
  if (LDOUBLE_VALUE_BYTES == 16) {
    caml_deserialize_block_8(p, 2);
  } else if (LDOUBLE_VALUE_BYTES == 10) {
    caml_deserialize_block_8(p, 1);
    caml_deserialize_block_2(p+8, 1);
  } else {
    double d;
    if (sizeof(double) == 4) d = caml_deserialize_float_4();
    else d = caml_deserialize_float_8();
    *q = (long double) d;
  }
}

static uintnat ldouble_deserialize(void *d) {
  if (caml_deserialize_uint_1() != LDBL_MANT_DIG)
    caml_deserialize_error("invalid long double size");
  ldouble_deserialize_data((long double *) d);
  return (sizeof(long double));
}

static struct custom_operations caml_ldouble_ops = {
  "ctypes:ldouble",
  custom_finalize_default,
  ldouble_cmp_val,
  ldouble_hash,
  ldouble_serialize,
  ldouble_deserialize,
  custom_compare_ext_default
};

value ctypes_copy_ldouble(long double u)
{
  value res = caml_alloc_custom(&caml_ldouble_ops, sizeof(long double), 0, 1);
  memcpy(Data_custom_val(res), &u, sizeof(u));
  return res;
}

long double ctypes_ldouble_val(value v) { return ldouble_custom_val(v); }

CAMLprim value ctypes_ldouble_of_float(value a) {
  CAMLparam1(a);
  CAMLreturn(ctypes_copy_ldouble(Double_val(a)));
}
CAMLprim value ctypes_ldouble_to_float(value a) {
  CAMLparam1(a);
  CAMLreturn(caml_copy_double(ldouble_custom_val(a)));
}
CAMLprim value ctypes_ldouble_of_int(value a) {
  CAMLparam1(a);
  CAMLreturn(ctypes_copy_ldouble(Long_val(a)));
}
CAMLprim value ctypes_ldouble_to_int(value a) {
  CAMLparam1(a);
  long double b = ldouble_custom_val(a);
  intnat c = b;
  CAMLreturn(Val_long(c));
}

#define OP2(OPNAME, OP)                                                               \
  CAMLprim value ctypes_ldouble_ ## OPNAME(value a, value b) {                        \
    CAMLparam2(a, b);                                                                 \
    CAMLreturn(ctypes_copy_ldouble( ldouble_custom_val(a) OP ldouble_custom_val(b))); \
  }

OP2(add, +)
OP2(sub, -)
OP2(mul, *)
OP2(div, /)

CAMLprim value ctypes_ldouble_neg(value a) {
  CAMLparam1(a);
  CAMLreturn(ctypes_copy_ldouble( - ldouble_custom_val(a)));
}

#define FN1(OP)                                                   \
  CAMLprim value ctypes_ldouble_ ## OP (value a) {                \
    CAMLparam1(a);                                                \
    CAMLreturn(ctypes_copy_ldouble( OP (ldouble_custom_val(a)))); \
  }

#define FN2(OP)                                                                          \
  CAMLprim value ctypes_ldouble_ ## OP (value a, value b) {                              \
    CAMLparam2(a, b);                                                                    \
    CAMLreturn(ctypes_copy_ldouble( OP (ldouble_custom_val(a), ldouble_custom_val(b)))); \
  }

#define FN1FAIL(OP)                                                        \
  CAMLprim value ctypes_ldouble_ ## OP (value a) {                         \
    CAMLparam1(a);                                                         \
    caml_failwith("ctypes: " #OP " does not exist on current platform");   \
  }

#define FN2FAIL(OP)                                                        \
  CAMLprim value ctypes_ldouble_ ## OP (value a, value b) {                \
    CAMLparam2(a, b);                                                      \
    caml_failwith("ctypes: " #OP " does not exist on current platform");   \
  }

FN2(powl)
FN1(sqrtl)
FN1(expl)
FN1(logl)
FN1(log10l)
#ifdef __NetBSD__
FN1FAIL(expm1l)
FN1FAIL(log1pl)
#else
FN1(expm1l)
FN1(log1pl)
#endif
FN1(cosl)
FN1(sinl)
FN1(tanl)
FN1(acosl)
FN1(asinl)
FN1(atanl)
FN2(atan2l)
FN2(hypotl)
FN1(coshl)
FN1(sinhl)
FN1(tanhl)
FN1(acoshl)
FN1(asinhl)
FN1(atanhl)
FN1(ceill)
FN1(floorl)
FN1(fabsl)
#ifdef __NetBSD__
FN2FAIL(remainderl)
#else
FN2(remainderl)
#endif
FN2(copysignl)

#undef OP2
#undef FN1
#undef FN2
#undef FN1FAIL
#undef FN2FAIL

CAMLprim value ctypes_ldouble_frexp(value v) {
  CAMLparam1(v);
  CAMLlocal2(r, rfv);
  long double f = ldouble_custom_val(v);
  int ri;
  long double rf;
  r = caml_alloc_tuple(2);
  rf = frexpl(f, &ri);
  rfv = ctypes_copy_ldouble(rf);
  Store_field(r,0, rfv);
  Store_field(r,1, Val_int(ri));
  CAMLreturn(r);
}

CAMLprim value ctypes_ldouble_ldexp(value vf, value vi) {
  CAMLparam2(vf, vi);
  CAMLlocal1(r);
  long double f = ldouble_custom_val(vf);
  int i = Int_val(vi);
  long double rf = ldexpl(f, i);
  r = ctypes_copy_ldouble(rf);
  CAMLreturn(r);
}

CAMLprim value ctypes_ldouble_modf(value v) {
  CAMLparam1(v);
  CAMLlocal1(r);
  long double f = ldouble_custom_val(v);
  long double rf2;
  long double rf1 = modfl(f, &rf2);
  r = caml_alloc_tuple(2);
  Store_field(r, 0, ctypes_copy_ldouble(rf1));
  Store_field(r, 1, ctypes_copy_ldouble(rf2));
  CAMLreturn(r);
}

enum {
  ml_FP_NORMAL = 0,
  ml_FP_SUBNORMAL,
  ml_FP_ZERO,
  ml_FP_INFINITE,
  ml_FP_NAN,
};

CAMLprim value ctypes_ldouble_classify(value v){
  CAMLparam1(v);
  CAMLlocal1(r);
  long double f = ldouble_custom_val(v);
  switch (fpclassify(f)){
  case FP_NORMAL    : r = Val_int(ml_FP_NORMAL); break;
  case FP_SUBNORMAL : r = Val_int(ml_FP_SUBNORMAL); break;
  case FP_ZERO      : r = Val_int(ml_FP_ZERO); break;
  case FP_INFINITE  : r = Val_int(ml_FP_INFINITE); break;
  case FP_NAN       :
  default           : r = Val_int(ml_FP_NAN); break;
  }
  CAMLreturn(r);
}

static char *format_ldouble(int width, int prec, long double d) {
  size_t print_len;
  char *buf = NULL;

  // find length
  print_len = snprintf(NULL, 0, "%*.*Lf", width, prec, d);
  if (0 == print_len) // this shouldn't happen
    caml_invalid_argument("bad ldouble format");

  // allocate buffer
  buf = malloc(print_len+1);
  if (NULL == buf) caml_raise_out_of_memory();

  // format string
  buf[0] = '\0';
  snprintf(buf, print_len+1, "%*.*Lf", width, prec, d);
  return buf;
}

CAMLprim value ctypes_ldouble_format(value width, value prec, value d) {
  CAMLparam3(width, prec, d);
  CAMLlocal1(s);
  char *str = format_ldouble(Int_val(width), Int_val(prec),
                             ldouble_custom_val(d));
  s = caml_copy_string(str);
  free(str);
  CAMLreturn(s);
}

CAMLprim value ctypes_ldouble_of_string(value v) {
  CAMLparam1(v);
  const char *str = String_val(v);
  int len = caml_string_length(v);
  char *end;
  long double r;
  if (0 == len) caml_invalid_argument("LDouble.of_string");
  r = strtold(str, &end);
  if (*end != '\0') caml_invalid_argument("LDouble.of_string");
  CAMLreturn(ctypes_copy_ldouble(r));
}

CAMLprim value ctypes_ldouble_min(value unit) { return ctypes_copy_ldouble(-LDBL_MAX); }
CAMLprim value ctypes_ldouble_max(value unit) { return ctypes_copy_ldouble(LDBL_MAX); }
CAMLprim value ctypes_ldouble_epsilon(value unit) { return ctypes_copy_ldouble(LDBL_EPSILON); }
CAMLprim value ctypes_ldouble_nan(value unit) { return ctypes_copy_ldouble(nan_); }
// XXX note; -(log 0) gives +ve inf (and vice versa).  Is this consistent? *)
CAMLprim value ctypes_ldouble_inf(value unit) { return ctypes_copy_ldouble(-log(0)); }
CAMLprim value ctypes_ldouble_ninf(value unit) { return ctypes_copy_ldouble(log(0)); }

CAMLprim value ctypes_ldouble_size(value unit) {
  CAMLparam1(unit);
  CAMLlocal1(r);
  r = caml_alloc_tuple(2);
  Store_field(r,0, Val_int(LDOUBLE_STORAGE_BYTES));
  Store_field(r,1, Val_int(LDOUBLE_VALUE_BYTES));
  CAMLreturn(r);
}

/*********************** complex *************************/

static inline long double _Complex ldouble_complex_custom_val(value v)
{
  long double _Complex r;
  memcpy(&r, Data_custom_val(v), sizeof(r));
  return r;
}

static int ldouble_complex_cmp_val(value v1, value v2)
{
  long double _Complex u1 = ldouble_complex_custom_val(v1);
  long double _Complex u2 = ldouble_complex_custom_val(v2);
  int cmp_real = ldouble_cmp(ctypes_compat_creall(u1), ctypes_compat_creall(u2));
  return cmp_real == 0 ? ldouble_cmp(ctypes_compat_cimagl(u1), ctypes_compat_cimagl(u2)) : cmp_real;
}

static intnat ldouble_complex_hash(value v) {
  long double _Complex c = ldouble_complex_custom_val(v);
  return ldouble_mix_hash(ldouble_mix_hash(0, ctypes_compat_creall(c)), ctypes_compat_cimagl(c));
}

static void ldouble_complex_serialize(value v, uintnat *wsize_32, uintnat *wsize_64) {
  long double re,im;
  long double _Complex c;
  void * p = Data_custom_val(v);
#if defined(__GNUC__) && __GNUC__  == 6 && __GNUC_MINOR__ == 4
  /* workaround gcc bug. gcc tries to inline the memcpy calls, but
   * fails with an internal compiler error. I've observed this error
   * only under Alpine Linux, other distros have already imported a
   * patch from upstream.
   */
  void *(*volatile mymemcpy)(void*,const void*,size_t) = memcpy;
  mymemcpy(&c, p, sizeof(c));
#else
  memcpy(&c, p, sizeof(c));
#endif
  caml_serialize_int_1(LDBL_MANT_DIG);
  re = ctypes_compat_creall(c);
  ldouble_serialize_data(&re);
  im = ctypes_compat_cimagl(c);
  ldouble_serialize_data(&im);
  *wsize_32 = *wsize_64 = sizeof(long double _Complex);
}

static uintnat ldouble_complex_deserialize(void *d) {
  long double re, im;
  long double _Complex c;
  if (caml_deserialize_uint_1() != LDBL_MANT_DIG)
    caml_deserialize_error("invalid long double size");
  ldouble_deserialize_data(&re);
  ldouble_deserialize_data(&im);
  c = ctypes_compat_make_complexl(re, im);
  memcpy(d, &c, sizeof(c));
  return (sizeof(long double _Complex));
}

static struct custom_operations caml_ldouble_complex_ops = {
  "ctypes:ldouble_complex",
  custom_finalize_default,
  ldouble_complex_cmp_val,
  ldouble_complex_hash,
  ldouble_complex_serialize,
  ldouble_complex_deserialize,
  custom_compare_ext_default
};

value ctypes_copy_ldouble_complex(long double _Complex u)
{
  value res = caml_alloc_custom(&caml_ldouble_complex_ops, sizeof(long double _Complex), 0, 1);
  memcpy(Data_custom_val(res), &u, sizeof(u));
  return res;
}

long double _Complex ctypes_ldouble_complex_val(value v) {
  return ldouble_complex_custom_val(v);
}

/* make : t -> t -> complex */
CAMLprim value ctypes_ldouble_complex_make(value r, value i) {
  CAMLparam2(r, i);
  long double re = ldouble_custom_val(r);
  long double im = ldouble_custom_val(i);
  CAMLreturn(ctypes_copy_ldouble_complex(ctypes_compat_make_complexl(re, im)));
}

/* real : complex -> t */
CAMLprim value ctypes_ldouble_complex_real(value v) {
  CAMLparam1(v);
  CAMLreturn(ctypes_copy_ldouble(ctypes_compat_creall(ldouble_complex_custom_val(v))));
}

/* imag : complex -> t */
CAMLprim value ctypes_ldouble_complex_imag(value v) {
  CAMLparam1(v);
  CAMLreturn(ctypes_copy_ldouble(ctypes_compat_cimagl(ldouble_complex_custom_val(v))));
}

#define OP2(OPNAME, OP)                                                    \
  CAMLprim value ctypes_ldouble_complex_ ## OPNAME(value a, value b) {     \
    CAMLparam2(a, b);                                                      \
    CAMLreturn(ctypes_copy_ldouble_complex(                                \
        ldouble_complex_custom_val(a) OP ldouble_complex_custom_val(b) )); \
  }

OP2(add, +)
OP2(sub, -)
OP2(mul, *)
OP2(div, /)

CAMLprim value ctypes_ldouble_complex_neg(value a) {
  CAMLparam1(a);
  CAMLreturn(ctypes_copy_ldouble_complex( - ldouble_complex_custom_val(a) ));
}

#define FN1(OP)                                                                   \
  CAMLprim value ctypes_ldouble_complex_ ## OP (value a) {                        \
    CAMLparam1(a);                                                                \
    CAMLreturn(ctypes_copy_ldouble_complex( ctypes_compat_ ## OP (ldouble_complex_custom_val(a)))); \
  }

#define FN2(OP)                                                            \
  CAMLprim value ctypes_ldouble_complex_ ## OP (value a, value b) {        \
    CAMLparam2(a, b);                                                      \
    CAMLreturn(ctypes_copy_ldouble_complex(                                \
      ctypes_compat_ ## OP (ldouble_complex_custom_val(a), ldouble_complex_custom_val(b)))); \
  }

FN1(conjl)
FN1(csqrtl)

FN1(cexpl)
FN1(clogl)
FN2(cpowl)

CAMLprim value ctypes_ldouble_complex_cargl(value a) {
  CAMLparam1(a);
  CAMLreturn(ctypes_copy_ldouble( ctypes_compat_cargl(ldouble_complex_custom_val(a))));
}

CAMLprim value ldouble_init(value unit) {
  nan_ = nanl(""); // platform dependant argument - use as cannonical nan
  caml_register_custom_operations(&caml_ldouble_ops);
  caml_register_custom_operations(&caml_ldouble_complex_ops);
  return Val_unit;
}

CAMLprim value ctypes_ldouble_mant_dig(value unit) {
  intnat r = LDBL_MANT_DIG;
  return Val_long(r);
}

/* 'a -> voidp */
CAMLprim value ctypes_caml_roots_create(value v)
{
  value *p = caml_stat_alloc(sizeof *p);
  *p = v;
  caml_register_generational_global_root(p);
  return CTYPES_FROM_PTR(p);
}

/* voidp -> 'a -> unit */
CAMLprim value ctypes_caml_roots_set(value p_, value v)
{
  value *p = CTYPES_TO_PTR(p_);
  caml_modify_generational_global_root(p, v);
  return Val_unit;
}

/* voidp -> 'a */
CAMLprim value ctypes_caml_roots_get(value p_)
{
  value *p = CTYPES_TO_PTR(p_);
  return *p;
}

/* voidp -> unit */
CAMLprim value ctypes_caml_roots_release(value p_)
{
  value *p = CTYPES_TO_PTR(p_);
  caml_remove_generational_global_root(p);
  caml_stat_free(p);
  return Val_unit;
}

/* 'a -> unit */
CAMLprim value ctypes_use(value v)
{
  return Val_unit;
}

#ifndef Caml_ba_layout_val
/* Caml_ba_layout_val was introduced when the representation of layout
   values changed from an integer to a GADT.  Up to that point the 
   OCaml values c_layout and fortran_layout had the same values as
   the C constants CAML_BA_C_LAYOUT and CAML_BA_FORTRAN_LAYOUT */
#define Caml_ba_layout_val(v) (Int_val(v))
#endif

/* address : 'b -> pointer */
CAMLprim value ctypes_bigarray_address(value ba)
{
  return CTYPES_FROM_PTR(Caml_ba_data_val(ba));
}

/* _view : ('a, 'b) kind -> dims:int array -> fatptr -> 'l layout ->
           ('a, 'b, 'l) Bigarray.Genarray.t */
CAMLprim value ctypes_bigarray_view(value kind_, value dims_, value ptr_, value layout_)
{
  int kind = Int_val(kind_);
  int layout = Caml_ba_layout_val(layout_);
  int ndims = Wosize_val(dims_);
  intnat dims[CAML_BA_MAX_NUM_DIMS];
  int i;
  for (i = 0; i < ndims; i++) {
    dims[i] = Long_val(Field(dims_, i));
  }
  int flags = kind | layout | CAML_BA_EXTERNAL;
  void *data = CTYPES_ADDR_OF_FATPTR(ptr_);
  return caml_ba_alloc(flags, ndims, data, dims);
}

static void finalize_free(value v)
{
  free(*((void **)Data_custom_val(v)));
}

static int compare_pointers(value l_, value r_)
{
  /* pointer comparison */
  intptr_t l = (intptr_t)*(void **)Data_custom_val(l_);
  intptr_t r = (intptr_t)*(void **)Data_custom_val(r_);
  return (l > r) - (l < r);
}

static intnat hash_address(value l)
{
  /* address hashing */
  return (intnat)*(void **)Data_custom_val(l);
}

static struct custom_operations managed_buffer_custom_ops = {
  "ocaml-ctypes:managed_buffer",
  finalize_free,
  compare_pointers,
  hash_address,
  /* Managed buffers are not serializable. */
  custom_serialize_default,
  custom_deserialize_default,
  custom_compare_ext_default
};

/* copy_bytes : void * -> size_t -> managed_buffer */
value ctypes_copy_bytes(void *src, size_t size)
{
  CAMLparam0();
  CAMLlocal1(block);
  block = caml_alloc_custom(&managed_buffer_custom_ops, sizeof(void*), 0, 1);
  void *dst = malloc(size);
  if (dst == NULL && size != 0) caml_raise_out_of_memory();
  *(void **)Data_custom_val(block) = memcpy(dst, src, size);
  CAMLreturn(block);
}

/* allocate : int -> int -> managed_buffer */
CAMLprim value ctypes_allocate(value count_, value size_)
{
  CAMLparam2(count_, size_);
  intnat size = Long_val(size_);
  intnat count = Long_val(count_);
  CAMLlocal1(block);
  block = caml_alloc_custom(&managed_buffer_custom_ops, sizeof(void*), 0, 1);
  // libc's calloc guarantees the memory is zero-filled
  // malloc may not be used internally
  void *p = calloc(count, size);
  if (p == NULL && count != 0 && size != 0) caml_raise_out_of_memory();
  void **d = (void **)Data_custom_val(block);
  *d = p;
  CAMLreturn(block);
}

/* block_address : managed_buffer -> immediate_pointer */
CAMLprim value ctypes_block_address(value managed_buffer)
{
  return CTYPES_FROM_PTR(*(void **)Data_custom_val(managed_buffer));
}

/* memcpy : dst:fat_pointer -> src:fat_pointer -> size:int -> unit */
CAMLprim value ctypes_memcpy(value dst, value src, value size)
{
  CAMLparam3(dst, src, size);
  memcpy(CTYPES_ADDR_OF_FATPTR(dst), CTYPES_ADDR_OF_FATPTR(src), Long_val(size));
  CAMLreturn(Val_unit);
}


/* string_of_cstring : raw_ptr -> int -> string */
CAMLprim value ctypes_string_of_cstring(value p)
{
  return caml_copy_string(CTYPES_ADDR_OF_FATPTR(p));
}


/* string_of_array : fat_ptr -> len:int -> string */
CAMLprim value ctypes_string_of_array(value p, value vlen)
{
  CAMLparam2(p, vlen);
  CAMLlocal1(dst);
  intnat len = Long_val(vlen);
  if (len < 0)
    caml_invalid_argument("ctypes_string_of_array");
  dst = caml_alloc_string(len);
  memcpy((char *)String_val(dst), CTYPES_ADDR_OF_FATPTR(p), len);
  CAMLreturn(dst);
}


/* cstring_of_string : string -> managed_buffer */
CAMLprim value ctypes_cstring_of_string(value s)
{
  CAMLparam1(s);
  CAMLlocal1(buffer);
  size_t len = caml_string_length(s);
  buffer = ctypes_allocate(Val_int(1), Val_long(len + 1));
  char *dst = CTYPES_TO_PTR(ctypes_block_address(buffer));
  const char *ss = String_val(s);
  memcpy(dst, ss, len);
  dst[len] = '\0';
  CAMLreturn(buffer);
}

#if __USE_MINGW_ANSI_STDIO && defined(__MINGW64__)
#define REAL_ARCH_INTNAT_PRINTF_FORMAT "ll"
#else
#define REAL_ARCH_INTNAT_PRINTF_FORMAT ARCH_INTNAT_PRINTF_FORMAT
#endif

static value allocate_complex_value(double r, double i)
{
  value v = caml_alloc(2 * Double_wosize, Double_array_tag);
  Store_double_field(v, 0, r);
  Store_double_field(v, 1, i);
  return v;
}

/* ctypes_copy_float_complex : float _Complex -> Complex.t */
value ctypes_copy_float_complex(float _Complex c)
{
  return allocate_complex_value(ctypes_compat_crealf(c), ctypes_compat_cimagf(c));
}

/* ctypes_copy_double_complex : double _Complex -> Complex.t */
value ctypes_copy_double_complex(double _Complex c)
{
  return allocate_complex_value(ctypes_compat_creal(c), ctypes_compat_cimag(c));
}

/* ctypes_float_complex_val : Complex.t -> float _Complex */
float _Complex ctypes_float_complex_val(value v)
{
  return ctypes_compat_make_complexf(Double_field(v, 0), Double_field(v, 1));
}

/* ctypes_double_complex_val : Complex.t -> double _Complex */
double _Complex ctypes_double_complex_val(value v)
{
  return ctypes_compat_make_complex(Double_field(v, 0), Double_field(v, 1));
}

/* Read a C value from a block of memory */
/* read : 'a prim -> fat_pointer -> 'a */
CAMLprim value ctypes_read(value prim_, value buffer_)
{
  CAMLparam2(prim_, buffer_);
  CAMLlocal1(b);
  void *buf = CTYPES_ADDR_OF_FATPTR(buffer_);
  switch (Int_val(prim_))
  {
   case Ctypes_Char: b = Val_int(*(unsigned char*)buf); break;
   case Ctypes_Schar: b = Val_int(*(signed char *)buf); break;
   case Ctypes_Uchar: b = Integers_val_uint8(*(unsigned char *)buf); break;
   case Ctypes_Bool: b = Val_bool(*(bool *)buf); break;
   case Ctypes_Short: b = Val_int(*(short *)buf); break;
   case Ctypes_Int: b = Val_int(*(int *)buf); break;
   case Ctypes_Long: b = ctypes_copy_long(*(long *)buf); break;
   case Ctypes_Llong: b = ctypes_copy_llong(*(long long *)buf); break;
   case Ctypes_Ushort: b = ctypes_copy_ushort(*(unsigned short *)buf); break;
   case Ctypes_Sint: b = ctypes_copy_sint(*(int *)buf); break;
   case Ctypes_Uint: b = ctypes_copy_uint(*(unsigned int *)buf); break;
   case Ctypes_Ulong: b = ctypes_copy_ulong(*(unsigned long *)buf); break;
   case Ctypes_Ullong: b = ctypes_copy_ullong(*(unsigned long long *)buf); break;
   case Ctypes_Size_t: b = ctypes_copy_size_t(*(size_t *)buf); break;
   case Ctypes_Int8_t: b = Val_int(*(int8_t *)buf); break;
   case Ctypes_Int16_t: b = Val_int(*(int16_t *)buf); break;
   case Ctypes_Int32_t: b = caml_copy_int32(*(int32_t *)buf); break;
   case Ctypes_Int64_t: b = caml_copy_int64(*(int64_t *)buf); break;
   case Ctypes_Uint8_t: b = Integers_val_uint8(*(uint8_t *)buf); break;
   case Ctypes_Uint16_t: b = Integers_val_uint16(*(uint16_t *)buf); break;
   case Ctypes_Uint32_t: b = integers_copy_uint32(*(uint32_t *)buf); break;
   case Ctypes_Uint64_t: b = integers_copy_uint64(*(uint64_t *)buf); break;
   case Ctypes_Camlint: b = Val_long(*(intnat *)buf); break;
   case Ctypes_Nativeint: b = caml_copy_nativeint(*(intnat *)buf); break;
   case Ctypes_Float: b = caml_copy_double(*(float *)buf); break;
   case Ctypes_Double: b = caml_copy_double(*(double *)buf); break;
   case Ctypes_LDouble: b = ctypes_copy_ldouble(*(long double *)buf); break;
   case Ctypes_Complex32: b = ctypes_copy_float_complex(*(float _Complex *)buf); break;
   case Ctypes_Complex64: b = ctypes_copy_double_complex(*(double _Complex *)buf); break;
   case Ctypes_Complexld: b = ctypes_copy_ldouble_complex(*(long double _Complex *)buf); break;
   default:
    assert(0);
  }
  CAMLreturn(b);
}

/* Read a C value from a block of memory */
/* write : 'a prim -> 'a -> fat_pointer -> unit */
CAMLprim value ctypes_write(value prim_, value v, value buffer_) /* noalloc */
{
  CAMLparam3(prim_, v, buffer_);
  void *buf = CTYPES_ADDR_OF_FATPTR(buffer_);
  switch (Int_val(prim_))
  {
   case Ctypes_Char: *(unsigned char *)buf = Int_val(v); break;
   case Ctypes_Schar: *(signed char *)buf = Int_val(v); break;
   case Ctypes_Uchar: *(unsigned char *)buf = Uint8_val(v); break;
   case Ctypes_Bool: *(bool *)buf = Bool_val(v); break;
   case Ctypes_Short: *(short *)buf = Int_val(v); break;
   case Ctypes_Int: *(int *)buf = Int_val(v); break;
   case Ctypes_Long: *(long *)buf = ctypes_long_val(v); break;
   case Ctypes_Llong: *(long long *)buf = ctypes_llong_val(v); break;
   case Ctypes_Ushort: *(unsigned short *)buf = ctypes_ushort_val(v); break;
   case Ctypes_Sint: *(int *)buf = ctypes_sint_val(v); break;
   case Ctypes_Uint: *(unsigned int *)buf = ctypes_uint_val(v); break;
   case Ctypes_Ulong: *(unsigned long *)buf = ctypes_ulong_val(v); break;
   case Ctypes_Ullong: *(unsigned long long *)buf = ctypes_ullong_val(v); break;
   case Ctypes_Size_t: *(size_t *)buf = ctypes_size_t_val(v); break;
   case Ctypes_Int8_t: *(int8_t *)buf = Int_val(v); break;
   case Ctypes_Int16_t: *(int16_t *)buf = Int_val(v); break;
   case Ctypes_Int32_t: *(int32_t *)buf = Int32_val(v); break;
   case Ctypes_Int64_t: *(int64_t *)buf = Int64_val(v); break;
   case Ctypes_Uint8_t: *(uint8_t *)buf = Uint8_val(v); break;
   case Ctypes_Uint16_t: *(uint16_t *)buf = Uint16_val(v); break;
   case Ctypes_Uint32_t: *(uint32_t *)buf = Uint32_val(v); break;
   case Ctypes_Uint64_t: *(uint64_t *)buf = Uint64_val(v); break;
   case Ctypes_Camlint: *(intnat *)buf = Long_val(v); break;
   case Ctypes_Nativeint: *(intnat *)buf = Nativeint_val(v); break;
   case Ctypes_Float: *(float *)buf = Double_val(v); break;
   case Ctypes_Double: *(double *)buf = Double_val(v); break;
   case Ctypes_LDouble: *(long double *)buf = ctypes_ldouble_val(v); break;
   case Ctypes_Complex32: *(float _Complex *)buf = ctypes_float_complex_val(v); break;
   case Ctypes_Complex64: *(double _Complex *)buf = ctypes_double_complex_val(v); break;
   case Ctypes_Complexld: *(long double _Complex *)buf = ctypes_ldouble_complex_val(v); break;
   default:
    assert(0);
  }
  CAMLreturn(Val_unit);
}

/* Format a C value */
/* string_of_prim : 'a prim -> 'a -> string */
CAMLprim value ctypes_string_of_prim(value prim_, value v)
{
  CAMLparam2(prim_, v);
  CAMLlocal1(s);
  char buf[64];
  int len = 0;
  switch (Int_val(prim_))
  {
  case Ctypes_Char: len = snprintf(buf, sizeof buf, "'%c'", Int_val(v)); break;
  case Ctypes_Schar: len = snprintf(buf, sizeof buf, "%d", Int_val(v)); break;
  case Ctypes_Uchar: len = snprintf(buf, sizeof buf, "%d", (unsigned char)Uint8_val(v)); break;
  case Ctypes_Bool: len = snprintf(buf, sizeof buf, "%s", Bool_val(v) ? "true" : "false"); break;
  case Ctypes_Short: len = snprintf(buf, sizeof buf, "%hd", (short)Int_val(v)); break;
  case Ctypes_Int: len = snprintf(buf, sizeof buf, "%d", Int_val(v)); break;
  case Ctypes_Long: len = snprintf(buf, sizeof buf, "%ld", (long)ctypes_long_val(v)); break;
  case Ctypes_Llong: len = snprintf(buf, sizeof buf, "%lld", (long long)ctypes_llong_val(v)); break;
  case Ctypes_Ushort: len = snprintf(buf, sizeof buf, "%hu", (unsigned short)ctypes_ushort_val(v)); break;
  case Ctypes_Sint: len = snprintf(buf, sizeof buf, "%d", ctypes_sint_val(v)); break;
  case Ctypes_Uint: len = snprintf(buf, sizeof buf, "%u", (unsigned)ctypes_uint_val(v)); break;
  case Ctypes_Ulong: len = snprintf(buf, sizeof buf, "%lu", (unsigned long)ctypes_ulong_val(v)); break;
  case Ctypes_Ullong: len = snprintf(buf, sizeof buf, "%llu", (unsigned long long)ctypes_ullong_val(v)); break;
  case Ctypes_Size_t: len = snprintf(buf, sizeof buf, "%zu", (size_t)ctypes_size_t_val(v)); break;
  case Ctypes_Int8_t: len = snprintf(buf, sizeof buf, "%" PRId8, (int8_t)Int_val(v)); break;
  case Ctypes_Int16_t: len = snprintf(buf, sizeof buf, "%" PRId16, (int16_t)Int_val(v)); break;
  case Ctypes_Int32_t: len = snprintf(buf, sizeof buf, "%" PRId32, Int32_val(v)); break;
  case Ctypes_Int64_t: len = snprintf(buf, sizeof buf, "%" PRId64, (int64_t)Int64_val(v)); break;
  case Ctypes_Uint8_t: len = snprintf(buf, sizeof buf, "%" PRIu8, Uint8_val(v)); break;
  case Ctypes_Uint16_t: len = snprintf(buf, sizeof buf, "%" PRIu16, Uint16_val(v)); break;
  case Ctypes_Uint32_t: len = snprintf(buf, sizeof buf, "%" PRIu32, Uint32_val(v)); break;
  case Ctypes_Uint64_t: len = snprintf(buf, sizeof buf, "%" PRIu64, Uint64_val(v)); break;
  case Ctypes_Camlint: len = snprintf(buf, sizeof buf, "%" REAL_ARCH_INTNAT_PRINTF_FORMAT "d",
                         (intnat)Long_val(v)); break;
  case Ctypes_Nativeint: len = snprintf(buf, sizeof buf, "%" REAL_ARCH_INTNAT_PRINTF_FORMAT "d",
                           (intnat)Nativeint_val(v)); break;
  case Ctypes_Float: len = snprintf(buf, sizeof buf, "%.12g", Double_val(v)); break;
  case Ctypes_Double: len = snprintf(buf, sizeof buf, "%.12g", Double_val(v)); break;
  case Ctypes_LDouble: len = snprintf(buf, sizeof buf, "%.12Lg", ctypes_ldouble_val(v)); break;
  case Ctypes_Complex32: {
    float _Complex c = ctypes_float_complex_val(v);
    len = snprintf(buf, sizeof buf, "%.12g+%.12gi", ctypes_compat_crealf(c), ctypes_compat_cimagf(c));
    break;
  }
  case Ctypes_Complex64: {
    double _Complex c = ctypes_double_complex_val(v);
    len = snprintf(buf, sizeof buf, "%.12g+%.12gi", ctypes_compat_creal(c), ctypes_compat_cimag(c));
    break;
  }
  case Ctypes_Complexld: {
    long double _Complex c = ctypes_ldouble_complex_val(v);
    len = snprintf(buf, sizeof buf, "%.12Lg+%.12Lgi", ctypes_compat_creall(c), ctypes_compat_cimagl(c));
    break;
  }
  default:
    assert(0);
  }
  s = caml_alloc_string(len);
  memcpy((char *)String_val(s), buf, len);
  CAMLreturn (s);
}

/* read_pointer : fat_pointer -> raw_pointer */
CAMLprim value ctypes_read_pointer(value src_)
{
  CAMLparam1(src_);
  void *src = CTYPES_ADDR_OF_FATPTR(src_);
  CAMLreturn(CTYPES_FROM_PTR(*(void **)src));
}

/* write_pointer : fat_pointer -> dst:fat_pointer -> unit */
CAMLprim value ctypes_write_pointer(value p_, value dst_)
{
  CAMLparam2(p_, dst_);
  void *dst = CTYPES_ADDR_OF_FATPTR(dst_);
  *(void **)dst = CTYPES_ADDR_OF_FATPTR(p_);
  CAMLreturn(Val_unit);
}

/* string_of_pointer : fat_pointer -> string */
CAMLprim value ctypes_string_of_pointer(value p_)
{
  char buf[32];
  CAMLparam1(p_);
  snprintf(buf, sizeof buf, "%p", CTYPES_ADDR_OF_FATPTR(p_));
  CAMLreturn (caml_copy_string(buf));
}

#define EXPOSE_TYPEINFO_COMMON(TYPENAME,STYPENAME)           \
  value ctypes_typeof_ ## TYPENAME(value unit)               \
  {                                                          \
    enum ctypes_arithmetic_type underlying =                 \
      CTYPES_CLASSIFY_ARITHMETIC_TYPE(STYPENAME);            \
    return Val_int(underlying);                              \
  }

#define EXPOSE_ALIGNMENT_COMMON(TYPENAME,STYPENAME)          \
  value ctypes_alignmentof_ ## TYPENAME(value unit)          \
  {                                                          \
    struct s { char c; STYPENAME t; };                       \
    return Val_int(offsetof(struct s, t));                   \
  }

#define EXPOSE_TYPESIZE_COMMON(TYPENAME,STYPENAME)           \
  value ctypes_sizeof_ ## TYPENAME(value unit)               \
  {                                                          \
    return Val_int(sizeof(STYPENAME));                       \
  }

#if !defined _WIN32 || defined __CYGWIN__
  #define UNDERSCORE(X) X
#else
  #define UNDERSCORE(X) _## X
#endif

#define EXPOSE_TYPEINFO(X) EXPOSE_TYPEINFO_COMMON(X, X)
#define EXPOSE_TYPEINFO_S(X) EXPOSE_TYPEINFO_COMMON(X, UNDERSCORE(X))
#define EXPOSE_TYPESIZE(X) EXPOSE_TYPESIZE_COMMON(X, X)
#define EXPOSE_TYPESIZE_S(X) EXPOSE_TYPESIZE_COMMON(X, UNDERSCORE(X))
#define EXPOSE_ALIGNMENT(X) EXPOSE_ALIGNMENT_COMMON(X, X)
#define EXPOSE_ALIGNMENT_S(X) EXPOSE_ALIGNMENT_COMMON(X, UNDERSCORE(X))

#ifdef __NetBSD__
/* NetBSD defines these types as macros, which expands to the wrong thing
 * in the EXPOSE_* macros above. I have no idea how to prevent cpp from
 * expanding macro arguments, so just hack around it for now. */
#undef off_t
#undef mode_t
#undef pid_t
typedef __off_t off_t;
typedef __mode_t mode_t;
typedef __pid_t pid_t;
#endif

EXPOSE_TYPEINFO(clock_t)
EXPOSE_TYPEINFO_S(dev_t)
EXPOSE_TYPEINFO_S(ino_t)
EXPOSE_TYPEINFO_S(mode_t)
EXPOSE_TYPEINFO_S(off_t)
EXPOSE_TYPEINFO_S(pid_t)
EXPOSE_TYPEINFO(ssize_t)
EXPOSE_TYPEINFO(time_t)
EXPOSE_TYPEINFO(useconds_t)
#if !defined _WIN32 || defined __CYGWIN__
  EXPOSE_TYPEINFO(nlink_t)
#else
  /* the mingw port of fts uses an int for nlink_t */
  EXPOSE_TYPEINFO_COMMON(nlink_t, int)
#endif


EXPOSE_TYPESIZE_S(sigset_t)
EXPOSE_ALIGNMENT_S(sigset_t)
