#include <stdint.h>
#define CAML_INTERNALS
#include "caml/mlvalues.h"
#include "caml/hash.h"
#include "caml/backtrace.h"
#include "caml/alloc.h"
#include "caml/memory.h"

/* The default [Base_am_testing] value is [false]. [ppx_inline_test] overrides
   the default by linking against an implementation of [Base_am_testing] that 
   returns [true]. */
CAMLprim CAMLweakdef value Base_am_testing()
{
  return Val_false;
}

/* This pretends that the state of the OCaml internal hash function, which is an
   int32, is actually stored in an OCaml int. */

CAMLprim value Base_internalhash_fold_int32(value st, value i)
{
  return Val_long(caml_hash_mix_uint32(Long_val(st), Int32_val(i)));
}

CAMLprim value Base_internalhash_fold_nativeint(value st, value i)
{
  return Val_long(caml_hash_mix_intnat(Long_val(st), Nativeint_val(i)));
}

CAMLprim value Base_internalhash_fold_int64(value st, value i)
{
  return Val_long(caml_hash_mix_int64(Long_val(st), Int64_val(i)));
}

CAMLprim value Base_internalhash_fold_int(value st, value i)
{
  return Val_long(caml_hash_mix_intnat(Long_val(st), Long_val(i)));
}

CAMLprim value Base_internalhash_fold_float(value st, value i)
{
  return Val_long(caml_hash_mix_double(Long_val(st), Double_val(i)));
}

/* This code mimics what hashtbl.hash does in OCaml's hash.c */
#define FINAL_MIX(h)                            \
  h ^= h >> 16; \
  h *= 0x85ebca6b; \
  h ^= h >> 13; \
  h *= 0xc2b2ae35; \
  h ^= h >> 16;

CAMLprim value Base_internalhash_get_hash_value(value st)
{
  uint32_t h = Int_val(st);
  FINAL_MIX(h);
  return Val_int(h & 0x3FFFFFFFU); /*30 bits*/
}

/* Macros copied from hash.c in ocaml distribution */
#define ROTL32(x,n) ((x) << n | (x) >> (32-n))

#define MIX(h,d)   \
  d *= 0xcc9e2d51; \
  d = ROTL32(d, 15); \
  d *= 0x1b873593; \
  h ^= d; \
  h = ROTL32(h, 13); \
  h = h * 5 + 0xe6546b64;

/* Version of [caml_hash_mix_string] from hash.c - adapted for arbitrary char arrays */
CAMLexport uint32_t Base_internalhash_fold_blob(uint32_t h, mlsize_t len, uint8_t *s)
{
  mlsize_t i;
  uint32_t w;

  /* Mix by 32-bit blocks (little-endian) */
  for (i = 0; i + 4 <= len; i += 4) {
#ifdef ARCH_BIG_ENDIAN
    w = s[i]
      | (s[i+1] << 8)
      | (s[i+2] << 16)
      | (s[i+3] << 24);
#else
    w = *((uint32_t *) &(s[i]));
#endif
    MIX(h, w);
  }
  /* Finish with up to 3 bytes */
  w = 0;
  switch (len & 3) {
  case 3: w  = s[i+2] << 16;   /* fallthrough */
  case 2: w |= s[i+1] << 8;    /* fallthrough */
  case 1: w |= s[i];
          MIX(h, w);
  default: /*skip*/;     /* len & 3 == 0, no extra bytes, do nothing */
  }
  /* Finally, mix in the length. Ignore the upper 32 bits, generally 0. */
  h ^= (uint32_t) len;
  return h;
}

CAMLprim value Base_internalhash_fold_string(value st, value v_str)
{
  uint32_t h = Long_val(st);
  mlsize_t len = caml_string_length(v_str);
  uint8_t *s = (uint8_t *) String_val(v_str);

  h = Base_internalhash_fold_blob(h, len, s);

  return Val_long(h);
}

/* Final mix and return from the hash.c implementation from INRIA */
#define FINAL_MIX_AND_RETURN(h) \
  h ^= h >> 16; \
  h *= 0x85ebca6b; \
  h ^= h >> 13; \
  h *= 0xc2b2ae35; \
  h ^= h >> 16; \
  return Val_int(h & 0x3FFFFFFFU);

CAMLprim value Base_hash_string (value string)
{
  uint32_t h;
  h = caml_hash_mix_string (0, string);
  FINAL_MIX_AND_RETURN(h)
}

CAMLprim value Base_hash_double (value d)
{
  uint32_t h;
  h = caml_hash_mix_double (0, Double_val(d));
  FINAL_MIX_AND_RETURN (h);
}

CAMLprim value Base_clear_caml_backtrace_pos () {
  caml_backtrace_pos = 0;
  return Val_unit;
}

CAMLprim value Base_caml_exn_is_most_recent_exn (value exn) {
  return Val_bool(Caml_state->backtrace_last_exn == exn);
}

#ifdef _MSC_VER

#include <intrin.h>

#define __builtin_popcountll __popcnt64
#define __builtin_popcount   __popcnt

static int __inline __builtin_clz(uint32_t x)
{
  int r = 0;
  _BitScanForward(&r, x);
  return r;
}

static int __inline __builtin_clzll(uint64_t x)
{
  int r = 0;
#ifdef _WIN64
  _BitScanForward64(&r, x);
#else
  if (!_BitScanForward(&r, (uint32_t)x) &&
      _BitScanForward(&r, (uint32_t)(x>>32))) {
    r += 32;
  }
#endif
  return r;
}

static uint32_t __inline __builtin_ctz(uint32_t x)
{
  int r = 0;
  _BitScanReverse(&r, x);
  return r;
}

static uint64_t __inline __builtin_ctzll(uint64_t x)
{
  int r = 0;
  _BitScanReverse64(&r, x);
  return r;
}

#endif

static int64_t int_pow(int64_t base, int64_t exponent) {
  int64_t ret = 1;
  int64_t mul[4];
  mul[0] = 1;
  mul[1] = base;
  mul[3] = 1;

  while(exponent != 0) {
    mul[1] *= mul[3];
    mul[2] = mul[1] * mul[1];
    mul[3] = mul[2] * mul[1];
    ret *= mul[exponent & 3];
    exponent >>= 2;
  }

  return ret;
}

CAMLprim value Base_int_math_int_pow_stub(value base, value exponent) {
  return (Val_long(int_pow(Long_val(base), Long_val(exponent))));
}

CAMLprim value Base_int_math_int64_pow_stub(value base, value exponent) {
  CAMLparam2(base, exponent);
  CAMLreturn(caml_copy_int64(int_pow(Int64_val(base), Int64_val(exponent))));
}

/* This implementation is faster than [__builtin_popcount(v) - 1], even though
 * it seems more complicated.  The [&] clears the shifted sign bit after
 * [Long_val] or [Int_val]. */
CAMLprim value Base_int_math_int_popcount(value v) {
#ifdef ARCH_SIXTYFOUR
  return Val_int (__builtin_popcountll (Long_val (v) & ~((uint64_t)1 << 63)));
#else
  return Val_int (__builtin_popcount   (Int_val  (v) & ~((uint32_t)1 << 31)));
#endif
}

/* The specification of all below [clz] and [ctz] functions are undefined for [v = 0]. */

/*
 * For an int [x] in the [2n + 1] representation:
 *
 *   clz(x) = __builtin_clz(x >> 1) - 1
 *
 * If [x] is negative, then the macro [Int_val] would perform a arithmetic
 * shift right, rather than a logical shift right, and sign extend the number.
 * Therefore
 *
 *   __builtin_clz(Int_val(x))
 *
 *  would always be zero, so
 *
 *    clz(x) = __builtin_clz(Int_val(x)) - 1
 *
 *  would always be -1. This is not what we want.
 *
 *  The logical shift right adds a leading zero to the argument of
 *  __builtin_clz, which the -1 accounts for. Rather than adding the leading
 *  zero and subtracting, we can just compute the clz of the tagged
 *  representation, and that should be equivalent, while also handing negative
 *  inputs correctly (the result will now be 0).
 */
intnat Base_int_math_int_clz_untagged(value v) {
#ifdef ARCH_SIXTYFOUR
  return __builtin_clzll (v);
#else
  return __builtin_clz   (v);
#endif
}

CAMLprim value Base_int_math_int_clz(value v) {
  return Val_int (Base_int_math_int_clz_untagged (v));
}

intnat Base_int_math_int32_clz_unboxed(int32_t v) {
  return __builtin_clz (v);
}

CAMLprim value Base_int_math_int32_clz(value v) {
  return Val_int (Base_int_math_int32_clz_unboxed (Int32_val(v)));
}

intnat Base_int_math_int64_clz_unboxed(int64_t v) {
  return __builtin_clzll (v);
}

CAMLprim value Base_int_math_int64_clz(value v) {
  return Val_int (Base_int_math_int64_clz_unboxed (Int64_val(v)));
}

intnat Base_int_math_nativeint_clz_unboxed(intnat v) {
#ifdef ARCH_SIXTYFOUR
  return __builtin_clzll (v);
#else
  return __builtin_clz   (v);
#endif
}

CAMLprim value Base_int_math_nativeint_clz(value v) {
  return Val_int (Base_int_math_nativeint_clz_unboxed (Nativeint_val(v)));
}

intnat Base_int_math_int_ctz_untagged(intnat v) {
#ifdef ARCH_SIXTYFOUR
  return __builtin_ctzll (v);
#else
  return __builtin_ctz   (v);
#endif
}

CAMLprim value Base_int_math_int_ctz(value v) {
  return Val_int (Base_int_math_int_ctz_untagged (Int_val(v)));
}

intnat Base_int_math_int32_ctz_unboxed(int32_t v) {
  return __builtin_ctz (v);
}

CAMLprim value Base_int_math_int32_ctz(value v) {
  return Val_int (Base_int_math_int32_ctz_unboxed (Int32_val(v)));
}

intnat Base_int_math_int64_ctz_unboxed(int64_t v) {
  return __builtin_ctzll (v);
}

CAMLprim value Base_int_math_int64_ctz(value v) {
  return Val_int (Base_int_math_int64_ctz_unboxed (Int64_val(v)));
}

intnat Base_int_math_nativeint_ctz_unboxed(intnat v) {
#ifdef ARCH_SIXTYFOUR
  return __builtin_ctzll (v);
#else
  return __builtin_ctz   (v);
#endif
}

CAMLprim value Base_int_math_nativeint_ctz(value v) {
  return Val_int (Base_int_math_nativeint_ctz_unboxed (Nativeint_val(v)));
}
