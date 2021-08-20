#include "caml/memory.h"
#include "caml/alloc.h"
#include "caml/memory.h"
#include "caml/fail.h"
#include "caml/signals.h"
#include "caml/bigarray.h"

#define CAML_INTERNALS
#pragma GCC diagnostic ignored "-pedantic"
#include "caml/md5.h"
#include "caml/sys.h"
#undef CAML_INTERNALS

#include <errno.h>
#include <string.h>
#include <time.h>
#include "ocaml_utils.h"

#define NANOS_PER_SECOND 1000000000

#if defined(JSC_POSIX_TIMERS)

/* Note: this is imported noalloc if (and only if) ARCH_SIXTYFOUR is defined.
 * This is OK because caml_alloc_int63 doesn't actually allocate in that case. */
CAMLprim value time_now_nanoseconds_since_unix_epoch_or_zero()
{
  struct timespec ts;

  if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
    return caml_alloc_int63(0);
  else
    return caml_alloc_int63(NANOS_PER_SECOND * (uint64_t)ts.tv_sec + (uint64_t)ts.tv_nsec);
}

#else

#include <sys/types.h>
#include <sys/time.h>

CAMLprim value time_now_nanoseconds_since_unix_epoch_or_zero()
{
  struct timeval tp;
  if (gettimeofday(&tp, NULL) == -1)
    return caml_alloc_int63(0);
  else
    return caml_alloc_int63(NANOS_PER_SECOND * (uint64_t)tp.tv_sec + (uint64_t)tp.tv_usec * 1000);
}

#endif

/* #include <caml/io.h> */

/* The definition of channel should be kept in sync with upstream ocaml  */
/* Start of duplicated code from caml/io.h */
#ifndef IO_BUFFER_SIZE
#define IO_BUFFER_SIZE 65536
#endif

#if defined(_WIN32)
typedef __int64 file_offset;
#elif defined(HAS_OFF_T)
#include <sys/types.h>
typedef off_t file_offset;
#endif

// struct channel {
//   int fd;                       /* Unix file descriptor */
//   file_offset offset;           /* Absolute position of fd in the file */
//   char * end;                   /* Physical end of the buffer */
//   char * curr;                  /* Current position in the buffer */
//   char * max;                   /* Logical end of the buffer (for input) */
//   void * mutex;                 /* Placeholder for mutex (for systhreads) */
//   struct channel * next, * prev;/* Double chaining of channels (flush_all) */
//   int revealed;                 /* For Cash only */
//   int old_revealed;             /* For Cash only */
//   int refcount;                 /* For flush_all and for Cash */
//   int flags;                    /* Bitfield */
//   char buff[IO_BUFFER_SIZE];    /* The buffer itself */
//   char * name;                  /* Optional name (to report fd leaks) */
// };

#define Channel(v) (*((struct channel **) (Data_custom_val(v))))

/* End of duplicated code from caml/io.h */

/* Start of duplicated code from caml/sys.h */
#define NO_ARG Val_int(0)
CAMLextern void caml_sys_error (value);
/* End of duplicated code from caml/sys.h */

static int expect_test_collector_saved_stdout;
static int expect_test_collector_saved_stderr;

CAMLprim value expect_test_collector_before_test (value voutput, value vstdout, value vstderr) {
  struct channel* output = Channel(voutput);
  struct channel* cstdout = Channel(vstdout);
  struct channel* cstderr = Channel(vstderr);
  int fd, ret;
  fd = dup(cstdout->fd);
  if(fd == -1) caml_sys_error(NO_ARG);
  expect_test_collector_saved_stdout = fd;
  fd = dup(cstderr->fd);
  if(fd == -1) caml_sys_error(NO_ARG);
  expect_test_collector_saved_stderr = fd;
  ret = dup2(output->fd, cstdout->fd);
  if(ret == -1) caml_sys_error(NO_ARG);
  ret = dup2(output->fd, cstderr->fd);
  if(ret == -1) caml_sys_error(NO_ARG);
  return Val_unit;
}

CAMLprim value expect_test_collector_after_test (value vstdout, value vstderr) {
  struct channel* cstdout = Channel(vstdout);
  struct channel* cstderr = Channel(vstderr);
  int ret;
  ret = dup2(expect_test_collector_saved_stdout, cstdout->fd);
  if(ret == -1) caml_sys_error(NO_ARG);
  ret = dup2(expect_test_collector_saved_stderr, cstderr->fd);
  if(ret == -1) caml_sys_error(NO_ARG);
  ret = close(expect_test_collector_saved_stdout);
  if(ret == -1) caml_sys_error(NO_ARG);
  ret = close(expect_test_collector_saved_stderr);
  if(ret == -1) caml_sys_error(NO_ARG);
  return Val_unit;
}

CAMLprim value caml_out_channel_pos_fd (value vchan) {
  struct channel* chan = Channel(vchan);
  file_offset ret;
  caml_enter_blocking_section();
  ret = lseek(chan->fd, 0, SEEK_CUR);
  caml_leave_blocking_section();
  if (ret == -1) caml_sys_error(NO_ARG);
  if (ret > Max_long) caml_failwith("caml_out_channel_pos_fd: overflow");
  return Val_long(ret);
}

extern value Base_internalhash_fold_int32(value st, value i);

extern value Base_internalhash_fold_nativeint(value st, value i);

extern value Base_internalhash_fold_int64(value st, value i);

extern value Base_internalhash_fold_int(value st, value i);

extern value Base_internalhash_fold_float(value st, value i);

extern value Base_internalhash_get_hash_value(value st);

/* Version of [caml_hash_mix_string] from hash.c - adapted for arbitrary char arrays */
extern uint32_t Base_internalhash_fold_blob(uint32_t h, mlsize_t len, uint8_t *s);

extern value Base_internalhash_fold_string(value st, value v_str);

// bigstring 
#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#define bswap_16 OSSwapInt16
#define bswap_32 OSSwapInt32
#define bswap_64 OSSwapInt64
#elif __GLIBC__
#include <byteswap.h>
#include <malloc.h>
#elif __OpenBSD__
#include <sys/types.h>
#define bswap_16 swap16
#define bswap_32 swap32
#define bswap_64 swap64
#elif __CYGWIN__
#include <endian.h>
#endif

/* Bigarray flags for creating a [Bigstring.t] */
#define BASE_BIGSTRING_FLAGS (CAML_BA_CHAR | CAML_BA_C_LAYOUT)

/* Bytes_val is only available from 4.06 */
#ifndef Bytes_val
#define Bytes_val String_val
#endif

static inline char * get_bstr(value v_bstr, value v_pos)
{
  return (char *) Caml_ba_data_val(v_bstr) + Long_val(v_pos);
}

CAMLprim value bigstring_alloc (value v_gc_max_unused, value v_size)
{
  intnat size = Long_val(v_size);
  void * data = NULL;
  int flags = BASE_BIGSTRING_FLAGS | CAML_BA_MANAGED;
  intnat gc_max_unused = Long_val(v_gc_max_unused);
  intnat dims[1];
  dims[0] = size;

  if (gc_max_unused >= 0) {
    data = (void *) malloc(sizeof(char) * size);
    if (NULL == data) caml_raise_out_of_memory ();
    /* caml_adjust_gc_speed is also called by caml_ba_alloc below, but it will have
    * numerator 0 when data != NULL. Effectively, that call will have no effect if this
    * call is made. */
    caml_adjust_gc_speed(size, gc_max_unused);
  }

  return caml_ba_alloc (flags, 1, data, dims);
}

/* Checking memory-mapping */

CAMLprim value bigstring_is_mmapped_stub(value v_bstr)
{
  return
    Val_bool((Caml_ba_array_val(v_bstr)->flags & CAML_BA_MAPPED_FILE) != 0);
}

/* Blitting */

CAMLprim value bigstring_blit_string_bigstring_stub(
  value v_str, value v_src_pos, value v_bstr, value v_dst_pos, value v_len)
{
  const char *str = String_val(v_str) + Long_val(v_src_pos);
  char *bstr = get_bstr(v_bstr, v_dst_pos);
  memcpy(bstr, str, Long_val(v_len));
  return Val_unit;
}

CAMLprim value bigstring_blit_bytes_bigstring_stub(
  value v_str, value v_src_pos, value v_bstr, value v_dst_pos, value v_len)
{
  unsigned char *str = Bytes_val(v_str) + Long_val(v_src_pos);
  char *bstr = get_bstr(v_bstr, v_dst_pos);
  memcpy(bstr, str, Long_val(v_len));
  return Val_unit;
}

CAMLprim value bigstring_blit_bigstring_bytes_stub(
  value v_bstr, value v_src_pos, value v_str, value v_dst_pos, value v_len)
{
  char *bstr = get_bstr(v_bstr, v_src_pos);
  unsigned char *str = Bytes_val(v_str) + Long_val(v_dst_pos);
  memcpy(str, bstr, Long_val(v_len));
  return Val_unit;
}

CAMLprim value bigstring_blit_stub(
  value v_src, value v_src_pos, value v_dst, value v_dst_pos, value v_len)
{
  struct caml_ba_array *ba_src = Caml_ba_array_val(v_src);
  struct caml_ba_array *ba_dst = Caml_ba_array_val(v_dst);
  char *src = (char *) ba_src->data + Long_val(v_src_pos);
  char *dst = (char *) ba_dst->data + Long_val(v_dst_pos);
  size_t len = Long_val(v_len);
  memmove(dst, src, len);
  return Val_unit;
}

CAMLprim value bigstring_memset_stub(value v_t, value v_pos, value v_len, value v_char)
{
  struct caml_ba_array *ba_t = Caml_ba_array_val(v_t);
  char *buffer = ((char *) ba_t->data) + Long_val(v_pos);
  memset(buffer, Int_val(v_char), Long_val(v_len));

  return Val_unit;
}

/* Comparison */

static inline value caml_memcmp(unsigned char * s1, unsigned char * s2, size_t n)
{
  int res = memcmp(s1, s2, n);
  if (res < 0) return Val_int(-1);
  if (res > 0) return Val_int(1);
  return Val_int(0);
}

CAMLprim value bigstring_memcmp_stub(value v_s1, value v_s1_pos,
                                     value v_s2, value v_s2_pos,
                                     value v_len) /* noalloc */
{
  struct caml_ba_array *ba_s1 = Caml_ba_array_val(v_s1);
  struct caml_ba_array *ba_s2 = Caml_ba_array_val(v_s2);
  return caml_memcmp((unsigned char *) ba_s1->data + Long_val(v_s1_pos),
                     (unsigned char *) ba_s2->data + Long_val(v_s2_pos),
                     Long_val(v_len));
}

CAMLprim value bigstring_memcmp_bytes_stub(value v_bstr, value v_s1_pos,
                                           value v_bytes, value v_s2_pos,
                                           value v_len) /* noalloc */
{
  struct caml_ba_array *ba_s1 = Caml_ba_array_val(v_bstr);
  return caml_memcmp((unsigned char *) ba_s1->data + Long_val(v_s1_pos),
                     Bytes_val(v_bytes) + Long_val(v_s2_pos),
                     Long_val(v_len));
}

/* Hashing */

CAMLprim value internalhash_fold_bigstring(value st, value v_str) /* noalloc */
{
  uint32_t h = Long_val(st);

  struct caml_ba_array *ba = Caml_ba_array_val(v_str);
  uint8_t *s = (uint8_t *) ba->data;

  mlsize_t len = ba->dim[0];

  h = Base_internalhash_fold_blob(h, len, s);

  return Val_long(h);
}

/* Search */

CAMLprim value bigstring_find(value v_str, value v_needle,
                              value v_pos, value v_len)
{
  char *start, *r;
  intnat ret;

  start = get_bstr(v_str, v_pos);
  r = (char*) memchr(start, Int_val(v_needle), Long_val(v_len));

  if (!r) return Val_long(-1);

  ret = Long_val(v_pos) + r - start;
  return Val_long(ret);
}

CAMLprim value core_array_unsafe_int_blit(value src, value src_pos,
                                          value dst, value dst_pos, value len)
{
  /* On 32bit boxes ocaml values are 32bits long. On 64bit boxes OCaml
     values are 64bits long. The value type will change its size
     accordingly and hence the following macro works.
   */
  memmove(&Field(dst, Long_val(dst_pos)),
          &Field(src, Long_val(src_pos)),
          Long_val(len) * sizeof(value));

  return Val_unit;
}

CAMLprim value core_array_unsafe_float_blit(value src, value src_pos,
                                            value dst, value dst_pos, value len)
{
  /* On both 32bit and 64bit boxes, floats are 64bits long and type
     casting the pointer to double achieves this.
  */
  memmove((double *)dst + Long_val(dst_pos),
          (double *)src + Long_val(src_pos),
          Long_val(len) * sizeof(double));

  return Val_unit;
}

/* Bytes_val is only available from 4.06 */
#ifndef Bytes_val
#define Bytes_val String_val
#endif

/* Bigarray flags for creating a [Bigstring.t] */
#define CORE_BIGSTRING_FLAGS (CAML_BA_CHAR | CAML_BA_C_LAYOUT)

/* Do not call [unmap] for bigstrings with kind [CAML_BA_MAPPED_FILE] */
#define CORE_BIGSTRING_DESTROY_DO_NOT_UNMAP   1

/* Don't fail on bigstring with kind [CAML_BA_EXTERNAL] */
#define CORE_BIGSTRING_DESTROY_ALLOW_EXTERNAL 2

CAMLprim value
bigstring_realloc (value v_bstr, value v_size)
{
  CAMLparam2(v_bstr, v_size);
  CAMLlocal1(v_bstr2);
  struct caml_ba_array *ba = Caml_ba_array_val(v_bstr);
  intnat size = Long_val(v_size);
  int i;

  struct caml_ba_array *ba2;
  void *data;
  switch (ba->flags & CAML_BA_MANAGED_MASK) {
    case CAML_BA_EXTERNAL :
      caml_failwith("bigstring_realloc: bigstring is external or deallocated");
      break;
    case CAML_BA_MANAGED :
      if (ba->proxy != NULL) caml_failwith("bigstring_realloc: bigstring has proxy");
      break;
    case CAML_BA_MAPPED_FILE :
      caml_failwith("bigstring_realloc: bigstring is backed by memory map");
      break;
  }

  data = realloc(ba->data, sizeof(char) * size);
  /* realloc is equivalent to free when size is equal to zero, and may return NULL. */
  if (NULL == data && size != 0) caml_raise_out_of_memory ();

  v_bstr2 = caml_ba_alloc(ba->flags, ba->num_dims, data, ba->dim);
  ba2 = Caml_ba_array_val(v_bstr2);
  ba2->dim[0] = size;

  /* ba is a pointer into the OCaml heap, hence may have been invalidated by the
   * call to [caml_ba_alloc]. */
  ba = Caml_ba_array_val(v_bstr);
  ba->data = NULL;
  ba->flags = CAML_BA_EXTERNAL;
  for (i = 0; i < ba->num_dims; ++i) ba->dim[i] = 0;

  CAMLreturn(v_bstr2);
}

/* Destruction */

static void check_bigstring_proxy(struct caml_ba_array *b)
{
  if (b->proxy != NULL) caml_failwith("bigstring_destroy: bigstring has proxy");
}

void core_bigstring_destroy(value v, int flags)
{
  int i;
  struct caml_ba_array *b = Caml_ba_array_val(v);
  struct custom_operations* ops = Custom_ops_val(v);
  switch (b->flags & CAML_BA_MANAGED_MASK) {
    case CAML_BA_EXTERNAL :
      if ((flags & CORE_BIGSTRING_DESTROY_ALLOW_EXTERNAL)
           != CORE_BIGSTRING_DESTROY_ALLOW_EXTERNAL)
        caml_failwith("bigstring_destroy: bigstring is external or already deallocated");
      break;
    case CAML_BA_MANAGED :
      check_bigstring_proxy(b);
      free(b->data);
      break;
    case CAML_BA_MAPPED_FILE :
      check_bigstring_proxy(b);
      /* This call to finalize is actually a call to caml_ba_mapped_finalize
         (the finalize function for *mapped* bigarrays), which will unmap the
         array. (note: this is compatible with OCaml 4.06+) */
      if ((flags & CORE_BIGSTRING_DESTROY_DO_NOT_UNMAP)
          != CORE_BIGSTRING_DESTROY_DO_NOT_UNMAP) {
        if (ops->finalize != NULL) {
          ops->finalize(v);
        }
      }
      break;
  }
  b->data = NULL;
  b->flags = CAML_BA_EXTERNAL;
  for (i = 0; i < b->num_dims; ++i) b->dim[i] = 0;
}

CAMLprim value bigstring_destroy_stub(value v_bstr)
{
  core_bigstring_destroy(v_bstr, 0);
  return Val_unit;
}

/* Contrary to caml_md5_chan, this function releases the runtime lock.

   [fd] must be a file descriptor open for reading and not be
   nonblocking, otherwise the function might fail non-deterministically.
 */
CAMLprim value core_md5_fd(value fd)
{
  CAMLparam1 (fd);
  value res;
  struct MD5Context ctx;
  caml_enter_blocking_section();
  {
    intnat bytes_read;
    char buffer[4096];

    caml_MD5Init(&ctx);
    while (1){
      bytes_read = read (Int_val(fd), buffer, sizeof(buffer));
      if (bytes_read < 0) {
        if (errno == EINTR) continue;
        caml_leave_blocking_section();
        caml_sys_io_error(NO_ARG);
      }
      if (bytes_read == 0) break;
      caml_MD5Update (&ctx, (unsigned char *) buffer, bytes_read);
    }
  }
  caml_leave_blocking_section();
  res = caml_alloc_string(16);
  caml_MD5Final(&Byte_u(res, 0), &ctx);
  CAMLreturn (res);
}

/* Cutoff point at which we need to release the runtime lock. The idea is that computing
   the md5 of a large block is slow so it's worth releasing the runtime lock to allow the
   computation to happen in parallel with OCaml code.

   The divisor is obtained by running the "md5 vs memcpy" benchmarks and comparing the
   results.
*/
#define THREAD_IO_CUTOFF 65536
#define MD5_CUTOFF (THREAD_IO_CUTOFF / 50)

CAMLprim value core_md5_digest_subbigstring(value buf, value ofs, value vlen, value res)
{
  CAMLparam2(buf, res);
  struct MD5Context ctx;
  unsigned char *data = (unsigned char*)Caml_ba_data_val(buf) + Long_val(ofs);
  size_t len = Long_val(vlen);
  caml_MD5Init(&ctx);

  if (len > MD5_CUTOFF) caml_enter_blocking_section();
  caml_MD5Update(&ctx, data, len);
  if (len > MD5_CUTOFF) caml_leave_blocking_section();

  caml_MD5Final(&Byte_u(res, 0), &ctx);
  CAMLreturn(Val_unit);
}
