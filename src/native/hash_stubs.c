#include "mirage_crypto.h"

#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"

#include <stdio.h>
#include <caml/mlvalues.h>
#include <caml/bigarray.h>

#define __define_hash(name, upper)                                           \
                                                                             \
  CAMLprim value                                                             \
  mc_ ## name ## _init (value ctx) {                                         \
    _mc_ ## name ## _init ((struct name ## _ctx *) Bytes_val (ctx));         \
    return Val_unit;                                                         \
  }                                                                          \
                                                                             \
  CAMLprim value                                                             \
  mc_ ## name ## _update (value ctx, value src, value off, value len) {      \
    int num_elts_input = 1;                                                  \
    for (int i = 0; i < Caml_ba_array_val(src)->num_dims; i++) num_elts_input = num_elts_input * Caml_ba_array_val(src)->dim[i];\
    printf("UPDATE => ctx : %p | &ctx->h[0] : %p | ba : %p | off : %lu | len : %d | num_elts_input : %d | num_dims : %d\n", Bytes_val(ctx), &(((struct name ## _ctx *) Bytes_val(ctx))->buf[0]), ((uint8_t*) Caml_ba_data_val (src)), Long_val (off), Int_val(len), num_elts_input, Caml_ba_array_val(src)->num_dims);\
    _mc_ ## name ## _update (                                                \
      (struct name ## _ctx *) Bytes_val (ctx),                               \
      _ba_uint8_off (src, off), Int_val (len));                              \
    return Val_unit;                                                         \
  }                                                                          \
                                                                             \
  CAMLprim value                                                             \
  mc_ ## name ## _finalize (value ctx, value dst, value off) {               \
    int num_elts_input = 1;                                                  \
    for (int i = 0; i < Caml_ba_array_val(dst)->num_dims; i++) num_elts_input = num_elts_input * Caml_ba_array_val(dst)->dim[i];\
    printf("FINALIZE => ctx : %p | dst : %p | off : %lu | num_elts_input : %d | num_dims : %d\n", Bytes_val(ctx), ((uint8_t*) Caml_ba_data_val (dst)), Long_val (off), num_elts_input, Caml_ba_array_val(dst)->num_dims);\
    _mc_ ## name ## _finalize (                                              \
      (struct name ## _ctx *) Bytes_val (ctx), _ba_uint8_off (dst, off));    \
    return Val_unit;                                                         \
  }                                                                          \
                                                                             \
  CAMLprim value                                                             \
  mc_ ## name ## _ctx_size (__unit ()) {                                     \
    return Val_int (upper ## _CTX_SIZE);                                     \
  }

__define_hash (md5, MD5)
__define_hash (sha1, SHA1)
__define_hash (sha224, SHA224)
__define_hash (sha256, SHA256)
__define_hash (sha384, SHA384)
__define_hash (sha512, SHA512)
