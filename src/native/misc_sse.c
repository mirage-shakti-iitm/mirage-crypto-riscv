#include "mirage_crypto.h"


#include <stdint.h>
#include <string.h>
#include <caml/mlvalues.h>
#include <caml/bigarray.h>

#ifdef __mc_ACCELERATE__

static inline void xor_into (uint8_t *src, uint8_t *dst, size_t n) {
#ifdef ARCH_64BIT
  __m128i r;
  for (; n >= 16; n -= 16, src += 16, dst += 16)
    _mm_storeu_si128 (
        (__m128i*) dst,
        _mm_xor_si128 (
          _mm_loadu_si128 ((__m128i*) memcpy(&r, src, 16)),
          _mm_loadu_si128 ((__m128i*) dst)));

  uint64_t s;
  for (; n >= 8; n -= 8, src += 8, dst += 8)
    *(uint64_t*) dst ^= *(uint64_t*) memcpy(&s, src, 8);
#endif

  uint32_t t;
  for (; n >= 4; n -= 4, src += 4, dst += 4)
    *(uint32_t*) dst ^= *(uint32_t*)memcpy(&t, src, 4);

  for (; n --; ++ src, ++ dst) *dst = *src ^ *dst;
}

/* The GCM counter. Counts on the last 32 bits, ignoring carry. */
static inline void _mc_count_16_be_4 (uint64_t *init, uint64_t *dst, size_t blocks) {

  __m128i ctr, c1   = _mm_set_epi32 (1, 0, 0, 0),
               mask = _mm_set_epi64x (0x0c0d0e0f0b0a0908, 0x0706050403020100);
  ctr = _mm_shuffle_epi8 (_mm_loadu_si128 ((__m128i *) init), mask);
  for (; blocks --; dst += 2) {
    _mm_storeu_si128 ((__m128i *) dst, _mm_shuffle_epi8 (ctr, mask));
    ctr = _mm_add_epi32 (ctr, c1);
  }
}

#endif /* __mc_ACCELERATE__ */

#ifdef FREESTANDING_CRYPTO

extern void xor_into (__int128 src, __int128 dst, size_t n);
extern void _mc_count_8_be (__int128 init, __int128 dst, size_t blocks);
extern void _mc_count_16_be (__int128 init, __int128 dst, size_t blocks);
extern void _mc_count_16_be_4 (__int128 init, __int128 dst, size_t blocks);

/*************************************************************** misc.c ***************************************************************/ 
CAMLprim value
mc_xor_into_generic (value b1, value off1, value b2, value off2, value n) {
  int num_elts_b1 = 1;
  for (int i = 0; i < Caml_ba_array_val(b1)->num_dims; i++) num_elts_b1 = num_elts_b1 * Caml_ba_array_val(b1)->dim[i];
  __int128 b1_off_fpr = craft(_ba_uint8_off (b1, off1), _ba_uint8 (b1), (uint8_t*)((_ba_uint8 (b1))+num_elts_b1), 0);

  int num_elts_b2 = 1;
  for (int i = 0; i < Caml_ba_array_val(b2)->num_dims; i++) num_elts_b2 = num_elts_b2 * Caml_ba_array_val(b2)->dim[i];
  __int128 b2_off_fpr = craft(_ba_uint8_off (b2, off1), _ba_uint8 (b2), (uint8_t*)((_ba_uint8 (b2))+num_elts_b2), 0);
  
  xor_into(b1_off_fpr, b2_off_fpr, Int_val(n));
  // xor_into (_ba_uint8_off (b1, off1), _ba_uint8_off (b2, off2), Int_val (n));
  return Val_unit;
}

CAMLprim value mc_count_16_be_4_generic (value ctr, value dst, value off, value blocks) {  
  int num_elts_dst = 1;
  for (int i = 0; i < Caml_ba_array_val(dst)->num_dims; i++) num_elts_dst = num_elts_dst * Caml_ba_array_val(dst)->dim[i];
  __int128 dst_off_fpr = craft(_ba_uint8_off (dst, off), _ba_uint8 (dst), (uint8_t*)((_ba_uint8 (dst))+num_elts_dst), 0);

  // some places 16 bytes allocated, some places only 8 bytes. How to get lenght from Bp_val()
  __int128 ctr_16_fpr = craft(Bp_val (ctr), Bp_val (ctr), (char*)((char*)(Bp_val (ctr))+16), 0);
  
  _mc_count_16_be_4(ctr_16_fpr, dst_off_fpr, Long_val (blocks));
  // _mc_count_16_be_4 ( (uint64_t*) Bp_val (ctr), (uint64_t*) _ba_uint8_off (dst, off), Long_val (blocks) );
  return Val_unit;
}

CAMLprim value mc_count_16_be (value ctr, value dst, value off, value blocks) {  
  int num_elts_dst = 1;
  for (int i = 0; i < Caml_ba_array_val(dst)->num_dims; i++) num_elts_dst = num_elts_dst * Caml_ba_array_val(dst)->dim[i];
  __int128 dst_off_fpr = craft(_ba_uint8_off (dst, off), _ba_uint8 (dst), (uint8_t*)((_ba_uint8 (dst))+num_elts_dst), 0);

  // some places 16 bytes allocated, some places only 8 bytes. How to get lenght from Bp_val()
  __int128 ctr_16_fpr = craft(Bp_val (ctr), Bp_val (ctr), (char*)((char*)(Bp_val (ctr))+16), 0);
  
  _mc_count_16_be(ctr_16_fpr, dst_off_fpr, Long_val (blocks));
  // _mc_count_16_be ( (uint64_t*) Bp_val (ctr), (uint64_t*) _ba_uint8_off (dst, off), Long_val (blocks) );
  return Val_unit;
}

CAMLprim value mc_count_8_be (value ctr, value dst, value off, value blocks) {  
  int num_elts_dst = 1;
  for (int i = 0; i < Caml_ba_array_val(dst)->num_dims; i++) num_elts_dst = num_elts_dst * Caml_ba_array_val(dst)->dim[i];
  __int128 dst_off_fpr = craft(_ba_uint8_off (dst, off), _ba_uint8 (dst), (uint8_t*)((_ba_uint8 (dst))+num_elts_dst), 0);

  // some places 16 bytes allocated, some places only 8 bytes. How to get lenght from Bp_val()
  __int128 ctr_16_fpr = craft(Bp_val (ctr), Bp_val (ctr), (char*)((char*)(Bp_val (ctr))+16), 0);
  
  _mc_count_8_be(ctr_16_fpr, dst_off_fpr, Long_val (blocks));
  // _mc_count_8_be ( (uint64_t*) Bp_val (ctr), (uint64_t*) _ba_uint8_off (dst, off), Long_val (blocks) );
  return Val_unit;
}

// __export_counter (mc_count_8_be, _mc_count_8_be)
// __export_counter (mc_count_16_be, _mc_count_16_be)
// __export_counter (mc_count_16_be_4_generic, _mc_count_16_be_4)

/*************************************************************** misc.c ***************************************************************/

#endif // FREESTANDING_CRYPTO

CAMLprim value
mc_xor_into (value b1, value off1, value b2, value off2, value n) {
  // _mc_switch_accel(ssse3,
    mc_xor_into_generic(b1, off1, b2, off2, n);
    // xor_into (_ba_uint8_off (b1, off1), _ba_uint8_off (b2, off2), Int_val (n)))
  return Val_unit;
}

// #define __export_counter(name, f)
CAMLprim value mc_count_16_be_4 (value ctr, value dst, value off, value blocks) {  
    // _mc_switch_accel(ssse3,                                     
    mc_count_16_be_4_generic(ctr, dst, off, blocks);                           
    // _mc_count_16_be_4 ( (uint64_t*) Bp_val (ctr),
          // (uint64_t*) _ba_uint8_off (dst, off), Long_val (blocks) ))
    return Val_unit;
}

// __export_counter(mc_count_16_be_4, _mc_count_16_be_4)


CAMLprim value mc_misc_mode (__unit ()) {
  value enabled = 0;
  // _mc_switch_accel(ssse3,
    enabled = 0;
    // enabled = 1)
  return Val_int (enabled);
}

