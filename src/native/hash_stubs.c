#include <stdio.h>
#include <caml/mlvalues.h>
#include <caml/bigarray.h>

#ifdef FREESTANDING_CRYPTO
#include <shakti_ms/fat_pointer.h>

// #include "mirage_crypto.h"
#define _ba_uint8_off(ba, off)  ((uint8_t*) Caml_ba_data_val (ba) + Long_val (off))
#define _ba_uint8(ba)  ((uint8_t*) Caml_ba_data_val (ba))

extern void _mc_md5_init(__int128 ctx);
extern void _mc_md5_update(__int128 ctx, __int128 data, uint32_t len);
extern void _mc_md5_finalize(__int128 ctx, __int128 out);

extern void _mc_sha1_init(__int128 ctx);
extern void _mc_sha1_update(__int128 ctx, __int128 data, uint32_t len);
extern void _mc_sha1_finalize(__int128 ctx, __int128 out);

extern void _mc_sha224_init(__int128 ctx);
extern void _mc_sha224_update(__int128 ctx, __int128 data, uint32_t len);
extern void _mc_sha224_finalize(__int128 ctx, __int128 out);

extern void _mc_sha256_init(__int128 ctx);
extern void _mc_sha256_update(__int128 ctx, __int128 data, uint32_t len);
extern void _mc_sha256_finalize(__int128 ctx, __int128 out);

extern void _mc_sha384_init(__int128 ctx);
extern void _mc_sha384_update(__int128 ctx, __int128 data, uint32_t len);
extern void _mc_sha384_finalize(__int128 ctx, __int128 out);

extern void _mc_sha512_init(__int128 ctx);
extern void _mc_sha512_update(__int128 ctx, __int128 data, uint32_t len);
extern void _mc_sha512_finalize(__int128 ctx, __int128 out);

/******************************************** MD5 ********************************************/
// #include "md5.h"

struct md5_ctx_fat_v
{
  uint64_t sz;
  __int128 buf; //[64];
  __int128 h; //[4];
};

struct md5_ctx_org
{
  uint64_t sz;
  uint8_t  buf[64];
  uint32_t h[4];
};

#define MD5_DIGEST_SIZE  16
#define MD5_CTX_SIZE   sizeof(struct md5_ctx_org)

  CAMLprim value                                                             
  mc_md5_init (value ctx) {                                         
    struct md5_ctx_org *ctx_org = (struct md5_ctx_org*) Bytes_val (ctx);  
                                                                             
    __int128 buf_fpr = safemalloc(64*sizeof(uint8_t));
    __int128 h_fpr = safemalloc(4*sizeof(uint32_t));                         
    uint8_t *buf = (uint8_t*)(buf_fpr & 0xffffffff);
    uint32_t *h = (uint32_t*)(h_fpr & 0xffffffff);
                                                                             
    __int128 ctx_new_fpr = safemalloc(sizeof(struct md5_ctx_fat_v));    
    struct md5_ctx_fat_v *ctx_new = (struct md5_ctx_fat_v*)(ctx_new_fpr & 0xffffffff); 
    ctx_new->sz = 0;                                                       
    ctx_new->buf = buf_fpr;                                                  
    ctx_new->h = h_fpr;                                                      
                                                                             
                                                                             
    _mc_md5_init (ctx_new_fpr);                                     
                                                                             
    for(int i=0; i<4; i++){                                                  
      ctx_org->h[i] = h[i];                                                  
    }                                                                        
    for(int i=0; i<64; i++){                                                
      ctx_org->buf[i] = buf[i];                                              
    }                                                                        
    ctx_org->sz = ctx_new->sz;                                           
                                                                             
    return Val_unit;                                                         
  }                                                                          
                                                                             
  CAMLprim value                                                             
  mc_md5_update (value ctx, value src, value off, value len) {      
    struct md5_ctx_org *ctx_org = (struct md5_ctx_org*) Bytes_val (ctx);  
                                                                             
    __int128 buf_fpr = safemalloc(64*sizeof(uint8_t));                      
    __int128 h_fpr = safemalloc(4*sizeof(uint32_t));                         
    uint8_t *buf = (uint8_t*)(buf_fpr & 0xffffffff);
    uint32_t *h = (uint32_t*)(h_fpr & 0xffffffff);
                                                                             
    __int128 ctx_new_fpr = safemalloc(sizeof(struct md5_ctx_fat_v));    
    struct md5_ctx_fat_v *ctx_new = (struct md5_ctx_fat_v*)(ctx_new_fpr & 0xffffffff); 
    ctx_new->sz = 0;                                                       
    ctx_new->buf = buf_fpr;                                                  
    ctx_new->h = h_fpr;                                                      
                                                                             
    for(int i=0; i<4; i++){                                                  
      h[i] = ctx_org->h[i];                                                  
    }                                                                        
    for(int i=0; i<64; i++){                                                
      buf[i] = ctx_org->buf[i];                                              
    }                                                                        
    ctx_new->sz = ctx_org->sz;                                           
                                                                             
    int num_elts_input = 1;                                                  
    for (int i = 0; i < Caml_ba_array_val(src)->num_dims; i++) num_elts_input = num_elts_input * Caml_ba_array_val(src)->dim[i];
                                                                             
    __int128 src_off_fpr = craft(_ba_uint8_off (src, off), (uint8_t*)Caml_ba_data_val(src), (uint8_t*)((uint8_t*)Caml_ba_data_val(src)+num_elts_input), 0); 
    _mc_md5_update(ctx_new_fpr, src_off_fpr, Int_val(len));          
    for(int i=0; i<4; i++){                                                  
      ctx_org->h[i] = h[i];                                                  
    }                                                                        
    for(int i=0; i<64; i++){                                                
      ctx_org->buf[i] = buf[i];                                              
    }                                                                        
    ctx_org->sz = ctx_new->sz;                                           
    return Val_unit;                                                         
  }                                                                          
                                                                             
  CAMLprim value                                                             
  mc_md5_finalize (value ctx, value dst, value off) {               
    struct md5_ctx_org *ctx_org = (struct md5_ctx_org*) Bytes_val (ctx);  
                                                                             
    __int128 buf_fpr = safemalloc(64*sizeof(uint8_t));                      
    __int128 h_fpr = safemalloc(4*sizeof(uint32_t));                         
    uint8_t *buf = (uint8_t*)(buf_fpr & 0xffffffff);
    uint32_t *h = (uint32_t*)(h_fpr & 0xffffffff);
                                                                             
    __int128 ctx_new_fpr = safemalloc(sizeof(struct md5_ctx_fat_v));    
    struct md5_ctx_fat_v *ctx_new = (struct md5_ctx_fat_v*)(ctx_new_fpr & 0xffffffff); 
    ctx_new->sz = 0;                                                       
    ctx_new->buf = buf_fpr;                                                  
    ctx_new->h = h_fpr;                                                      
                                                                             
    for(int i=0; i<4; i++){                                                  
      h[i] = ctx_org->h[i];                                                  
    }                                                                        
    for(int i=0; i<64; i++){                                                
      buf[i] = ctx_org->buf[i];                                              
    }                                                                        
    ctx_new->sz = ctx_org->sz;                                           
                                                                             
    int num_elts_input = 1;                                                  
    for (int i = 0; i < Caml_ba_array_val(dst)->num_dims; i++) num_elts_input = num_elts_input * Caml_ba_array_val(dst)->dim[i];
    __int128 dst_off_fpr = craft(_ba_uint8_off (dst, off), (uint8_t*)Caml_ba_data_val(dst), (uint8_t*)((uint8_t*)Caml_ba_data_val(dst)+num_elts_input), 0); 
    // printf("FINALIZE => ctx : %p | dst : %p | off : %lu | num_elts_input : %dn", Bytes_val(ctx), ((uint8_t*) Caml_ba_data_val (dst)), Long_val (off), num_elts_input);
                                                                             
    _mc_md5_finalize(ctx_new_fpr, dst_off_fpr);                     
    for(int i=0; i<4; i++){                                                  
      ctx_org->h[i] = h[i];                                                  
    }                                                                        
    for(int i=0; i<64; i++){                                                
      ctx_org->buf[i] = buf[i];                                              
    }                                                                        
    ctx_org->sz = ctx_new->sz;                                           
    return Val_unit;                                                         
  }                                                                          
                                                                             
  CAMLprim value                                                             
  mc_md5_ctx_size (__unit ()) {                                     
    return Val_int (MD5_CTX_SIZE);                                     
  }                                                                          


/******************************************** SHA1 ********************************************/
// #include "sha1.h"


struct sha1_ctx_fat_v
{
  uint64_t sz;
  __int128 buf; //[64];
  __int128 h; //[5];
};

struct sha1_ctx_org
{
  uint64_t sz;
  uint8_t  buf[64];
  uint32_t h[5];
};                                                                      

#define SHA1_DIGEST_SIZE  20
#define SHA1_CTX_SIZE   sizeof(struct sha1_ctx_org)


  CAMLprim value                                                             
  mc_sha1_init (value ctx) {                                         
    struct sha1_ctx_org *ctx_org = (struct sha1_ctx_org*) Bytes_val (ctx);  
                                                                             
    __int128 buf_fpr = safemalloc(64*sizeof(uint8_t));                      
    __int128 h_fpr = safemalloc(5*sizeof(uint32_t));                         
    uint8_t *buf = (uint8_t*)(buf_fpr & 0xffffffff);
    uint32_t *h = (uint32_t*)(h_fpr & 0xffffffff);
                                                                             
    __int128 ctx_new_fpr = safemalloc(sizeof(struct sha1_ctx_fat_v));    
    struct sha1_ctx_fat_v *ctx_new = (struct sha1_ctx_fat_v*)(ctx_new_fpr & 0xffffffff); 
    ctx_new->sz = 0;                                                       
    ctx_new->buf = buf_fpr;                                                  
    ctx_new->h = h_fpr;                                                      
                                                                             
                                                                             
    _mc_sha1_init (ctx_new_fpr);                                     
                                                                             
    for(int i=0; i<5; i++){                                                  
      ctx_org->h[i] = h[i];                                                  
    }                                                                        
    for(int i=0; i<64; i++){                                                
      ctx_org->buf[i] = buf[i];                                              
    }                                                                        
    ctx_org->sz = ctx_new->sz;                                           
                                                                             
    return Val_unit;                                                         
  }                                                                          
                                                                             
  CAMLprim value                                                             
  mc_sha1_update (value ctx, value src, value off, value len) {      
    struct sha1_ctx_org *ctx_org = (struct sha1_ctx_org*) Bytes_val (ctx);  
                                                                             
    __int128 buf_fpr = safemalloc(64*sizeof(uint8_t));                      
    __int128 h_fpr = safemalloc(5*sizeof(uint32_t));                         
    uint8_t *buf = (uint8_t*)(buf_fpr & 0xffffffff);
    uint32_t *h = (uint32_t*)(h_fpr & 0xffffffff);
                                                                             
    __int128 ctx_new_fpr = safemalloc(sizeof(struct sha1_ctx_fat_v));    
    struct sha1_ctx_fat_v *ctx_new = (struct sha1_ctx_fat_v*)(ctx_new_fpr & 0xffffffff); 
    ctx_new->sz = 0;                                                       
    ctx_new->buf = buf_fpr;                                                  
    ctx_new->h = h_fpr;                                                      
                                                                             
    for(int i=0; i<5; i++){                                                  
      h[i] = ctx_org->h[i];                                                  
    }                                                                        
    for(int i=0; i<64; i++){                                                
      buf[i] = ctx_org->buf[i];                                              
    }                                                                        
    ctx_new->sz = ctx_org->sz;                                           
                                                                             
    int num_elts_input = 1;                                                  
    for (int i = 0; i < Caml_ba_array_val(src)->num_dims; i++) num_elts_input = num_elts_input * Caml_ba_array_val(src)->dim[i];
                                                                             
    __int128 src_off_fpr = craft(_ba_uint8_off (src, off), (uint8_t*)Caml_ba_data_val(src), (uint8_t*)((uint8_t*)Caml_ba_data_val(src)+num_elts_input), 0); 
    _mc_sha1_update(ctx_new_fpr, src_off_fpr, Int_val(len));          
    for(int i=0; i<5; i++){                                                  
      ctx_org->h[i] = h[i];                                                  
    }                                                                        
    for(int i=0; i<64; i++){                                                
      ctx_org->buf[i] = buf[i];                                              
    }                                                                        
    ctx_org->sz = ctx_new->sz;                                           
    return Val_unit;                                                         
  }                                                                          
                                                                             
  CAMLprim value                                                             
  mc_sha1_finalize (value ctx, value dst, value off) {               
    struct sha1_ctx_org *ctx_org = (struct sha1_ctx_org*) Bytes_val (ctx);  
                                                                             
    __int128 buf_fpr = safemalloc(64*sizeof(uint8_t));                      
    __int128 h_fpr = safemalloc(5*sizeof(uint32_t));                         
    uint8_t *buf = (uint8_t*)(buf_fpr & 0xffffffff);
    uint32_t *h = (uint32_t*)(h_fpr & 0xffffffff);
                                                                             
    __int128 ctx_new_fpr = safemalloc(sizeof(struct sha1_ctx_fat_v));    
    struct sha1_ctx_fat_v *ctx_new = (struct sha1_ctx_fat_v*)(ctx_new_fpr & 0xffffffff); 
    ctx_new->sz = 0;                                                       
    ctx_new->buf = buf_fpr;                                                  
    ctx_new->h = h_fpr;                                                      
                                                                             
    for(int i=0; i<5; i++){                                                  
      h[i] = ctx_org->h[i];                                                  
    }                                                                        
    for(int i=0; i<64; i++){                                                
      buf[i] = ctx_org->buf[i];                                              
    }                                                                        
    ctx_new->sz = ctx_org->sz;                                           
                                                                             
    int num_elts_input = 1;                                                  
    for (int i = 0; i < Caml_ba_array_val(dst)->num_dims; i++) num_elts_input = num_elts_input * Caml_ba_array_val(dst)->dim[i];
    __int128 dst_off_fpr = craft(_ba_uint8_off (dst, off), (uint8_t*)Caml_ba_data_val(dst), (uint8_t*)((uint8_t*)Caml_ba_data_val(dst)+num_elts_input), 0); 
    // printf("FINALIZE => ctx : %p | dst : %p | off : %lu | num_elts_input : %dn", Bytes_val(ctx), ((uint8_t*) Caml_ba_data_val (dst)), Long_val (off), num_elts_input);
                                                                             
    _mc_sha1_finalize(ctx_new_fpr, dst_off_fpr);                     
    for(int i=0; i<5; i++){                                                  
      ctx_org->h[i] = h[i];                                                  
    }                                                                        
    for(int i=0; i<64; i++){                                                
      ctx_org->buf[i] = buf[i];                                              
    }                                                                        
    ctx_org->sz = ctx_new->sz;                                           
    return Val_unit;                                                         
  }                                                                          
                                                                             
  CAMLprim value                                                             
  mc_sha1_ctx_size (__unit ()) {                                     
    return Val_int (SHA1_CTX_SIZE);                                     
  }                                                                          


/******************************************** SHA224 - SHA256 ********************************************/
// #include "sha256.h"

struct sha256_ctx_fat_v
{
  uint64_t sz;
  __int128 buf; //[128];
  __int128 h; //[8];
};

struct sha256_ctx_org
{
  uint64_t sz;
  uint8_t  buf[128];
  uint32_t h[8];
};
                                                                        
#define sha224_ctx_fat_v    sha256_ctx_fat_v
#define sha224_ctx_org    sha256_ctx_org

#define SHA224_DIGEST_SIZE  28
#define SHA224_CTX_SIZE   sizeof(struct sha224_ctx_org)

#define SHA256_DIGEST_SIZE  32
#define SHA256_CTX_SIZE   sizeof(struct sha256_ctx_org)

  CAMLprim value                                                             
  mc_sha224_init (value ctx) {                                         
    struct sha224_ctx_org *ctx_org = (struct sha224_ctx_org*) Bytes_val (ctx);  
                                                                             
    __int128 buf_fpr = safemalloc(128*sizeof(uint8_t));                      
    __int128 h_fpr = safemalloc(8*sizeof(uint32_t));                         
    uint8_t *buf = (uint8_t*)(buf_fpr & 0xffffffff);
    uint32_t *h = (uint32_t*)(h_fpr & 0xffffffff);
                                                                             
    __int128 ctx_new_fpr = safemalloc(sizeof(struct sha224_ctx_fat_v));    
    struct sha224_ctx_fat_v *ctx_new = (struct sha224_ctx_fat_v*)(ctx_new_fpr & 0xffffffff); 
    ctx_new->sz = 0;                                                       
    ctx_new->buf = buf_fpr;                                                  
    ctx_new->h = h_fpr;                                                      
                                                                             
                                                                             
    _mc_sha224_init (ctx_new_fpr);                                     
                                                                             
    for(int i=0; i<8; i++){                                                  
      ctx_org->h[i] = h[i];                                                  
    }                                                                        
    for(int i=0; i<128; i++){                                                
      ctx_org->buf[i] = buf[i];                                              
    }                                                                        
    ctx_org->sz = ctx_new->sz;                                           
                                                                             
    return Val_unit;                                                         
  }                                                                          
                                                                             
  CAMLprim value                                                             
  mc_sha224_update (value ctx, value src, value off, value len) {      
    struct sha224_ctx_org *ctx_org = (struct sha224_ctx_org*) Bytes_val (ctx);  
                                                                             
    __int128 buf_fpr = safemalloc(128*sizeof(uint8_t));                      
    __int128 h_fpr = safemalloc(8*sizeof(uint32_t));                         
    uint8_t *buf = (uint8_t*)(buf_fpr & 0xffffffff);
    uint32_t *h = (uint32_t*)(h_fpr & 0xffffffff);
                                                                             
    __int128 ctx_new_fpr = safemalloc(sizeof(struct sha224_ctx_fat_v));    
    struct sha224_ctx_fat_v *ctx_new = (struct sha224_ctx_fat_v*)(ctx_new_fpr & 0xffffffff); 
    ctx_new->sz = 0;                                                       
    ctx_new->buf = buf_fpr;                                                  
    ctx_new->h = h_fpr;                                                      
                                                                             
    for(int i=0; i<8; i++){                                                  
      h[i] = ctx_org->h[i];                                                  
    }                                                                        
    for(int i=0; i<128; i++){                                                
      buf[i] = ctx_org->buf[i];                                              
    }                                                                        
    ctx_new->sz = ctx_org->sz;                                           
                                                                             
    int num_elts_input = 1;                                                  
    for (int i = 0; i < Caml_ba_array_val(src)->num_dims; i++) num_elts_input = num_elts_input * Caml_ba_array_val(src)->dim[i];
                                                                             
    __int128 src_off_fpr = craft(_ba_uint8_off (src, off), (uint8_t*)Caml_ba_data_val(src), (uint8_t*)((uint8_t*)Caml_ba_data_val(src)+num_elts_input), 0); 
    _mc_sha224_update(ctx_new_fpr, src_off_fpr, Int_val(len));          
    for(int i=0; i<8; i++){                                                  
      ctx_org->h[i] = h[i];                                                  
    }                                                                        
    for(int i=0; i<128; i++){                                                
      ctx_org->buf[i] = buf[i];                                              
    }                                                                        
    ctx_org->sz = ctx_new->sz;                                           
    return Val_unit;                                                         
  }                                                                          
                                                                             
  CAMLprim value                                                             
  mc_sha224_finalize (value ctx, value dst, value off) {               
    struct sha224_ctx_org *ctx_org = (struct sha224_ctx_org*) Bytes_val (ctx);  
                                                                             
    __int128 buf_fpr = safemalloc(128*sizeof(uint8_t));
    __int128 h_fpr = safemalloc(8*sizeof(uint32_t));
    uint8_t *buf = (uint8_t*)(buf_fpr & 0xffffffff);
    uint32_t *h = (uint32_t*)(h_fpr & 0xffffffff);
                                                                             
    __int128 ctx_new_fpr = safemalloc(sizeof(struct sha224_ctx_fat_v));    
    struct sha224_ctx_fat_v *ctx_new = (struct sha224_ctx_fat_v*)(ctx_new_fpr & 0xffffffff); 
    ctx_new->sz = 0;                                                       
    ctx_new->buf = buf_fpr;                                                  
    ctx_new->h = h_fpr;                                                      
                                                                             
    for(int i=0; i<8; i++){                                                  
      h[i] = ctx_org->h[i];                                                  
    }                                                                        
    for(int i=0; i<128; i++){                                                
      buf[i] = ctx_org->buf[i];                                              
    }                                                                        
    ctx_new->sz = ctx_org->sz;                                           
                                                                             
    int num_elts_input = 1;                                                  
    for (int i = 0; i < Caml_ba_array_val(dst)->num_dims; i++) num_elts_input = num_elts_input * Caml_ba_array_val(dst)->dim[i];
    __int128 dst_off_fpr = craft(_ba_uint8_off (dst, off), (uint8_t*)Caml_ba_data_val(dst), (uint8_t*)((uint8_t*)Caml_ba_data_val(dst)+num_elts_input), 0); 
    // printf("FINALIZE => ctx : %p | dst : %p | off : %lu | num_elts_input : %dn", Bytes_val(ctx), ((uint8_t*) Caml_ba_data_val (dst)), Long_val (off), num_elts_input);
                                                                             
    _mc_sha224_finalize(ctx_new_fpr, dst_off_fpr);                     
    for(int i=0; i<8; i++){                                                  
      ctx_org->h[i] = h[i];                                                  
    }                                                                        
    for(int i=0; i<128; i++){                                                
      ctx_org->buf[i] = buf[i];                                              
    }                                                                        
    ctx_org->sz = ctx_new->sz;                                           
    return Val_unit;                                                         
  }                                                                          
                                                                             
  CAMLprim value                                                             
  mc_sha224_ctx_size (__unit ()) {                                     
    return Val_int (SHA224_CTX_SIZE);                                     
  }                                                                          

  CAMLprim value                                                             
  mc_sha256_init (value ctx) {                                         
    struct sha256_ctx_org *ctx_org = (struct sha256_ctx_org*) Bytes_val (ctx);  
                

                                                           
    __int128 buf_fpr = safemalloc(128*sizeof(uint8_t));                      
    __int128 h_fpr = safemalloc(8*sizeof(uint32_t));                         
    uint8_t *buf = (uint8_t*)(buf_fpr & 0xffffffff);                       
    uint32_t *h = (uint32_t*)(h_fpr & 0xffffffff);                             
                                                                             
    __int128 ctx_new_fpr = safemalloc(sizeof(struct sha256_ctx_fat_v));    
    struct sha256_ctx_fat_v *ctx_new = (struct sha256_ctx_fat_v*)(ctx_new_fpr & 0xffffffff); 
    ctx_new->sz = 0;                                                       
    ctx_new->buf = buf_fpr;                                                  
    ctx_new->h = h_fpr;                                                      
                                                                             
                                                                             
    _mc_sha256_init (ctx_new_fpr);                                     
                                                                             
    for(int i=0; i<8; i++){                                                  
      ctx_org->h[i] = h[i];                                                  
    }                                                                        
    for(int i=0; i<128; i++){                                                
      ctx_org->buf[i] = buf[i];                                              
    }                                                                        
    ctx_org->sz = ctx_new->sz;                                   



    // printf("sha256 : ctx_org->sz = %d\n", ctx_org->sz);
    // for(int i=0; i<8; i++)
      // printf("sha256 : ctx_org->h[%d] = %x\n", i, ctx_org->h[i]);
    // for(int i=0; i<128; i++)
      // printf("sha256 : ctx_org->buf[%d] = %x\n", i, ctx_org->h[i]);
    

    return Val_unit;                                                         
  }                                                                          
                                                                             
  CAMLprim value                                                             
  mc_sha256_update (value ctx, value src, value off, value len) {      
    struct sha256_ctx_org *ctx_org = (struct sha256_ctx_org*) Bytes_val (ctx);  
                                                                             
    __int128 buf_fpr = safemalloc(128*sizeof(uint8_t));                      
    __int128 h_fpr = safemalloc(8*sizeof(uint32_t));                         
    uint8_t *buf = (uint8_t*)(buf_fpr & 0xffffffff);                       
    uint32_t *h = (uint32_t*)(h_fpr & 0xffffffff);                             
                                                                             
    __int128 ctx_new_fpr = safemalloc(sizeof(struct sha256_ctx_fat_v));    
    struct sha256_ctx_fat_v *ctx_new = (struct sha256_ctx_fat_v*)(ctx_new_fpr & 0xffffffff); 
    ctx_new->sz = 0;                                                       
    ctx_new->buf = buf_fpr;                                                  
    ctx_new->h = h_fpr;                                                      
                                                                             
    for(int i=0; i<8; i++){                                                  
      h[i] = ctx_org->h[i];                                                  
    }                                                                        
    for(int i=0; i<128; i++){                                                
      buf[i] = ctx_org->buf[i];                                              
    }                                                                        
    ctx_new->sz = ctx_org->sz;                                           
                                                                             
    int num_elts_input = 1;                                                  
    for (int i = 0; i < Caml_ba_array_val(src)->num_dims; i++) num_elts_input = num_elts_input * Caml_ba_array_val(src)->dim[i];
                                                                             
    __int128 src_off_fpr = craft(_ba_uint8_off (src, off), (uint8_t*)Caml_ba_data_val(src), (uint8_t*)((uint8_t*)Caml_ba_data_val(src)+num_elts_input), 0); 
    _mc_sha256_update(ctx_new_fpr, src_off_fpr, Int_val(len));          
    for(int i=0; i<8; i++){                                                  
      ctx_org->h[i] = h[i];                                                  
    }                                                                        
    for(int i=0; i<128; i++){                                                
      ctx_org->buf[i] = buf[i];                                              
    }                                                                        
    ctx_org->sz = ctx_new->sz;                                           
    return Val_unit;                                                         
  }                                                                          
                                                                             
  CAMLprim value                                                             
  mc_sha256_finalize (value ctx, value dst, value off) {               
    struct sha256_ctx_org *ctx_org = (struct sha256_ctx_org*) Bytes_val (ctx);  
                                                                             
    __int128 buf_fpr = safemalloc(128*sizeof(uint8_t));                      
    __int128 h_fpr = safemalloc(8*sizeof(uint32_t));                         
    uint8_t *buf = (uint8_t*)(buf_fpr & 0xffffffff);
    uint32_t *h = (uint32_t*)(h_fpr & 0xffffffff);
                                                                             
    __int128 ctx_new_fpr = safemalloc(sizeof(struct sha256_ctx_fat_v));    
    struct sha256_ctx_fat_v *ctx_new = (struct sha256_ctx_fat_v*)(ctx_new_fpr & 0xffffffff); 
    ctx_new->sz = 0;                                                       
    ctx_new->buf = buf_fpr;                                                  
    ctx_new->h = h_fpr;                                                      
                                                                             
    for(int i=0; i<8; i++){                                                  
      h[i] = ctx_org->h[i];                                                  
    }                                                                        
    for(int i=0; i<128; i++){                                                
      buf[i] = ctx_org->buf[i];                                              
    }                                                                        
    ctx_new->sz = ctx_org->sz;                                           
                                                                             
    int num_elts_input = 1;                                                  
    for (int i = 0; i < Caml_ba_array_val(dst)->num_dims; i++) num_elts_input = num_elts_input * Caml_ba_array_val(dst)->dim[i];
    __int128 dst_off_fpr = craft(_ba_uint8_off (dst, off), (uint8_t*)Caml_ba_data_val(dst), (uint8_t*)((uint8_t*)Caml_ba_data_val(dst)+num_elts_input), 0); 
    // printf("FINALIZE => ctx : %p | dst : %p | off : %lu | num_elts_input : %dn", Bytes_val(ctx), ((uint8_t*) Caml_ba_data_val (dst)), Long_val (off), num_elts_input);
                                                                             
    _mc_sha256_finalize(ctx_new_fpr, dst_off_fpr);                     
    for(int i=0; i<8; i++){                                                  
      ctx_org->h[i] = h[i];                                                  
    }                                                                        
    for(int i=0; i<128; i++){                                                
      ctx_org->buf[i] = buf[i];                                              
    }                                                                        
    ctx_org->sz = ctx_new->sz;                                           
    return Val_unit;                                                         
  }                                                                          
                                                                             
  CAMLprim value                                                             
  mc_sha256_ctx_size (__unit ()) {                                     
    return Val_int (SHA256_CTX_SIZE);                                     
  }                                                                          

/******************************************** SHA384 - SHA512 ********************************************/
// #include "sha512.h"


struct sha512_ctx_fat_v
{
  __int128 sz; //[2]
  __int128 buf; //[128];
  __int128 h; //[8];
};

struct sha512_ctx_org
{
  uint64_t sz[2];
  uint8_t  buf[128];
  uint32_t h[8];
};
                                                                        
#define sha384_ctx_fat_v    sha512_ctx_fat_v
#define sha384_ctx_org    sha512_ctx_org

#define SHA384_DIGEST_SIZE  48
#define SHA384_CTX_SIZE   sizeof(struct sha384_ctx_org)

#define SHA512_DIGEST_SIZE  64
#define SHA512_CTX_SIZE   sizeof(struct sha512_ctx_org)

  CAMLprim value                                                             
  mc_sha384_init (value ctx) {                                         
    struct sha384_ctx_org *ctx_org = (struct sha384_ctx_org*) Bytes_val (ctx);  
                                                                             
    __int128 sz_fpr = safemalloc(2*sizeof(uint64_t));                      
    __int128 buf_fpr = safemalloc(128*sizeof(uint8_t));                      
    __int128 h_fpr = safemalloc(8*sizeof(uint32_t));                         
    uint64_t *sz = (uint64_t*)(sz_fpr & 0xffffffff);
    uint8_t *buf = (uint8_t*)(buf_fpr & 0xffffffff);
    uint32_t *h = (uint32_t*)(h_fpr & 0xffffffff);
                                                                             
    __int128 ctx_new_fpr = safemalloc(sizeof(struct sha384_ctx_fat_v));    
    struct sha384_ctx_fat_v *ctx_new = (struct sha384_ctx_fat_v*)(ctx_new_fpr & 0xffffffff); 
    ctx_new->sz = sz_fpr;                                                       
    ctx_new->buf = buf_fpr;                                                  
    ctx_new->h = h_fpr;                                                      
                                                                             
                                                                             
    _mc_sha384_init (ctx_new_fpr);                                     
    
    for(int i=0; i<2; i++){                                                  
      ctx_org->sz[i] = sz[i];                                                  
    }                                                                         
    for(int i=0; i<8; i++){                                                  
      ctx_org->h[i] = h[i];                                                  
    }                                                                        
    for(int i=0; i<128; i++){                                                
      ctx_org->buf[i] = buf[i];                                              
    }                                                                               
                                                                             
    return Val_unit;                                                         
  }                                                                          
                                                                             
  CAMLprim value                                                             
  mc_sha384_update (value ctx, value src, value off, value len) {      
    struct sha384_ctx_org *ctx_org = (struct sha384_ctx_org*) Bytes_val (ctx);  

    __int128 sz_fpr = safemalloc(2*sizeof(uint64_t));                                                                                                   
    __int128 buf_fpr = safemalloc(128*sizeof(uint8_t));                      
    __int128 h_fpr = safemalloc(8*sizeof(uint32_t));                         
    uint64_t *sz = (uint64_t*)(sz_fpr & 0xffffffff);                       
    uint8_t *buf = (uint8_t*)(buf_fpr & 0xffffffff);
    uint32_t *h = (uint32_t*)(h_fpr & 0xffffffff);
                                                                             
    __int128 ctx_new_fpr = safemalloc(sizeof(struct sha384_ctx_fat_v));    
    struct sha384_ctx_fat_v *ctx_new = (struct sha384_ctx_fat_v*)(ctx_new_fpr & 0xffffffff); 
    ctx_new->sz = sz_fpr;                                                       
    ctx_new->buf = buf_fpr;                                                  
    ctx_new->h = h_fpr;                                                      
                                                                             
    for(int i=0; i<2; i++){                                                  
      sz[i] = ctx_org->sz[i];                                                  
    }
    for(int i=0; i<8; i++){                                                  
      h[i] = ctx_org->h[i];                                                  
    }                                                                        
    for(int i=0; i<128; i++){                                                
      buf[i] = ctx_org->buf[i];                                              
    }                                                                        
                                                                             
    int num_elts_input = 1;                                                  
    for (int i = 0; i < Caml_ba_array_val(src)->num_dims; i++) num_elts_input = num_elts_input * Caml_ba_array_val(src)->dim[i];
                                                                             
    __int128 src_off_fpr = craft(_ba_uint8_off (src, off), (uint8_t*)Caml_ba_data_val(src), (uint8_t*)((uint8_t*)Caml_ba_data_val(src)+num_elts_input), 0); 
    _mc_sha384_update(ctx_new_fpr, src_off_fpr, Int_val(len));          
    
    for(int i=0; i<2; i++){                                                  
      ctx_org->sz[i] = sz[i];                                                  
    }
    for(int i=0; i<8; i++){                                                  
      ctx_org->h[i] = h[i];                                                  
    }                                                                        
    for(int i=0; i<128; i++){                                                
      ctx_org->buf[i] = buf[i];                                              
    }                                                                        
    return Val_unit;                                                         
  }                                                                          
                                                                             
  CAMLprim value                                                             
  mc_sha384_finalize (value ctx, value dst, value off) {               
    struct sha384_ctx_org *ctx_org = (struct sha384_ctx_org*) Bytes_val (ctx);  
    
    __int128 sz_fpr = safemalloc(2*sizeof(uint64_t));                                                                                               
    __int128 buf_fpr = safemalloc(128*sizeof(uint8_t));                      
    __int128 h_fpr = safemalloc(8*sizeof(uint32_t));                         
    uint64_t *sz = (uint64_t*)(sz_fpr & 0xffffffff);     
    uint8_t *buf = (uint8_t*)(buf_fpr & 0xffffffff);
    uint32_t *h = (uint32_t*)(h_fpr & 0xffffffff);
                                                                             
    __int128 ctx_new_fpr = safemalloc(sizeof(struct sha384_ctx_fat_v));    
    struct sha384_ctx_fat_v *ctx_new = (struct sha384_ctx_fat_v*)(ctx_new_fpr & 0xffffffff); 
    ctx_new->sz = sz_fpr;                                                       
    ctx_new->buf = buf_fpr;                                                  
    ctx_new->h = h_fpr;                                                      
                                                                             
    for(int i=0; i<2; i++){                                                  
      sz[i] = ctx_org->sz[i];                                                  
    }
    for(int i=0; i<8; i++){                                                  
      h[i] = ctx_org->h[i];                                                  
    }                                                                        
    for(int i=0; i<128; i++){                                                
      buf[i] = ctx_org->buf[i];                                              
    }                                                                        
                                             
                                                                             
    int num_elts_input = 1;                                                  
    for (int i = 0; i < Caml_ba_array_val(dst)->num_dims; i++) num_elts_input = num_elts_input * Caml_ba_array_val(dst)->dim[i];
    __int128 dst_off_fpr = craft(_ba_uint8_off (dst, off), (uint8_t*)Caml_ba_data_val(dst), (uint8_t*)((uint8_t*)Caml_ba_data_val(dst)+num_elts_input), 0); 
    // printf("FINALIZE => ctx : %p | dst : %p | off : %lu | num_elts_input : %dn", Bytes_val(ctx), ((uint8_t*) Caml_ba_data_val (dst)), Long_val (off), num_elts_input);
                                                                             
    _mc_sha384_finalize(ctx_new_fpr, dst_off_fpr);                     
    for(int i=0; i<2; i++){                                                
      ctx_org->sz[i] = sz[i];                                              
    }
    for(int i=0; i<8; i++){                                                  
      ctx_org->h[i] = h[i];                                                  
    }                                                                        
    for(int i=0; i<128; i++){                                                
      ctx_org->buf[i] = buf[i];                                              
    }                                                                        
                    
    return Val_unit;                                                         
  }                                                                          
                                                                             
  CAMLprim value                                                             
  mc_sha384_ctx_size (__unit ()) {                                     
    return Val_int (SHA384_CTX_SIZE);                                     
  }                                                                          

 CAMLprim value                                                             
  mc_sha512_init (value ctx) {                                         
    struct sha512_ctx_org *ctx_org = (struct sha512_ctx_org*) Bytes_val (ctx);  
                                                                             
    __int128 sz_fpr = safemalloc(2*sizeof(uint64_t));                      
    __int128 buf_fpr = safemalloc(128*sizeof(uint8_t));                      
    __int128 h_fpr = safemalloc(8*sizeof(uint32_t));                         
    uint64_t *sz = (uint64_t*)(sz_fpr & 0xffffffff);
    uint8_t *buf = (uint8_t*)(buf_fpr & 0xffffffff);
    uint32_t *h = (uint32_t*)(h_fpr & 0xffffffff);
                                                                             
    __int128 ctx_new_fpr = safemalloc(sizeof(struct sha512_ctx_fat_v));    
    struct sha512_ctx_fat_v *ctx_new = (struct sha512_ctx_fat_v*)(ctx_new_fpr & 0xffffffff); 
    ctx_new->sz = sz_fpr;                                                       
    ctx_new->buf = buf_fpr;                                                  
    ctx_new->h = h_fpr;                                                      
                                                                             
                                                                             
    _mc_sha512_init (ctx_new_fpr);                                     
    
    for(int i=0; i<2; i++){                                                  
      ctx_org->sz[i] = sz[i];                                                  
    }                                                                         
    for(int i=0; i<8; i++){                                                  
      ctx_org->h[i] = h[i];                                                  
    }                                                                        
    for(int i=0; i<128; i++){                                                
      ctx_org->buf[i] = buf[i];                                              
    }                                                                               
                                                                             
    return Val_unit;                                                         
  }                                                                          
                                                                             
  CAMLprim value                                                             
  mc_sha512_update (value ctx, value src, value off, value len) {      
    struct sha512_ctx_org *ctx_org = (struct sha512_ctx_org*) Bytes_val (ctx);  

    __int128 sz_fpr = safemalloc(2*sizeof(uint64_t));                                                                                                   
    __int128 buf_fpr = safemalloc(128*sizeof(uint8_t));                      
    __int128 h_fpr = safemalloc(8*sizeof(uint32_t));                         
    uint64_t *sz = (uint64_t*)(sz_fpr & 0xffffffff);                       
    uint8_t *buf = (uint8_t*)(buf_fpr & 0xffffffff);
    uint32_t *h = (uint32_t*)(h_fpr & 0xffffffff);
                                                                             
    __int128 ctx_new_fpr = safemalloc(sizeof(struct sha512_ctx_fat_v));    
    struct sha512_ctx_fat_v *ctx_new = (struct sha512_ctx_fat_v*)(ctx_new_fpr & 0xffffffff); 
    ctx_new->sz = sz_fpr;                                                       
    ctx_new->buf = buf_fpr;                                                  
    ctx_new->h = h_fpr;                                                      
                                                                             
    for(int i=0; i<2; i++){                                                  
      sz[i] = ctx_org->sz[i];                                                  
    }
    for(int i=0; i<8; i++){                                                  
      h[i] = ctx_org->h[i];                                                  
    }                                                                        
    for(int i=0; i<128; i++){                                                
      buf[i] = ctx_org->buf[i];                                              
    }                                                                        
                                                                             
    int num_elts_input = 1;                                                  
    for (int i = 0; i < Caml_ba_array_val(src)->num_dims; i++) num_elts_input = num_elts_input * Caml_ba_array_val(src)->dim[i];
                                                                             
    __int128 src_off_fpr = craft(_ba_uint8_off (src, off), (uint8_t*)Caml_ba_data_val(src), (uint8_t*)((uint8_t*)Caml_ba_data_val(src)+num_elts_input), 0); 
    _mc_sha512_update(ctx_new_fpr, src_off_fpr, Int_val(len));          
    
    for(int i=0; i<2; i++){                                                  
      ctx_org->sz[i] = sz[i];                                                  
    }
    for(int i=0; i<8; i++){                                                  
      ctx_org->h[i] = h[i];                                                  
    }                                                                        
    for(int i=0; i<128; i++){                                                
      ctx_org->buf[i] = buf[i];                                              
    }                                                                        
    return Val_unit;                                                         
  }                                                                          
                                                                             
  CAMLprim value                                                             
  mc_sha512_finalize (value ctx, value dst, value off) {               
    struct sha512_ctx_org *ctx_org = (struct sha512_ctx_org*) Bytes_val (ctx);  
    
    __int128 sz_fpr = safemalloc(2*sizeof(uint64_t));                                                                                               
    __int128 buf_fpr = safemalloc(128*sizeof(uint8_t));                      
    __int128 h_fpr = safemalloc(8*sizeof(uint32_t));                         
    uint64_t *sz = (uint64_t*)(sz_fpr & 0xffffffff);     
    uint8_t *buf = (uint8_t*)(buf_fpr & 0xffffffff);
    uint32_t *h = (uint32_t*)(h_fpr & 0xffffffff);
                                                                             
    __int128 ctx_new_fpr = safemalloc(sizeof(struct sha512_ctx_fat_v));    
    struct sha512_ctx_fat_v *ctx_new = (struct sha512_ctx_fat_v*)(ctx_new_fpr & 0xffffffff); 
    ctx_new->sz = sz_fpr;                                                       
    ctx_new->buf = buf_fpr;                                                  
    ctx_new->h = h_fpr;                                                      
                                                                             
    for(int i=0; i<2; i++){                                                  
      sz[i] = ctx_org->sz[i];                                                  
    }
    for(int i=0; i<8; i++){                                                  
      h[i] = ctx_org->h[i];                                                  
    }                                                                        
    for(int i=0; i<128; i++){                                                
      buf[i] = ctx_org->buf[i];                                              
    }                                                                        
                                             
                                                                             
    int num_elts_input = 1;                                                  
    for (int i = 0; i < Caml_ba_array_val(dst)->num_dims; i++) num_elts_input = num_elts_input * Caml_ba_array_val(dst)->dim[i];
    __int128 dst_off_fpr = craft(_ba_uint8_off (dst, off), (uint8_t*)Caml_ba_data_val(dst), (uint8_t*)((uint8_t*)Caml_ba_data_val(dst)+num_elts_input), 0); 
    // printf("FINALIZE => ctx : %p | dst : %p | off : %lu | num_elts_input : %dn", Bytes_val(ctx), ((uint8_t*) Caml_ba_data_val (dst)), Long_val (off), num_elts_input);
                                                                             
    _mc_sha512_finalize(ctx_new_fpr, dst_off_fpr);                     
    for(int i=0; i<2; i++){                                                
      ctx_org->sz[i] = sz[i];                                              
    }
    for(int i=0; i<8; i++){                                                  
      ctx_org->h[i] = h[i];                                                  
    }                                                                        
    for(int i=0; i<128; i++){                                                
      ctx_org->buf[i] = buf[i];                                              
    }                                                                        
                    
    return Val_unit;                                                         
  }                                                                          
                                                                             
  CAMLprim value                                                             
  mc_sha512_ctx_size (__unit ()) {                                     
    return Val_int (SHA512_CTX_SIZE);                                     
  }                                                                          



#else // FREESTANDING_CRYPTO

#include "mirage_crypto.h"

#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "sha512.h"

  CAMLprim value                                                             
  mc_sha256_init (value ctx) {                                         
    // struct sha256_ctx_org *ctx_org = (struct sha256_ctx_org*) Bytes_val (ctx);  

    _mc_sha256_init ((struct sha256_ctx *) Bytes_val (ctx));
    struct sha256_ctx *ctx_org = Bytes_val(ctx); 

    printf("sha256 : ctx_org->sz = %d\n", ctx_org->sz);
    for(int i=0; i<8; i++)
      printf("sha256 : ctx_org->h[%d] = %x\n", i, ctx_org->h[i]);
    for(int i=0; i<128; i++)
      printf("sha256 : ctx_org->buf[%d] = %x\n", i, ctx_org->h[i]);
    

    return Val_unit;
  }



#define __define_hash(name, upper)                                           \
                                                                             \
  CAMLprim value                                                             \
  mc_ ## name ## _init (value ctx) {                                         \
    _mc_ ## name ## _init ((struct name ## _ctx *) Bytes_val (ctx));         \
    return Val_unit;                                                         \
  }                                                                          \
                                                                             \
  CAMLprim value                                                             \
  mc_ ## name ## _update (value ctx, value src, value len) {                 \
    _mc_ ## name ## _update (                                                \
      (struct name ## _ctx *) Bytes_val (ctx),                               \
      _ba_uint8 (src), Int_val (len));                                       \
    return Val_unit;                                                         \
  }                                                                          \
                                                                             \
  CAMLprim value                                                             \
  mc_ ## name ## _finalize (value ctx, value dst) {                          \
    _mc_ ## name ## _finalize (                                              \
      (struct name ## _ctx *) Bytes_val (ctx), _ba_uint8 (dst));             \
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
// __define_hash (sha256, SHA256)
__define_hash (sha384, SHA384)
__define_hash (sha512, SHA512)
#endif