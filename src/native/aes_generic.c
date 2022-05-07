/*
 * public domain
 * Philip J. Erdelsky
 * http://www.efgh.com/software/rijndael.htm
 */

#include "mirage_crypto.h"

#define KEYLENGTH(keybits) ((keybits)/8)
#define RKLENGTH(keybits)  ((keybits)/8+28)
#define NROUNDS(keybits)   ((keybits)/32+6)

#define FULL_UNROLL

static const uint32_t *Te0; //[256]
static const uint32_t *Te1; //[256]
static const uint32_t *Te2; //[256]
static const uint32_t *Te3; //[256]
static const uint32_t *Te4; //[256]

static const uint32_t *Td0; //[256]
static const uint32_t *Td1; //[256]
static const uint32_t *Td2; //[256]
static const uint32_t *Td3; //[256]
static const uint32_t *Td4; //[256]

static /*const*/ uint32_t *rcon; //[10]

#define GETU32(plaintext) (((uint32_t)(plaintext)[0] << 24) ^ \
                    ((uint32_t)(plaintext)[1] << 16) ^ \
                    ((uint32_t)(plaintext)[2] <<  8) ^ \
                    ((uint32_t)(plaintext)[3]))

#define PUTU32(ciphertext, st) { (ciphertext)[0] = (uint8_t)((st) >> 24); \
                         (ciphertext)[1] = (uint8_t)((st) >> 16); \
                         (ciphertext)[2] = (uint8_t)((st) >>  8); \
                         (ciphertext)[3] = (uint8_t)(st); }

/**
 * Expand the cipher key into the encryption key schedule.
 *
 * @return the number of rounds for the given cipher key size.
 */
/*static*/ int mc_rijndaelSetupEncrypt(uint32_t *rk, const uint8_t *key, int keybits)
{
  int i = 0;
  uint32_t temp;

  rk[0] = GETU32(key     );
  rk[1] = GETU32(key +  4);
  rk[2] = GETU32(key +  8);
  rk[3] = GETU32(key + 12);
  if (keybits == 128)
  {
    for (;;)
    {
      temp  = rk[3];
      rk[4] = rk[0] ^
        (Te4[(temp >> 16) & 0xff] & 0xff000000) ^
        (Te4[(temp >>  8) & 0xff] & 0x00ff0000) ^
        (Te4[(temp      ) & 0xff] & 0x0000ff00) ^
        (Te4[(temp >> 24)       ] & 0x000000ff) ^
        rcon[i];
      rk[5] = rk[1] ^ rk[4];
      rk[6] = rk[2] ^ rk[5];
      rk[7] = rk[3] ^ rk[6];
      if (++i == 10)
        return 10;
      rk += 4;
    }
  }
  rk[4] = GETU32(key + 16);
  rk[5] = GETU32(key + 20);
  if (keybits == 192)
  {
    for (;;)
    {
      temp = rk[ 5];
      rk[ 6] = rk[ 0] ^
        (Te4[(temp >> 16) & 0xff] & 0xff000000) ^
        (Te4[(temp >>  8) & 0xff] & 0x00ff0000) ^
        (Te4[(temp      ) & 0xff] & 0x0000ff00) ^
        (Te4[(temp >> 24)       ] & 0x000000ff) ^
        rcon[i];
      rk[ 7] = rk[ 1] ^ rk[ 6];
      rk[ 8] = rk[ 2] ^ rk[ 7];
      rk[ 9] = rk[ 3] ^ rk[ 8];
      if (++i == 8)
        return 12;
      rk[10] = rk[ 4] ^ rk[ 9];
      rk[11] = rk[ 5] ^ rk[10];
      rk += 6;
    }
  }
  rk[6] = GETU32(key + 24);
  rk[7] = GETU32(key + 28);
  if (keybits == 256)
  {
    for (;;)
    {
      temp = rk[ 7];
      rk[ 8] = rk[ 0] ^
        (Te4[(temp >> 16) & 0xff] & 0xff000000) ^
        (Te4[(temp >>  8) & 0xff] & 0x00ff0000) ^
        (Te4[(temp      ) & 0xff] & 0x0000ff00) ^
        (Te4[(temp >> 24)       ] & 0x000000ff) ^
        rcon[i];
      rk[ 9] = rk[ 1] ^ rk[ 8];
      rk[10] = rk[ 2] ^ rk[ 9];
      rk[11] = rk[ 3] ^ rk[10];
      if (++i == 7)
        return 14;
      temp = rk[11];
      rk[12] = rk[ 4] ^
        (Te4[(temp >> 24)       ] & 0xff000000) ^
        (Te4[(temp >> 16) & 0xff] & 0x00ff0000) ^
        (Te4[(temp >>  8) & 0xff] & 0x0000ff00) ^
        (Te4[(temp      ) & 0xff] & 0x000000ff);
      rk[13] = rk[ 5] ^ rk[12];
      rk[14] = rk[ 6] ^ rk[13];
      rk[15] = rk[ 7] ^ rk[14];
      rk += 8;
    }
  }
  return 0;
}

/**
 * Expand the cipher key into the decryption key schedule.
 *
 * @return the number of rounds for the given cipher key size.
 */
/*static*/ int mc_rijndaelSetupDecrypt(uint32_t *rk, const uint8_t *key, int keybits) {
  int nrounds, i, j;
  uint32_t temp;

  /* expand the cipher key: */
  nrounds = mc_rijndaelSetupEncrypt(rk, key, keybits);
  /* invert the order of the round keys: */
  for (i = 0, j = 4*nrounds; i < j; i += 4, j -= 4)
  {
    temp = rk[i    ]; rk[i    ] = rk[j    ]; rk[j    ] = temp;
    temp = rk[i + 1]; rk[i + 1] = rk[j + 1]; rk[j + 1] = temp;
    temp = rk[i + 2]; rk[i + 2] = rk[j + 2]; rk[j + 2] = temp;
    temp = rk[i + 3]; rk[i + 3] = rk[j + 3]; rk[j + 3] = temp;
  }
  /* apply the inverse MixColumn transform to all round keys but the first and the last: */
  for (i = 1; i < nrounds; i++)
  {
    rk += 4;
    rk[0] =
      Td0[Te4[(rk[0] >> 24)       ] & 0xff] ^
      Td1[Te4[(rk[0] >> 16) & 0xff] & 0xff] ^
      Td2[Te4[(rk[0] >>  8) & 0xff] & 0xff] ^
      Td3[Te4[(rk[0]      ) & 0xff] & 0xff];
    rk[1] =
      Td0[Te4[(rk[1] >> 24)       ] & 0xff] ^
      Td1[Te4[(rk[1] >> 16) & 0xff] & 0xff] ^
      Td2[Te4[(rk[1] >>  8) & 0xff] & 0xff] ^
      Td3[Te4[(rk[1]      ) & 0xff] & 0xff];
    rk[2] =
      Td0[Te4[(rk[2] >> 24)       ] & 0xff] ^
      Td1[Te4[(rk[2] >> 16) & 0xff] & 0xff] ^
      Td2[Te4[(rk[2] >>  8) & 0xff] & 0xff] ^
      Td3[Te4[(rk[2]      ) & 0xff] & 0xff];
    rk[3] =
      Td0[Te4[(rk[3] >> 24)       ] & 0xff] ^
      Td1[Te4[(rk[3] >> 16) & 0xff] & 0xff] ^
      Td2[Te4[(rk[3] >>  8) & 0xff] & 0xff] ^
      Td3[Te4[(rk[3]      ) & 0xff] & 0xff];
  }
  return nrounds;
}

static void mc_rijndaelEncrypt(const uint32_t *rk, int nrounds, const uint8_t plaintext[16], uint8_t ciphertext[16]) {
  uint32_t s0, s1, s2, s3, t0, t1, t2, t3;
  #ifndef FULL_UNROLL
    int r;
  #endif /* ?FULL_UNROLL */
  /*
   * map byte array block to cipher state
   * and add initial round key:
  */
  s0 = GETU32(plaintext     ) ^ rk[0];
  s1 = GETU32(plaintext +  4) ^ rk[1];
  s2 = GETU32(plaintext +  8) ^ rk[2];
  s3 = GETU32(plaintext + 12) ^ rk[3];
  #ifdef FULL_UNROLL
    /* round 1: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[ 4];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[ 5];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[ 6];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[ 7];
    /* round 2: */
    s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[ 8];
    s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[ 9];
    s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[10];
    s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[11];
    /* round 3: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[12];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[13];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[14];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[15];
    /* round 4: */
    s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[16];
    s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[17];
    s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[18];
    s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[19];
    /* round 5: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[20];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[21];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[22];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[23];
    /* round 6: */
    s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[24];
    s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[25];
    s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[26];
    s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[27];
    /* round 7: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[28];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[29];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[30];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[31];
    /* round 8: */
    s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[32];
    s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[33];
    s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[34];
    s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[35];
    /* round 9: */
    t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[36];
    t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[37];
    t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[38];
    t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[39];
    if (nrounds > 10)
    {
      /* round 10: */
      s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[40];
      s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[41];
      s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[42];
      s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[43];
      /* round 11: */
      t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[44];
      t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[45];
      t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[46];
      t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[47];
      if (nrounds > 12)
      {
        /* round 12: */
        s0 = Te0[t0 >> 24] ^ Te1[(t1 >> 16) & 0xff] ^ Te2[(t2 >>  8) & 0xff] ^ Te3[t3 & 0xff] ^ rk[48];
        s1 = Te0[t1 >> 24] ^ Te1[(t2 >> 16) & 0xff] ^ Te2[(t3 >>  8) & 0xff] ^ Te3[t0 & 0xff] ^ rk[49];
        s2 = Te0[t2 >> 24] ^ Te1[(t3 >> 16) & 0xff] ^ Te2[(t0 >>  8) & 0xff] ^ Te3[t1 & 0xff] ^ rk[50];
        s3 = Te0[t3 >> 24] ^ Te1[(t0 >> 16) & 0xff] ^ Te2[(t1 >>  8) & 0xff] ^ Te3[t2 & 0xff] ^ rk[51];
        /* round 13: */
        t0 = Te0[s0 >> 24] ^ Te1[(s1 >> 16) & 0xff] ^ Te2[(s2 >>  8) & 0xff] ^ Te3[s3 & 0xff] ^ rk[52];
        t1 = Te0[s1 >> 24] ^ Te1[(s2 >> 16) & 0xff] ^ Te2[(s3 >>  8) & 0xff] ^ Te3[s0 & 0xff] ^ rk[53];
        t2 = Te0[s2 >> 24] ^ Te1[(s3 >> 16) & 0xff] ^ Te2[(s0 >>  8) & 0xff] ^ Te3[s1 & 0xff] ^ rk[54];
        t3 = Te0[s3 >> 24] ^ Te1[(s0 >> 16) & 0xff] ^ Te2[(s1 >>  8) & 0xff] ^ Te3[s2 & 0xff] ^ rk[55];
      }
    }
    rk += nrounds << 2;
  #else  /* !FULL_UNROLL */
    /*
    * nrounds - 1 full rounds:
    */
    r = nrounds >> 1;
    for (;;)
    {
      t0 =
        Te0[(s0 >> 24)       ] ^
        Te1[(s1 >> 16) & 0xff] ^
        Te2[(s2 >>  8) & 0xff] ^
        Te3[(s3      ) & 0xff] ^
        rk[4];
      t1 =
        Te0[(s1 >> 24)       ] ^
        Te1[(s2 >> 16) & 0xff] ^
        Te2[(s3 >>  8) & 0xff] ^
        Te3[(s0      ) & 0xff] ^
        rk[5];
      t2 =
        Te0[(s2 >> 24)       ] ^
        Te1[(s3 >> 16) & 0xff] ^
        Te2[(s0 >>  8) & 0xff] ^
        Te3[(s1      ) & 0xff] ^
        rk[6];
      t3 =
        Te0[(s3 >> 24)       ] ^
        Te1[(s0 >> 16) & 0xff] ^
        Te2[(s1 >>  8) & 0xff] ^
        Te3[(s2      ) & 0xff] ^
        rk[7];
        rk += 8;
        if (--r == 0)
            break;
      s0 =
        Te0[(t0 >> 24)       ] ^
        Te1[(t1 >> 16) & 0xff] ^
        Te2[(t2 >>  8) & 0xff] ^
        Te3[(t3      ) & 0xff] ^
        rk[0];
      s1 =
        Te0[(t1 >> 24)       ] ^
        Te1[(t2 >> 16) & 0xff] ^
        Te2[(t3 >>  8) & 0xff] ^
        Te3[(t0      ) & 0xff] ^
        rk[1];
      s2 =
        Te0[(t2 >> 24)       ] ^
        Te1[(t3 >> 16) & 0xff] ^
        Te2[(t0 >>  8) & 0xff] ^
        Te3[(t1      ) & 0xff] ^
        rk[2];
      s3 =
        Te0[(t3 >> 24)       ] ^
        Te1[(t0 >> 16) & 0xff] ^
        Te2[(t1 >>  8) & 0xff] ^
        Te3[(t2      ) & 0xff] ^
        rk[3];
     }
 #endif /* ?FULL_UNROLL */
  /*
  * apply last round and
  * map cipher state to byte array block:
  */
  s0 =
    (Te4[(t0 >> 24)       ] & 0xff000000) ^
    (Te4[(t1 >> 16) & 0xff] & 0x00ff0000) ^
    (Te4[(t2 >>  8) & 0xff] & 0x0000ff00) ^
    (Te4[(t3      ) & 0xff] & 0x000000ff) ^
    rk[0];
  PUTU32(ciphertext     , s0);
  s1 =
    (Te4[(t1 >> 24)       ] & 0xff000000) ^
    (Te4[(t2 >> 16) & 0xff] & 0x00ff0000) ^
    (Te4[(t3 >>  8) & 0xff] & 0x0000ff00) ^
    (Te4[(t0      ) & 0xff] & 0x000000ff) ^
    rk[1];
  PUTU32(ciphertext +  4, s1);
  s2 =
    (Te4[(t2 >> 24)       ] & 0xff000000) ^
    (Te4[(t3 >> 16) & 0xff] & 0x00ff0000) ^
    (Te4[(t0 >>  8) & 0xff] & 0x0000ff00) ^
    (Te4[(t1      ) & 0xff] & 0x000000ff) ^
    rk[2];
  PUTU32(ciphertext +  8, s2);
  s3 =
    (Te4[(t3 >> 24)       ] & 0xff000000) ^
    (Te4[(t0 >> 16) & 0xff] & 0x00ff0000) ^
    (Te4[(t1 >>  8) & 0xff] & 0x0000ff00) ^
    (Te4[(t2      ) & 0xff] & 0x000000ff) ^
    rk[3];
  PUTU32(ciphertext + 12, s3);
}

static void mc_rijndaelDecrypt(const uint32_t *rk, int nrounds, const uint8_t ciphertext[16], uint8_t plaintext[16]) {
  uint32_t s0, s1, s2, s3, t0, t1, t2, t3;
  #ifndef FULL_UNROLL
    int r;
  #endif /* ?FULL_UNROLL */

  /*
  * map byte array block to cipher state
  * and add initial round key:
  */
    s0 = GETU32(ciphertext     ) ^ rk[0];
    s1 = GETU32(ciphertext +  4) ^ rk[1];
    s2 = GETU32(ciphertext +  8) ^ rk[2];
    s3 = GETU32(ciphertext + 12) ^ rk[3];
  #ifdef FULL_UNROLL
    /* round 1: */
    t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[ 4];
    t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[ 5];
    t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[ 6];
    t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[ 7];
    /* round 2: */
    s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[ 8];
    s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[ 9];
    s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[10];
    s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[11];
    /* round 3: */
    t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[12];
    t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[13];
    t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[14];
    t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[15];
    /* round 4: */
    s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[16];
    s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[17];
    s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[18];
    s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[19];
    /* round 5: */
    t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[20];
    t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[21];
    t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[22];
    t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[23];
    /* round 6: */
    s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[24];
    s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[25];
    s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[26];
    s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[27];
    /* round 7: */
    t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[28];
    t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[29];
    t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[30];
    t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[31];
    /* round 8: */
    s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[32];
    s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[33];
    s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[34];
    s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[35];
    /* round 9: */
    t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[36];
    t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[37];
    t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[38];
    t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[39];
    if (nrounds > 10)
    {
      /* round 10: */
      s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[40];
      s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[41];
      s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[42];
      s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[43];
      /* round 11: */
      t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[44];
      t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[45];
      t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[46];
      t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[47];
      if (nrounds > 12)
      {
        /* round 12: */
        s0 = Td0[t0 >> 24] ^ Td1[(t3 >> 16) & 0xff] ^ Td2[(t2 >>  8) & 0xff] ^ Td3[t1 & 0xff] ^ rk[48];
        s1 = Td0[t1 >> 24] ^ Td1[(t0 >> 16) & 0xff] ^ Td2[(t3 >>  8) & 0xff] ^ Td3[t2 & 0xff] ^ rk[49];
        s2 = Td0[t2 >> 24] ^ Td1[(t1 >> 16) & 0xff] ^ Td2[(t0 >>  8) & 0xff] ^ Td3[t3 & 0xff] ^ rk[50];
        s3 = Td0[t3 >> 24] ^ Td1[(t2 >> 16) & 0xff] ^ Td2[(t1 >>  8) & 0xff] ^ Td3[t0 & 0xff] ^ rk[51];
        /* round 13: */
        t0 = Td0[s0 >> 24] ^ Td1[(s3 >> 16) & 0xff] ^ Td2[(s2 >>  8) & 0xff] ^ Td3[s1 & 0xff] ^ rk[52];
        t1 = Td0[s1 >> 24] ^ Td1[(s0 >> 16) & 0xff] ^ Td2[(s3 >>  8) & 0xff] ^ Td3[s2 & 0xff] ^ rk[53];
        t2 = Td0[s2 >> 24] ^ Td1[(s1 >> 16) & 0xff] ^ Td2[(s0 >>  8) & 0xff] ^ Td3[s3 & 0xff] ^ rk[54];
        t3 = Td0[s3 >> 24] ^ Td1[(s2 >> 16) & 0xff] ^ Td2[(s1 >>  8) & 0xff] ^ Td3[s0 & 0xff] ^ rk[55];
      }
    }
    rk += nrounds << 2;
  #else  /* !FULL_UNROLL */
    /*
    * nrounds - 1 full rounds:
    */
    r = nrounds >> 1;
    for (;;)
    {
      t0 =
        Td0[(s0 >> 24)       ] ^
        Td1[(s3 >> 16) & 0xff] ^
        Td2[(s2 >>  8) & 0xff] ^
        Td3[(s1      ) & 0xff] ^
        rk[4];
      t1 =
        Td0[(s1 >> 24)       ] ^
        Td1[(s0 >> 16) & 0xff] ^
        Td2[(s3 >>  8) & 0xff] ^
        Td3[(s2      ) & 0xff] ^
        rk[5];
      t2 =
        Td0[(s2 >> 24)       ] ^
        Td1[(s1 >> 16) & 0xff] ^
        Td2[(s0 >>  8) & 0xff] ^
        Td3[(s3      ) & 0xff] ^
        rk[6];
      t3 =
        Td0[(s3 >> 24)       ] ^
        Td1[(s2 >> 16) & 0xff] ^
        Td2[(s1 >>  8) & 0xff] ^
        Td3[(s0      ) & 0xff] ^
        rk[7];
      rk += 8;
      if (--r == 0)
          break;
      s0 =
        Td0[(t0 >> 24)       ] ^
        Td1[(t3 >> 16) & 0xff] ^
        Td2[(t2 >>  8) & 0xff] ^
        Td3[(t1      ) & 0xff] ^
        rk[0];
      s1 =
        Td0[(t1 >> 24)       ] ^
        Td1[(t0 >> 16) & 0xff] ^
        Td2[(t3 >>  8) & 0xff] ^
        Td3[(t2      ) & 0xff] ^
        rk[1];
      s2 =
        Td0[(t2 >> 24)       ] ^
        Td1[(t1 >> 16) & 0xff] ^
        Td2[(t0 >>  8) & 0xff] ^
        Td3[(t3      ) & 0xff] ^
        rk[2];
      s3 =
        Td0[(t3 >> 24)       ] ^
        Td1[(t2 >> 16) & 0xff] ^
        Td2[(t1 >>  8) & 0xff] ^
        Td3[(t0      ) & 0xff] ^
        rk[3];
    }
  #endif /* ?FULL_UNROLL */
  /*
  * apply last round and
  * map cipher state to byte array block:
  */
  s0 =
    (Td4[(t0 >> 24)       ] & 0xff000000) ^
    (Td4[(t3 >> 16) & 0xff] & 0x00ff0000) ^
    (Td4[(t2 >>  8) & 0xff] & 0x0000ff00) ^
    (Td4[(t1      ) & 0xff] & 0x000000ff) ^
    rk[0];
  PUTU32(plaintext     , s0);
  s1 =
    (Td4[(t1 >> 24)       ] & 0xff000000) ^
    (Td4[(t0 >> 16) & 0xff] & 0x00ff0000) ^
    (Td4[(t3 >>  8) & 0xff] & 0x0000ff00) ^
    (Td4[(t2      ) & 0xff] & 0x000000ff) ^
    rk[1];
  PUTU32(plaintext +  4, s1);
  s2 =
    (Td4[(t2 >> 24)       ] & 0xff000000) ^
    (Td4[(t1 >> 16) & 0xff] & 0x00ff0000) ^
    (Td4[(t0 >>  8) & 0xff] & 0x0000ff00) ^
    (Td4[(t3      ) & 0xff] & 0x000000ff) ^
    rk[2];
  PUTU32(plaintext +  8, s2);
  s3 =
    (Td4[(t3 >> 24)       ] & 0xff000000) ^
    (Td4[(t2 >> 16) & 0xff] & 0x00ff0000) ^
    (Td4[(t1 >>  8) & 0xff] & 0x0000ff00) ^
    (Td4[(t0      ) & 0xff] & 0x000000ff) ^
    rk[3];
  PUTU32(plaintext + 12, s3);
}


/* OCaml front-end */

#define keybits_of_r(x) ((x - 6) * 32)

#define __blocked_loop(f, src, dst, rk, rounds, blocks) \
  while (blocks --) {                                   \
    f (rk, rounds, src, dst);                           \
    src += 16 ; dst += 16 ;                             \
  }

/*static inline*/ void _mc_aes_enc_blocks (const uint8_t *src, uint8_t *dst, const uint32_t *rk, uint8_t rounds, size_t blocks) {
  __blocked_loop (mc_rijndaelEncrypt, src, dst, rk, rounds, blocks);
}

/*static inline*/ void _mc_aes_dec_blocks (const uint8_t *src, uint8_t *dst, const uint32_t *rk, uint8_t rounds, size_t blocks) {
  __blocked_loop (mc_rijndaelDecrypt, src, dst, rk, rounds, blocks);
}


void init_static_array(){
  if(!init_called){
    init_called = 1;
    init_actual();
  }
}

void init_actual(){
Td0 = malloc(sizeof(uint32_t) * 256)
Td0[0] = 0x51f4a750U;
Td0[1] = 0x7e416553U;
Td0[2] = 0x1a17a4c3U;
Td0[3] = 0x3a275e96U;
Td0[4] = 0x3bab6bcbU;
Td0[5] = 0x1f9d45f1U;
Td0[6] = 0xacfa58abU;
Td0[7] = 0x4be30393U;
Td0[8] = 0x2030fa55U;
Td0[9] = 0xad766df6U;
Td0[10] = 0x88cc7691U;
Td0[11] = 0xf5024c25U;
Td0[12] = 0x4fe5d7fcU;
Td0[13] = 0xc52acbd7U;
Td0[14] = 0x26354480U;
Td0[15] = 0xb562a38fU;
Td0[16] = 0xdeb15a49U;
Td0[17] = 0x25ba1b67U;
Td0[18] = 0x45ea0e98U;
Td0[19] = 0x5dfec0e1U;
Td0[20] = 0xc32f7502U;
Td0[21] = 0x814cf012U;
Td0[22] = 0x8d4697a3U;
Td0[23] = 0x6bd3f9c6U;
Td0[24] = 0x038f5fe7U;
Td0[25] = 0x15929c95U;
Td0[26] = 0xbf6d7aebU;
Td0[27] = 0x955259daU;
Td0[28] = 0xd4be832dU;
Td0[29] = 0x587421d3U;
Td0[30] = 0x49e06929U;
Td0[31] = 0x8ec9c844U;
Td0[32] = 0x75c2896aU;
Td0[33] = 0xf48e7978U;
Td0[34] = 0x99583e6bU;
Td0[35] = 0x27b971ddU;
Td0[36] = 0xbee14fb6U;
Td0[37] = 0xf088ad17U;
Td0[38] = 0xc920ac66U;
Td0[39] = 0x7dce3ab4U;
Td0[40] = 0x63df4a18U;
Td0[41] = 0xe51a3182U;
Td0[42] = 0x97513360U;
Td0[43] = 0x62537f45U;
Td0[44] = 0xb16477e0U;
Td0[45] = 0xbb6bae84U;
Td0[46] = 0xfe81a01cU;
Td0[47] = 0xf9082b94U;
Td0[48] = 0x70486858U;
Td0[49] = 0x8f45fd19U;
Td0[50] = 0x94de6c87U;
Td0[51] = 0x527bf8b7U;
Td0[52] = 0xab73d323U;
Td0[53] = 0x724b02e2U;
Td0[54] = 0xe31f8f57U;
Td0[55] = 0x6655ab2aU;
Td0[56] = 0xb2eb2807U;
Td0[57] = 0x2fb5c203U;
Td0[58] = 0x86c57b9aU;
Td0[59] = 0xd33708a5U;
Td0[60] = 0x302887f2U;
Td0[61] = 0x23bfa5b2U;
Td0[62] = 0x02036abaU;
Td0[63] = 0xed16825cU;
Td0[64] = 0x8acf1c2bU;
Td0[65] = 0xa779b492U;
Td0[66] = 0xf307f2f0U;
Td0[67] = 0x4e69e2a1U;
Td0[68] = 0x65daf4cdU;
Td0[69] = 0x0605bed5U;
Td0[70] = 0xd134621fU;
Td0[71] = 0xc4a6fe8aU;
Td0[72] = 0x342e539dU;
Td0[73] = 0xa2f355a0U;
Td0[74] = 0x058ae132U;
Td0[75] = 0xa4f6eb75U;
Td0[76] = 0x0b83ec39U;
Td0[77] = 0x4060efaaU;
Td0[78] = 0x5e719f06U;
Td0[79] = 0xbd6e1051U;
Td0[80] = 0x3e218af9U;
Td0[81] = 0x96dd063dU;
Td0[82] = 0xdd3e05aeU;
Td0[83] = 0x4de6bd46U;
Td0[84] = 0x91548db5U;
Td0[85] = 0x71c45d05U;
Td0[86] = 0x0406d46fU;
Td0[87] = 0x605015ffU;
Td0[88] = 0x1998fb24U;
Td0[89] = 0xd6bde997U;
Td0[90] = 0x894043ccU;
Td0[91] = 0x67d99e77U;
Td0[92] = 0xb0e842bdU;
Td0[93] = 0x07898b88U;
Td0[94] = 0xe7195b38U;
Td0[95] = 0x79c8eedbU;
Td0[96] = 0xa17c0a47U;
Td0[97] = 0x7c420fe9U;
Td0[98] = 0xf8841ec9U;
Td0[99] = 0x00000000U;
Td0[100] = 0x09808683U;
Td0[101] = 0x322bed48U;
Td0[102] = 0x1e1170acU;
Td0[103] = 0x6c5a724eU;
Td0[104] = 0xfd0efffbU;
Td0[105] = 0x0f853856U;
Td0[106] = 0x3daed51eU;
Td0[107] = 0x362d3927U;
Td0[108] = 0x0a0fd964U;
Td0[109] = 0x685ca621U;
Td0[110] = 0x9b5b54d1U;
Td0[111] = 0x24362e3aU;
Td0[112] = 0x0c0a67b1U;
Td0[113] = 0x9357e70fU;
Td0[114] = 0xb4ee96d2U;
Td0[115] = 0x1b9b919eU;
Td0[116] = 0x80c0c54fU;
Td0[117] = 0x61dc20a2U;
Td0[118] = 0x5a774b69U;
Td0[119] = 0x1c121a16U;
Td0[120] = 0xe293ba0aU;
Td0[121] = 0xc0a02ae5U;
Td0[122] = 0x3c22e043U;
Td0[123] = 0x121b171dU;
Td0[124] = 0x0e090d0bU;
Td0[125] = 0xf28bc7adU;
Td0[126] = 0x2db6a8b9U;
Td0[127] = 0x141ea9c8U;
Td0[128] = 0x57f11985U;
Td0[129] = 0xaf75074cU;
Td0[130] = 0xee99ddbbU;
Td0[131] = 0xa37f60fdU;
Td0[132] = 0xf701269fU;
Td0[133] = 0x5c72f5bcU;
Td0[134] = 0x44663bc5U;
Td0[135] = 0x5bfb7e34U;
Td0[136] = 0x8b432976U;
Td0[137] = 0xcb23c6dcU;
Td0[138] = 0xb6edfc68U;
Td0[139] = 0xb8e4f163U;
Td0[140] = 0xd731dccaU;
Td0[141] = 0x42638510U;
Td0[142] = 0x13972240U;
Td0[143] = 0x84c61120U;
Td0[144] = 0x854a247dU;
Td0[145] = 0xd2bb3df8U;
Td0[146] = 0xaef93211U;
Td0[147] = 0xc729a16dU;
Td0[148] = 0x1d9e2f4bU;
Td0[149] = 0xdcb230f3U;
Td0[150] = 0x0d8652ecU;
Td0[151] = 0x77c1e3d0U;
Td0[152] = 0x2bb3166cU;
Td0[153] = 0xa970b999U;
Td0[154] = 0x119448faU;
Td0[155] = 0x47e96422U;
Td0[156] = 0xa8fc8cc4U;
Td0[157] = 0xa0f03f1aU;
Td0[158] = 0x567d2cd8U;
Td0[159] = 0x223390efU;
Td0[160] = 0x87494ec7U;
Td0[161] = 0xd938d1c1U;
Td0[162] = 0x8ccaa2feU;
Td0[163] = 0x98d40b36U;
Td0[164] = 0xa6f581cfU;
Td0[165] = 0xa57ade28U;
Td0[166] = 0xdab78e26U;
Td0[167] = 0x3fadbfa4U;
Td0[168] = 0x2c3a9de4U;
Td0[169] = 0x5078920dU;
Td0[170] = 0x6a5fcc9bU;
Td0[171] = 0x547e4662U;
Td0[172] = 0xf68d13c2U;
Td0[173] = 0x90d8b8e8U;
Td0[174] = 0x2e39f75eU;
Td0[175] = 0x82c3aff5U;
Td0[176] = 0x9f5d80beU;
Td0[177] = 0x69d0937cU;
Td0[178] = 0x6fd52da9U;
Td0[179] = 0xcf2512b3U;
Td0[180] = 0xc8ac993bU;
Td0[181] = 0x10187da7U;
Td0[182] = 0xe89c636eU;
Td0[183] = 0xdb3bbb7bU;
Td0[184] = 0xcd267809U;
Td0[185] = 0x6e5918f4U;
Td0[186] = 0xec9ab701U;
Td0[187] = 0x834f9aa8U;
Td0[188] = 0xe6956e65U;
Td0[189] = 0xaaffe67eU;
Td0[190] = 0x21bccf08U;
Td0[191] = 0xef15e8e6U;
Td0[192] = 0xbae79bd9U;
Td0[193] = 0x4a6f36ceU;
Td0[194] = 0xea9f09d4U;
Td0[195] = 0x29b07cd6U;
Td0[196] = 0x31a4b2afU;
Td0[197] = 0x2a3f2331U;
Td0[198] = 0xc6a59430U;
Td0[199] = 0x35a266c0U;
Td0[200] = 0x744ebc37U;
Td0[201] = 0xfc82caa6U;
Td0[202] = 0xe090d0b0U;
Td0[203] = 0x33a7d815U;
Td0[204] = 0xf104984aU;
Td0[205] = 0x41ecdaf7U;
Td0[206] = 0x7fcd500eU;
Td0[207] = 0x1791f62fU;
Td0[208] = 0x764dd68dU;
Td0[209] = 0x43efb04dU;
Td0[210] = 0xccaa4d54U;
Td0[211] = 0xe49604dfU;
Td0[212] = 0x9ed1b5e3U;
Td0[213] = 0x4c6a881bU;
Td0[214] = 0xc12c1fb8U;
Td0[215] = 0x4665517fU;
Td0[216] = 0x9d5eea04U;
Td0[217] = 0x018c355dU;
Td0[218] = 0xfa877473U;
Td0[219] = 0xfb0b412eU;
Td0[220] = 0xb3671d5aU;
Td0[221] = 0x92dbd252U;
Td0[222] = 0xe9105633U;
Td0[223] = 0x6dd64713U;
Td0[224] = 0x9ad7618cU;
Td0[225] = 0x37a10c7aU;
Td0[226] = 0x59f8148eU;
Td0[227] = 0xeb133c89U;
Td0[228] = 0xcea927eeU;
Td0[229] = 0xb761c935U;
Td0[230] = 0xe11ce5edU;
Td0[231] = 0x7a47b13cU;
Td0[232] = 0x9cd2df59U;
Td0[233] = 0x55f2733fU;
Td0[234] = 0x1814ce79U;
Td0[235] = 0x73c737bfU;
Td0[236] = 0x53f7cdeaU;
Td0[237] = 0x5ffdaa5bU;
Td0[238] = 0xdf3d6f14U;
Td0[239] = 0x7844db86U;
Td0[240] = 0xcaaff381U;
Td0[241] = 0xb968c43eU;
Td0[242] = 0x3824342cU;
Td0[243] = 0xc2a3405fU;
Td0[244] = 0x161dc372U;
Td0[245] = 0xbce2250cU;
Td0[246] = 0x283c498bU;
Td0[247] = 0xff0d9541U;
Td0[248] = 0x39a80171U;
Td0[249] = 0x080cb3deU;
Td0[250] = 0xd8b4e49cU;
Td0[251] = 0x6456c190U;
Td0[252] = 0x7bcb8461U;
Td0[253] = 0xd532b670U;
Td0[254] = 0x486c5c74U;
Td0[255] = 0xd0b85742U;
Td1 = malloc(sizeof(uint32_t) * 256)
Td1[0] = 0x5051f4a7U;
Td1[1] = 0x537e4165U;
Td1[2] = 0xc31a17a4U;
Td1[3] = 0x963a275eU;
Td1[4] = 0xcb3bab6bU;
Td1[5] = 0xf11f9d45U;
Td1[6] = 0xabacfa58U;
Td1[7] = 0x934be303U;
Td1[8] = 0x552030faU;
Td1[9] = 0xf6ad766dU;
Td1[10] = 0x9188cc76U;
Td1[11] = 0x25f5024cU;
Td1[12] = 0xfc4fe5d7U;
Td1[13] = 0xd7c52acbU;
Td1[14] = 0x80263544U;
Td1[15] = 0x8fb562a3U;
Td1[16] = 0x49deb15aU;
Td1[17] = 0x6725ba1bU;
Td1[18] = 0x9845ea0eU;
Td1[19] = 0xe15dfec0U;
Td1[20] = 0x02c32f75U;
Td1[21] = 0x12814cf0U;
Td1[22] = 0xa38d4697U;
Td1[23] = 0xc66bd3f9U;
Td1[24] = 0xe7038f5fU;
Td1[25] = 0x9515929cU;
Td1[26] = 0xebbf6d7aU;
Td1[27] = 0xda955259U;
Td1[28] = 0x2dd4be83U;
Td1[29] = 0xd3587421U;
Td1[30] = 0x2949e069U;
Td1[31] = 0x448ec9c8U;
Td1[32] = 0x6a75c289U;
Td1[33] = 0x78f48e79U;
Td1[34] = 0x6b99583eU;
Td1[35] = 0xdd27b971U;
Td1[36] = 0xb6bee14fU;
Td1[37] = 0x17f088adU;
Td1[38] = 0x66c920acU;
Td1[39] = 0xb47dce3aU;
Td1[40] = 0x1863df4aU;
Td1[41] = 0x82e51a31U;
Td1[42] = 0x60975133U;
Td1[43] = 0x4562537fU;
Td1[44] = 0xe0b16477U;
Td1[45] = 0x84bb6baeU;
Td1[46] = 0x1cfe81a0U;
Td1[47] = 0x94f9082bU;
Td1[48] = 0x58704868U;
Td1[49] = 0x198f45fdU;
Td1[50] = 0x8794de6cU;
Td1[51] = 0xb7527bf8U;
Td1[52] = 0x23ab73d3U;
Td1[53] = 0xe2724b02U;
Td1[54] = 0x57e31f8fU;
Td1[55] = 0x2a6655abU;
Td1[56] = 0x07b2eb28U;
Td1[57] = 0x032fb5c2U;
Td1[58] = 0x9a86c57bU;
Td1[59] = 0xa5d33708U;
Td1[60] = 0xf2302887U;
Td1[61] = 0xb223bfa5U;
Td1[62] = 0xba02036aU;
Td1[63] = 0x5ced1682U;
Td1[64] = 0x2b8acf1cU;
Td1[65] = 0x92a779b4U;
Td1[66] = 0xf0f307f2U;
Td1[67] = 0xa14e69e2U;
Td1[68] = 0xcd65daf4U;
Td1[69] = 0xd50605beU;
Td1[70] = 0x1fd13462U;
Td1[71] = 0x8ac4a6feU;
Td1[72] = 0x9d342e53U;
Td1[73] = 0xa0a2f355U;
Td1[74] = 0x32058ae1U;
Td1[75] = 0x75a4f6ebU;
Td1[76] = 0x390b83ecU;
Td1[77] = 0xaa4060efU;
Td1[78] = 0x065e719fU;
Td1[79] = 0x51bd6e10U;
Td1[80] = 0xf93e218aU;
Td1[81] = 0x3d96dd06U;
Td1[82] = 0xaedd3e05U;
Td1[83] = 0x464de6bdU;
Td1[84] = 0xb591548dU;
Td1[85] = 0x0571c45dU;
Td1[86] = 0x6f0406d4U;
Td1[87] = 0xff605015U;
Td1[88] = 0x241998fbU;
Td1[89] = 0x97d6bde9U;
Td1[90] = 0xcc894043U;
Td1[91] = 0x7767d99eU;
Td1[92] = 0xbdb0e842U;
Td1[93] = 0x8807898bU;
Td1[94] = 0x38e7195bU;
Td1[95] = 0xdb79c8eeU;
Td1[96] = 0x47a17c0aU;
Td1[97] = 0xe97c420fU;
Td1[98] = 0xc9f8841eU;
Td1[99] = 0x00000000U;
Td1[100] = 0x83098086U;
Td1[101] = 0x48322bedU;
Td1[102] = 0xac1e1170U;
Td1[103] = 0x4e6c5a72U;
Td1[104] = 0xfbfd0effU;
Td1[105] = 0x560f8538U;
Td1[106] = 0x1e3daed5U;
Td1[107] = 0x27362d39U;
Td1[108] = 0x640a0fd9U;
Td1[109] = 0x21685ca6U;
Td1[110] = 0xd19b5b54U;
Td1[111] = 0x3a24362eU;
Td1[112] = 0xb10c0a67U;
Td1[113] = 0x0f9357e7U;
Td1[114] = 0xd2b4ee96U;
Td1[115] = 0x9e1b9b91U;
Td1[116] = 0x4f80c0c5U;
Td1[117] = 0xa261dc20U;
Td1[118] = 0x695a774bU;
Td1[119] = 0x161c121aU;
Td1[120] = 0x0ae293baU;
Td1[121] = 0xe5c0a02aU;
Td1[122] = 0x433c22e0U;
Td1[123] = 0x1d121b17U;
Td1[124] = 0x0b0e090dU;
Td1[125] = 0xadf28bc7U;
Td1[126] = 0xb92db6a8U;
Td1[127] = 0xc8141ea9U;
Td1[128] = 0x8557f119U;
Td1[129] = 0x4caf7507U;
Td1[130] = 0xbbee99ddU;
Td1[131] = 0xfda37f60U;
Td1[132] = 0x9ff70126U;
Td1[133] = 0xbc5c72f5U;
Td1[134] = 0xc544663bU;
Td1[135] = 0x345bfb7eU;
Td1[136] = 0x768b4329U;
Td1[137] = 0xdccb23c6U;
Td1[138] = 0x68b6edfcU;
Td1[139] = 0x63b8e4f1U;
Td1[140] = 0xcad731dcU;
Td1[141] = 0x10426385U;
Td1[142] = 0x40139722U;
Td1[143] = 0x2084c611U;
Td1[144] = 0x7d854a24U;
Td1[145] = 0xf8d2bb3dU;
Td1[146] = 0x11aef932U;
Td1[147] = 0x6dc729a1U;
Td1[148] = 0x4b1d9e2fU;
Td1[149] = 0xf3dcb230U;
Td1[150] = 0xec0d8652U;
Td1[151] = 0xd077c1e3U;
Td1[152] = 0x6c2bb316U;
Td1[153] = 0x99a970b9U;
Td1[154] = 0xfa119448U;
Td1[155] = 0x2247e964U;
Td1[156] = 0xc4a8fc8cU;
Td1[157] = 0x1aa0f03fU;
Td1[158] = 0xd8567d2cU;
Td1[159] = 0xef223390U;
Td1[160] = 0xc787494eU;
Td1[161] = 0xc1d938d1U;
Td1[162] = 0xfe8ccaa2U;
Td1[163] = 0x3698d40bU;
Td1[164] = 0xcfa6f581U;
Td1[165] = 0x28a57adeU;
Td1[166] = 0x26dab78eU;
Td1[167] = 0xa43fadbfU;
Td1[168] = 0xe42c3a9dU;
Td1[169] = 0x0d507892U;
Td1[170] = 0x9b6a5fccU;
Td1[171] = 0x62547e46U;
Td1[172] = 0xc2f68d13U;
Td1[173] = 0xe890d8b8U;
Td1[174] = 0x5e2e39f7U;
Td1[175] = 0xf582c3afU;
Td1[176] = 0xbe9f5d80U;
Td1[177] = 0x7c69d093U;
Td1[178] = 0xa96fd52dU;
Td1[179] = 0xb3cf2512U;
Td1[180] = 0x3bc8ac99U;
Td1[181] = 0xa710187dU;
Td1[182] = 0x6ee89c63U;
Td1[183] = 0x7bdb3bbbU;
Td1[184] = 0x09cd2678U;
Td1[185] = 0xf46e5918U;
Td1[186] = 0x01ec9ab7U;
Td1[187] = 0xa8834f9aU;
Td1[188] = 0x65e6956eU;
Td1[189] = 0x7eaaffe6U;
Td1[190] = 0x0821bccfU;
Td1[191] = 0xe6ef15e8U;
Td1[192] = 0xd9bae79bU;
Td1[193] = 0xce4a6f36U;
Td1[194] = 0xd4ea9f09U;
Td1[195] = 0xd629b07cU;
Td1[196] = 0xaf31a4b2U;
Td1[197] = 0x312a3f23U;
Td1[198] = 0x30c6a594U;
Td1[199] = 0xc035a266U;
Td1[200] = 0x37744ebcU;
Td1[201] = 0xa6fc82caU;
Td1[202] = 0xb0e090d0U;
Td1[203] = 0x1533a7d8U;
Td1[204] = 0x4af10498U;
Td1[205] = 0xf741ecdaU;
Td1[206] = 0x0e7fcd50U;
Td1[207] = 0x2f1791f6U;
Td1[208] = 0x8d764dd6U;
Td1[209] = 0x4d43efb0U;
Td1[210] = 0x54ccaa4dU;
Td1[211] = 0xdfe49604U;
Td1[212] = 0xe39ed1b5U;
Td1[213] = 0x1b4c6a88U;
Td1[214] = 0xb8c12c1fU;
Td1[215] = 0x7f466551U;
Td1[216] = 0x049d5eeaU;
Td1[217] = 0x5d018c35U;
Td1[218] = 0x73fa8774U;
Td1[219] = 0x2efb0b41U;
Td1[220] = 0x5ab3671dU;
Td1[221] = 0x5292dbd2U;
Td1[222] = 0x33e91056U;
Td1[223] = 0x136dd647U;
Td1[224] = 0x8c9ad761U;
Td1[225] = 0x7a37a10cU;
Td1[226] = 0x8e59f814U;
Td1[227] = 0x89eb133cU;
Td1[228] = 0xeecea927U;
Td1[229] = 0x35b761c9U;
Td1[230] = 0xede11ce5U;
Td1[231] = 0x3c7a47b1U;
Td1[232] = 0x599cd2dfU;
Td1[233] = 0x3f55f273U;
Td1[234] = 0x791814ceU;
Td1[235] = 0xbf73c737U;
Td1[236] = 0xea53f7cdU;
Td1[237] = 0x5b5ffdaaU;
Td1[238] = 0x14df3d6fU;
Td1[239] = 0x867844dbU;
Td1[240] = 0x81caaff3U;
Td1[241] = 0x3eb968c4U;
Td1[242] = 0x2c382434U;
Td1[243] = 0x5fc2a340U;
Td1[244] = 0x72161dc3U;
Td1[245] = 0x0cbce225U;
Td1[246] = 0x8b283c49U;
Td1[247] = 0x41ff0d95U;
Td1[248] = 0x7139a801U;
Td1[249] = 0xde080cb3U;
Td1[250] = 0x9cd8b4e4U;
Td1[251] = 0x906456c1U;
Td1[252] = 0x617bcb84U;
Td1[253] = 0x70d532b6U;
Td1[254] = 0x74486c5cU;
Td1[255] = 0x42d0b857U;
Td2 = malloc(sizeof(uint32_t) * 256)
Td2[0] = 0xa75051f4U;
Td2[1] = 0x65537e41U;
Td2[2] = 0xa4c31a17U;
Td2[3] = 0x5e963a27U;
Td2[4] = 0x6bcb3babU;
Td2[5] = 0x45f11f9dU;
Td2[6] = 0x58abacfaU;
Td2[7] = 0x03934be3U;
Td2[8] = 0xfa552030U;
Td2[9] = 0x6df6ad76U;
Td2[10] = 0x769188ccU;
Td2[11] = 0x4c25f502U;
Td2[12] = 0xd7fc4fe5U;
Td2[13] = 0xcbd7c52aU;
Td2[14] = 0x44802635U;
Td2[15] = 0xa38fb562U;
Td2[16] = 0x5a49deb1U;
Td2[17] = 0x1b6725baU;
Td2[18] = 0x0e9845eaU;
Td2[19] = 0xc0e15dfeU;
Td2[20] = 0x7502c32fU;
Td2[21] = 0xf012814cU;
Td2[22] = 0x97a38d46U;
Td2[23] = 0xf9c66bd3U;
Td2[24] = 0x5fe7038fU;
Td2[25] = 0x9c951592U;
Td2[26] = 0x7aebbf6dU;
Td2[27] = 0x59da9552U;
Td2[28] = 0x832dd4beU;
Td2[29] = 0x21d35874U;
Td2[30] = 0x692949e0U;
Td2[31] = 0xc8448ec9U;
Td2[32] = 0x896a75c2U;
Td2[33] = 0x7978f48eU;
Td2[34] = 0x3e6b9958U;
Td2[35] = 0x71dd27b9U;
Td2[36] = 0x4fb6bee1U;
Td2[37] = 0xad17f088U;
Td2[38] = 0xac66c920U;
Td2[39] = 0x3ab47dceU;
Td2[40] = 0x4a1863dfU;
Td2[41] = 0x3182e51aU;
Td2[42] = 0x33609751U;
Td2[43] = 0x7f456253U;
Td2[44] = 0x77e0b164U;
Td2[45] = 0xae84bb6bU;
Td2[46] = 0xa01cfe81U;
Td2[47] = 0x2b94f908U;
Td2[48] = 0x68587048U;
Td2[49] = 0xfd198f45U;
Td2[50] = 0x6c8794deU;
Td2[51] = 0xf8b7527bU;
Td2[52] = 0xd323ab73U;
Td2[53] = 0x02e2724bU;
Td2[54] = 0x8f57e31fU;
Td2[55] = 0xab2a6655U;
Td2[56] = 0x2807b2ebU;
Td2[57] = 0xc2032fb5U;
Td2[58] = 0x7b9a86c5U;
Td2[59] = 0x08a5d337U;
Td2[60] = 0x87f23028U;
Td2[61] = 0xa5b223bfU;
Td2[62] = 0x6aba0203U;
Td2[63] = 0x825ced16U;
Td2[64] = 0x1c2b8acfU;
Td2[65] = 0xb492a779U;
Td2[66] = 0xf2f0f307U;
Td2[67] = 0xe2a14e69U;
Td2[68] = 0xf4cd65daU;
Td2[69] = 0xbed50605U;
Td2[70] = 0x621fd134U;
Td2[71] = 0xfe8ac4a6U;
Td2[72] = 0x539d342eU;
Td2[73] = 0x55a0a2f3U;
Td2[74] = 0xe132058aU;
Td2[75] = 0xeb75a4f6U;
Td2[76] = 0xec390b83U;
Td2[77] = 0xefaa4060U;
Td2[78] = 0x9f065e71U;
Td2[79] = 0x1051bd6eU;
Td2[80] = 0x8af93e21U;
Td2[81] = 0x063d96ddU;
Td2[82] = 0x05aedd3eU;
Td2[83] = 0xbd464de6U;
Td2[84] = 0x8db59154U;
Td2[85] = 0x5d0571c4U;
Td2[86] = 0xd46f0406U;
Td2[87] = 0x15ff6050U;
Td2[88] = 0xfb241998U;
Td2[89] = 0xe997d6bdU;
Td2[90] = 0x43cc8940U;
Td2[91] = 0x9e7767d9U;
Td2[92] = 0x42bdb0e8U;
Td2[93] = 0x8b880789U;
Td2[94] = 0x5b38e719U;
Td2[95] = 0xeedb79c8U;
Td2[96] = 0x0a47a17cU;
Td2[97] = 0x0fe97c42U;
Td2[98] = 0x1ec9f884U;
Td2[99] = 0x00000000U;
Td2[100] = 0x86830980U;
Td2[101] = 0xed48322bU;
Td2[102] = 0x70ac1e11U;
Td2[103] = 0x724e6c5aU;
Td2[104] = 0xfffbfd0eU;
Td2[105] = 0x38560f85U;
Td2[106] = 0xd51e3daeU;
Td2[107] = 0x3927362dU;
Td2[108] = 0xd9640a0fU;
Td2[109] = 0xa621685cU;
Td2[110] = 0x54d19b5bU;
Td2[111] = 0x2e3a2436U;
Td2[112] = 0x67b10c0aU;
Td2[113] = 0xe70f9357U;
Td2[114] = 0x96d2b4eeU;
Td2[115] = 0x919e1b9bU;
Td2[116] = 0xc54f80c0U;
Td2[117] = 0x20a261dcU;
Td2[118] = 0x4b695a77U;
Td2[119] = 0x1a161c12U;
Td2[120] = 0xba0ae293U;
Td2[121] = 0x2ae5c0a0U;
Td2[122] = 0xe0433c22U;
Td2[123] = 0x171d121bU;
Td2[124] = 0x0d0b0e09U;
Td2[125] = 0xc7adf28bU;
Td2[126] = 0xa8b92db6U;
Td2[127] = 0xa9c8141eU;
Td2[128] = 0x198557f1U;
Td2[129] = 0x074caf75U;
Td2[130] = 0xddbbee99U;
Td2[131] = 0x60fda37fU;
Td2[132] = 0x269ff701U;
Td2[133] = 0xf5bc5c72U;
Td2[134] = 0x3bc54466U;
Td2[135] = 0x7e345bfbU;
Td2[136] = 0x29768b43U;
Td2[137] = 0xc6dccb23U;
Td2[138] = 0xfc68b6edU;
Td2[139] = 0xf163b8e4U;
Td2[140] = 0xdccad731U;
Td2[141] = 0x85104263U;
Td2[142] = 0x22401397U;
Td2[143] = 0x112084c6U;
Td2[144] = 0x247d854aU;
Td2[145] = 0x3df8d2bbU;
Td2[146] = 0x3211aef9U;
Td2[147] = 0xa16dc729U;
Td2[148] = 0x2f4b1d9eU;
Td2[149] = 0x30f3dcb2U;
Td2[150] = 0x52ec0d86U;
Td2[151] = 0xe3d077c1U;
Td2[152] = 0x166c2bb3U;
Td2[153] = 0xb999a970U;
Td2[154] = 0x48fa1194U;
Td2[155] = 0x642247e9U;
Td2[156] = 0x8cc4a8fcU;
Td2[157] = 0x3f1aa0f0U;
Td2[158] = 0x2cd8567dU;
Td2[159] = 0x90ef2233U;
Td2[160] = 0x4ec78749U;
Td2[161] = 0xd1c1d938U;
Td2[162] = 0xa2fe8ccaU;
Td2[163] = 0x0b3698d4U;
Td2[164] = 0x81cfa6f5U;
Td2[165] = 0xde28a57aU;
Td2[166] = 0x8e26dab7U;
Td2[167] = 0xbfa43fadU;
Td2[168] = 0x9de42c3aU;
Td2[169] = 0x920d5078U;
Td2[170] = 0xcc9b6a5fU;
Td2[171] = 0x4662547eU;
Td2[172] = 0x13c2f68dU;
Td2[173] = 0xb8e890d8U;
Td2[174] = 0xf75e2e39U;
Td2[175] = 0xaff582c3U;
Td2[176] = 0x80be9f5dU;
Td2[177] = 0x937c69d0U;
Td2[178] = 0x2da96fd5U;
Td2[179] = 0x12b3cf25U;
Td2[180] = 0x993bc8acU;
Td2[181] = 0x7da71018U;
Td2[182] = 0x636ee89cU;
Td2[183] = 0xbb7bdb3bU;
Td2[184] = 0x7809cd26U;
Td2[185] = 0x18f46e59U;
Td2[186] = 0xb701ec9aU;
Td2[187] = 0x9aa8834fU;
Td2[188] = 0x6e65e695U;
Td2[189] = 0xe67eaaffU;
Td2[190] = 0xcf0821bcU;
Td2[191] = 0xe8e6ef15U;
Td2[192] = 0x9bd9bae7U;
Td2[193] = 0x36ce4a6fU;
Td2[194] = 0x09d4ea9fU;
Td2[195] = 0x7cd629b0U;
Td2[196] = 0xb2af31a4U;
Td2[197] = 0x23312a3fU;
Td2[198] = 0x9430c6a5U;
Td2[199] = 0x66c035a2U;
Td2[200] = 0xbc37744eU;
Td2[201] = 0xcaa6fc82U;
Td2[202] = 0xd0b0e090U;
Td2[203] = 0xd81533a7U;
Td2[204] = 0x984af104U;
Td2[205] = 0xdaf741ecU;
Td2[206] = 0x500e7fcdU;
Td2[207] = 0xf62f1791U;
Td2[208] = 0xd68d764dU;
Td2[209] = 0xb04d43efU;
Td2[210] = 0x4d54ccaaU;
Td2[211] = 0x04dfe496U;
Td2[212] = 0xb5e39ed1U;
Td2[213] = 0x881b4c6aU;
Td2[214] = 0x1fb8c12cU;
Td2[215] = 0x517f4665U;
Td2[216] = 0xea049d5eU;
Td2[217] = 0x355d018cU;
Td2[218] = 0x7473fa87U;
Td2[219] = 0x412efb0bU;
Td2[220] = 0x1d5ab367U;
Td2[221] = 0xd25292dbU;
Td2[222] = 0x5633e910U;
Td2[223] = 0x47136dd6U;
Td2[224] = 0x618c9ad7U;
Td2[225] = 0x0c7a37a1U;
Td2[226] = 0x148e59f8U;
Td2[227] = 0x3c89eb13U;
Td2[228] = 0x27eecea9U;
Td2[229] = 0xc935b761U;
Td2[230] = 0xe5ede11cU;
Td2[231] = 0xb13c7a47U;
Td2[232] = 0xdf599cd2U;
Td2[233] = 0x733f55f2U;
Td2[234] = 0xce791814U;
Td2[235] = 0x37bf73c7U;
Td2[236] = 0xcdea53f7U;
Td2[237] = 0xaa5b5ffdU;
Td2[238] = 0x6f14df3dU;
Td2[239] = 0xdb867844U;
Td2[240] = 0xf381caafU;
Td2[241] = 0xc43eb968U;
Td2[242] = 0x342c3824U;
Td2[243] = 0x405fc2a3U;
Td2[244] = 0xc372161dU;
Td2[245] = 0x250cbce2U;
Td2[246] = 0x498b283cU;
Td2[247] = 0x9541ff0dU;
Td2[248] = 0x017139a8U;
Td2[249] = 0xb3de080cU;
Td2[250] = 0xe49cd8b4U;
Td2[251] = 0xc1906456U;
Td2[252] = 0x84617bcbU;
Td2[253] = 0xb670d532U;
Td2[254] = 0x5c74486cU;
Td2[255] = 0x5742d0b8U;
Td3 = malloc(sizeof(uint32_t) * 256)
Td3[0] = 0xf4a75051U;
Td3[1] = 0x4165537eU;
Td3[2] = 0x17a4c31aU;
Td3[3] = 0x275e963aU;
Td3[4] = 0xab6bcb3bU;
Td3[5] = 0x9d45f11fU;
Td3[6] = 0xfa58abacU;
Td3[7] = 0xe303934bU;
Td3[8] = 0x30fa5520U;
Td3[9] = 0x766df6adU;
Td3[10] = 0xcc769188U;
Td3[11] = 0x024c25f5U;
Td3[12] = 0xe5d7fc4fU;
Td3[13] = 0x2acbd7c5U;
Td3[14] = 0x35448026U;
Td3[15] = 0x62a38fb5U;
Td3[16] = 0xb15a49deU;
Td3[17] = 0xba1b6725U;
Td3[18] = 0xea0e9845U;
Td3[19] = 0xfec0e15dU;
Td3[20] = 0x2f7502c3U;
Td3[21] = 0x4cf01281U;
Td3[22] = 0x4697a38dU;
Td3[23] = 0xd3f9c66bU;
Td3[24] = 0x8f5fe703U;
Td3[25] = 0x929c9515U;
Td3[26] = 0x6d7aebbfU;
Td3[27] = 0x5259da95U;
Td3[28] = 0xbe832dd4U;
Td3[29] = 0x7421d358U;
Td3[30] = 0xe0692949U;
Td3[31] = 0xc9c8448eU;
Td3[32] = 0xc2896a75U;
Td3[33] = 0x8e7978f4U;
Td3[34] = 0x583e6b99U;
Td3[35] = 0xb971dd27U;
Td3[36] = 0xe14fb6beU;
Td3[37] = 0x88ad17f0U;
Td3[38] = 0x20ac66c9U;
Td3[39] = 0xce3ab47dU;
Td3[40] = 0xdf4a1863U;
Td3[41] = 0x1a3182e5U;
Td3[42] = 0x51336097U;
Td3[43] = 0x537f4562U;
Td3[44] = 0x6477e0b1U;
Td3[45] = 0x6bae84bbU;
Td3[46] = 0x81a01cfeU;
Td3[47] = 0x082b94f9U;
Td3[48] = 0x48685870U;
Td3[49] = 0x45fd198fU;
Td3[50] = 0xde6c8794U;
Td3[51] = 0x7bf8b752U;
Td3[52] = 0x73d323abU;
Td3[53] = 0x4b02e272U;
Td3[54] = 0x1f8f57e3U;
Td3[55] = 0x55ab2a66U;
Td3[56] = 0xeb2807b2U;
Td3[57] = 0xb5c2032fU;
Td3[58] = 0xc57b9a86U;
Td3[59] = 0x3708a5d3U;
Td3[60] = 0x2887f230U;
Td3[61] = 0xbfa5b223U;
Td3[62] = 0x036aba02U;
Td3[63] = 0x16825cedU;
Td3[64] = 0xcf1c2b8aU;
Td3[65] = 0x79b492a7U;
Td3[66] = 0x07f2f0f3U;
Td3[67] = 0x69e2a14eU;
Td3[68] = 0xdaf4cd65U;
Td3[69] = 0x05bed506U;
Td3[70] = 0x34621fd1U;
Td3[71] = 0xa6fe8ac4U;
Td3[72] = 0x2e539d34U;
Td3[73] = 0xf355a0a2U;
Td3[74] = 0x8ae13205U;
Td3[75] = 0xf6eb75a4U;
Td3[76] = 0x83ec390bU;
Td3[77] = 0x60efaa40U;
Td3[78] = 0x719f065eU;
Td3[79] = 0x6e1051bdU;
Td3[80] = 0x218af93eU;
Td3[81] = 0xdd063d96U;
Td3[82] = 0x3e05aeddU;
Td3[83] = 0xe6bd464dU;
Td3[84] = 0x548db591U;
Td3[85] = 0xc45d0571U;
Td3[86] = 0x06d46f04U;
Td3[87] = 0x5015ff60U;
Td3[88] = 0x98fb2419U;
Td3[89] = 0xbde997d6U;
Td3[90] = 0x4043cc89U;
Td3[91] = 0xd99e7767U;
Td3[92] = 0xe842bdb0U;
Td3[93] = 0x898b8807U;
Td3[94] = 0x195b38e7U;
Td3[95] = 0xc8eedb79U;
Td3[96] = 0x7c0a47a1U;
Td3[97] = 0x420fe97cU;
Td3[98] = 0x841ec9f8U;
Td3[99] = 0x00000000U;
Td3[100] = 0x80868309U;
Td3[101] = 0x2bed4832U;
Td3[102] = 0x1170ac1eU;
Td3[103] = 0x5a724e6cU;
Td3[104] = 0x0efffbfdU;
Td3[105] = 0x8538560fU;
Td3[106] = 0xaed51e3dU;
Td3[107] = 0x2d392736U;
Td3[108] = 0x0fd9640aU;
Td3[109] = 0x5ca62168U;
Td3[110] = 0x5b54d19bU;
Td3[111] = 0x362e3a24U;
Td3[112] = 0x0a67b10cU;
Td3[113] = 0x57e70f93U;
Td3[114] = 0xee96d2b4U;
Td3[115] = 0x9b919e1bU;
Td3[116] = 0xc0c54f80U;
Td3[117] = 0xdc20a261U;
Td3[118] = 0x774b695aU;
Td3[119] = 0x121a161cU;
Td3[120] = 0x93ba0ae2U;
Td3[121] = 0xa02ae5c0U;
Td3[122] = 0x22e0433cU;
Td3[123] = 0x1b171d12U;
Td3[124] = 0x090d0b0eU;
Td3[125] = 0x8bc7adf2U;
Td3[126] = 0xb6a8b92dU;
Td3[127] = 0x1ea9c814U;
Td3[128] = 0xf1198557U;
Td3[129] = 0x75074cafU;
Td3[130] = 0x99ddbbeeU;
Td3[131] = 0x7f60fda3U;
Td3[132] = 0x01269ff7U;
Td3[133] = 0x72f5bc5cU;
Td3[134] = 0x663bc544U;
Td3[135] = 0xfb7e345bU;
Td3[136] = 0x4329768bU;
Td3[137] = 0x23c6dccbU;
Td3[138] = 0xedfc68b6U;
Td3[139] = 0xe4f163b8U;
Td3[140] = 0x31dccad7U;
Td3[141] = 0x63851042U;
Td3[142] = 0x97224013U;
Td3[143] = 0xc6112084U;
Td3[144] = 0x4a247d85U;
Td3[145] = 0xbb3df8d2U;
Td3[146] = 0xf93211aeU;
Td3[147] = 0x29a16dc7U;
Td3[148] = 0x9e2f4b1dU;
Td3[149] = 0xb230f3dcU;
Td3[150] = 0x8652ec0dU;
Td3[151] = 0xc1e3d077U;
Td3[152] = 0xb3166c2bU;
Td3[153] = 0x70b999a9U;
Td3[154] = 0x9448fa11U;
Td3[155] = 0xe9642247U;
Td3[156] = 0xfc8cc4a8U;
Td3[157] = 0xf03f1aa0U;
Td3[158] = 0x7d2cd856U;
Td3[159] = 0x3390ef22U;
Td3[160] = 0x494ec787U;
Td3[161] = 0x38d1c1d9U;
Td3[162] = 0xcaa2fe8cU;
Td3[163] = 0xd40b3698U;
Td3[164] = 0xf581cfa6U;
Td3[165] = 0x7ade28a5U;
Td3[166] = 0xb78e26daU;
Td3[167] = 0xadbfa43fU;
Td3[168] = 0x3a9de42cU;
Td3[169] = 0x78920d50U;
Td3[170] = 0x5fcc9b6aU;
Td3[171] = 0x7e466254U;
Td3[172] = 0x8d13c2f6U;
Td3[173] = 0xd8b8e890U;
Td3[174] = 0x39f75e2eU;
Td3[175] = 0xc3aff582U;
Td3[176] = 0x5d80be9fU;
Td3[177] = 0xd0937c69U;
Td3[178] = 0xd52da96fU;
Td3[179] = 0x2512b3cfU;
Td3[180] = 0xac993bc8U;
Td3[181] = 0x187da710U;
Td3[182] = 0x9c636ee8U;
Td3[183] = 0x3bbb7bdbU;
Td3[184] = 0x267809cdU;
Td3[185] = 0x5918f46eU;
Td3[186] = 0x9ab701ecU;
Td3[187] = 0x4f9aa883U;
Td3[188] = 0x956e65e6U;
Td3[189] = 0xffe67eaaU;
Td3[190] = 0xbccf0821U;
Td3[191] = 0x15e8e6efU;
Td3[192] = 0xe79bd9baU;
Td3[193] = 0x6f36ce4aU;
Td3[194] = 0x9f09d4eaU;
Td3[195] = 0xb07cd629U;
Td3[196] = 0xa4b2af31U;
Td3[197] = 0x3f23312aU;
Td3[198] = 0xa59430c6U;
Td3[199] = 0xa266c035U;
Td3[200] = 0x4ebc3774U;
Td3[201] = 0x82caa6fcU;
Td3[202] = 0x90d0b0e0U;
Td3[203] = 0xa7d81533U;
Td3[204] = 0x04984af1U;
Td3[205] = 0xecdaf741U;
Td3[206] = 0xcd500e7fU;
Td3[207] = 0x91f62f17U;
Td3[208] = 0x4dd68d76U;
Td3[209] = 0xefb04d43U;
Td3[210] = 0xaa4d54ccU;
Td3[211] = 0x9604dfe4U;
Td3[212] = 0xd1b5e39eU;
Td3[213] = 0x6a881b4cU;
Td3[214] = 0x2c1fb8c1U;
Td3[215] = 0x65517f46U;
Td3[216] = 0x5eea049dU;
Td3[217] = 0x8c355d01U;
Td3[218] = 0x877473faU;
Td3[219] = 0x0b412efbU;
Td3[220] = 0x671d5ab3U;
Td3[221] = 0xdbd25292U;
Td3[222] = 0x105633e9U;
Td3[223] = 0xd647136dU;
Td3[224] = 0xd7618c9aU;
Td3[225] = 0xa10c7a37U;
Td3[226] = 0xf8148e59U;
Td3[227] = 0x133c89ebU;
Td3[228] = 0xa927eeceU;
Td3[229] = 0x61c935b7U;
Td3[230] = 0x1ce5ede1U;
Td3[231] = 0x47b13c7aU;
Td3[232] = 0xd2df599cU;
Td3[233] = 0xf2733f55U;
Td3[234] = 0x14ce7918U;
Td3[235] = 0xc737bf73U;
Td3[236] = 0xf7cdea53U;
Td3[237] = 0xfdaa5b5fU;
Td3[238] = 0x3d6f14dfU;
Td3[239] = 0x44db8678U;
Td3[240] = 0xaff381caU;
Td3[241] = 0x68c43eb9U;
Td3[242] = 0x24342c38U;
Td3[243] = 0xa3405fc2U;
Td3[244] = 0x1dc37216U;
Td3[245] = 0xe2250cbcU;
Td3[246] = 0x3c498b28U;
Td3[247] = 0x0d9541ffU;
Td3[248] = 0xa8017139U;
Td3[249] = 0x0cb3de08U;
Td3[250] = 0xb4e49cd8U;
Td3[251] = 0x56c19064U;
Td3[252] = 0xcb84617bU;
Td3[253] = 0x32b670d5U;
Td3[254] = 0x6c5c7448U;
Td3[255] = 0xb85742d0U;
Td4 = malloc(sizeof(uint32_t) * 256)
Td4[0] = 0x52525252U;
Td4[1] = 0x09090909U;
Td4[2] = 0x6a6a6a6aU;
Td4[3] = 0xd5d5d5d5U;
Td4[4] = 0x30303030U;
Td4[5] = 0x36363636U;
Td4[6] = 0xa5a5a5a5U;
Td4[7] = 0x38383838U;
Td4[8] = 0xbfbfbfbfU;
Td4[9] = 0x40404040U;
Td4[10] = 0xa3a3a3a3U;
Td4[11] = 0x9e9e9e9eU;
Td4[12] = 0x81818181U;
Td4[13] = 0xf3f3f3f3U;
Td4[14] = 0xd7d7d7d7U;
Td4[15] = 0xfbfbfbfbU;
Td4[16] = 0x7c7c7c7cU;
Td4[17] = 0xe3e3e3e3U;
Td4[18] = 0x39393939U;
Td4[19] = 0x82828282U;
Td4[20] = 0x9b9b9b9bU;
Td4[21] = 0x2f2f2f2fU;
Td4[22] = 0xffffffffU;
Td4[23] = 0x87878787U;
Td4[24] = 0x34343434U;
Td4[25] = 0x8e8e8e8eU;
Td4[26] = 0x43434343U;
Td4[27] = 0x44444444U;
Td4[28] = 0xc4c4c4c4U;
Td4[29] = 0xdedededeU;
Td4[30] = 0xe9e9e9e9U;
Td4[31] = 0xcbcbcbcbU;
Td4[32] = 0x54545454U;
Td4[33] = 0x7b7b7b7bU;
Td4[34] = 0x94949494U;
Td4[35] = 0x32323232U;
Td4[36] = 0xa6a6a6a6U;
Td4[37] = 0xc2c2c2c2U;
Td4[38] = 0x23232323U;
Td4[39] = 0x3d3d3d3dU;
Td4[40] = 0xeeeeeeeeU;
Td4[41] = 0x4c4c4c4cU;
Td4[42] = 0x95959595U;
Td4[43] = 0x0b0b0b0bU;
Td4[44] = 0x42424242U;
Td4[45] = 0xfafafafaU;
Td4[46] = 0xc3c3c3c3U;
Td4[47] = 0x4e4e4e4eU;
Td4[48] = 0x08080808U;
Td4[49] = 0x2e2e2e2eU;
Td4[50] = 0xa1a1a1a1U;
Td4[51] = 0x66666666U;
Td4[52] = 0x28282828U;
Td4[53] = 0xd9d9d9d9U;
Td4[54] = 0x24242424U;
Td4[55] = 0xb2b2b2b2U;
Td4[56] = 0x76767676U;
Td4[57] = 0x5b5b5b5bU;
Td4[58] = 0xa2a2a2a2U;
Td4[59] = 0x49494949U;
Td4[60] = 0x6d6d6d6dU;
Td4[61] = 0x8b8b8b8bU;
Td4[62] = 0xd1d1d1d1U;
Td4[63] = 0x25252525U;
Td4[64] = 0x72727272U;
Td4[65] = 0xf8f8f8f8U;
Td4[66] = 0xf6f6f6f6U;
Td4[67] = 0x64646464U;
Td4[68] = 0x86868686U;
Td4[69] = 0x68686868U;
Td4[70] = 0x98989898U;
Td4[71] = 0x16161616U;
Td4[72] = 0xd4d4d4d4U;
Td4[73] = 0xa4a4a4a4U;
Td4[74] = 0x5c5c5c5cU;
Td4[75] = 0xccccccccU;
Td4[76] = 0x5d5d5d5dU;
Td4[77] = 0x65656565U;
Td4[78] = 0xb6b6b6b6U;
Td4[79] = 0x92929292U;
Td4[80] = 0x6c6c6c6cU;
Td4[81] = 0x70707070U;
Td4[82] = 0x48484848U;
Td4[83] = 0x50505050U;
Td4[84] = 0xfdfdfdfdU;
Td4[85] = 0xededededU;
Td4[86] = 0xb9b9b9b9U;
Td4[87] = 0xdadadadaU;
Td4[88] = 0x5e5e5e5eU;
Td4[89] = 0x15151515U;
Td4[90] = 0x46464646U;
Td4[91] = 0x57575757U;
Td4[92] = 0xa7a7a7a7U;
Td4[93] = 0x8d8d8d8dU;
Td4[94] = 0x9d9d9d9dU;
Td4[95] = 0x84848484U;
Td4[96] = 0x90909090U;
Td4[97] = 0xd8d8d8d8U;
Td4[98] = 0xababababU;
Td4[99] = 0x00000000U;
Td4[100] = 0x8c8c8c8cU;
Td4[101] = 0xbcbcbcbcU;
Td4[102] = 0xd3d3d3d3U;
Td4[103] = 0x0a0a0a0aU;
Td4[104] = 0xf7f7f7f7U;
Td4[105] = 0xe4e4e4e4U;
Td4[106] = 0x58585858U;
Td4[107] = 0x05050505U;
Td4[108] = 0xb8b8b8b8U;
Td4[109] = 0xb3b3b3b3U;
Td4[110] = 0x45454545U;
Td4[111] = 0x06060606U;
Td4[112] = 0xd0d0d0d0U;
Td4[113] = 0x2c2c2c2cU;
Td4[114] = 0x1e1e1e1eU;
Td4[115] = 0x8f8f8f8fU;
Td4[116] = 0xcacacacaU;
Td4[117] = 0x3f3f3f3fU;
Td4[118] = 0x0f0f0f0fU;
Td4[119] = 0x02020202U;
Td4[120] = 0xc1c1c1c1U;
Td4[121] = 0xafafafafU;
Td4[122] = 0xbdbdbdbdU;
Td4[123] = 0x03030303U;
Td4[124] = 0x01010101U;
Td4[125] = 0x13131313U;
Td4[126] = 0x8a8a8a8aU;
Td4[127] = 0x6b6b6b6bU;
Td4[128] = 0x3a3a3a3aU;
Td4[129] = 0x91919191U;
Td4[130] = 0x11111111U;
Td4[131] = 0x41414141U;
Td4[132] = 0x4f4f4f4fU;
Td4[133] = 0x67676767U;
Td4[134] = 0xdcdcdcdcU;
Td4[135] = 0xeaeaeaeaU;
Td4[136] = 0x97979797U;
Td4[137] = 0xf2f2f2f2U;
Td4[138] = 0xcfcfcfcfU;
Td4[139] = 0xcecececeU;
Td4[140] = 0xf0f0f0f0U;
Td4[141] = 0xb4b4b4b4U;
Td4[142] = 0xe6e6e6e6U;
Td4[143] = 0x73737373U;
Td4[144] = 0x96969696U;
Td4[145] = 0xacacacacU;
Td4[146] = 0x74747474U;
Td4[147] = 0x22222222U;
Td4[148] = 0xe7e7e7e7U;
Td4[149] = 0xadadadadU;
Td4[150] = 0x35353535U;
Td4[151] = 0x85858585U;
Td4[152] = 0xe2e2e2e2U;
Td4[153] = 0xf9f9f9f9U;
Td4[154] = 0x37373737U;
Td4[155] = 0xe8e8e8e8U;
Td4[156] = 0x1c1c1c1cU;
Td4[157] = 0x75757575U;
Td4[158] = 0xdfdfdfdfU;
Td4[159] = 0x6e6e6e6eU;
Td4[160] = 0x47474747U;
Td4[161] = 0xf1f1f1f1U;
Td4[162] = 0x1a1a1a1aU;
Td4[163] = 0x71717171U;
Td4[164] = 0x1d1d1d1dU;
Td4[165] = 0x29292929U;
Td4[166] = 0xc5c5c5c5U;
Td4[167] = 0x89898989U;
Td4[168] = 0x6f6f6f6fU;
Td4[169] = 0xb7b7b7b7U;
Td4[170] = 0x62626262U;
Td4[171] = 0x0e0e0e0eU;
Td4[172] = 0xaaaaaaaaU;
Td4[173] = 0x18181818U;
Td4[174] = 0xbebebebeU;
Td4[175] = 0x1b1b1b1bU;
Td4[176] = 0xfcfcfcfcU;
Td4[177] = 0x56565656U;
Td4[178] = 0x3e3e3e3eU;
Td4[179] = 0x4b4b4b4bU;
Td4[180] = 0xc6c6c6c6U;
Td4[181] = 0xd2d2d2d2U;
Td4[182] = 0x79797979U;
Td4[183] = 0x20202020U;
Td4[184] = 0x9a9a9a9aU;
Td4[185] = 0xdbdbdbdbU;
Td4[186] = 0xc0c0c0c0U;
Td4[187] = 0xfefefefeU;
Td4[188] = 0x78787878U;
Td4[189] = 0xcdcdcdcdU;
Td4[190] = 0x5a5a5a5aU;
Td4[191] = 0xf4f4f4f4U;
Td4[192] = 0x1f1f1f1fU;
Td4[193] = 0xddddddddU;
Td4[194] = 0xa8a8a8a8U;
Td4[195] = 0x33333333U;
Td4[196] = 0x88888888U;
Td4[197] = 0x07070707U;
Td4[198] = 0xc7c7c7c7U;
Td4[199] = 0x31313131U;
Td4[200] = 0xb1b1b1b1U;
Td4[201] = 0x12121212U;
Td4[202] = 0x10101010U;
Td4[203] = 0x59595959U;
Td4[204] = 0x27272727U;
Td4[205] = 0x80808080U;
Td4[206] = 0xececececU;
Td4[207] = 0x5f5f5f5fU;
Td4[208] = 0x60606060U;
Td4[209] = 0x51515151U;
Td4[210] = 0x7f7f7f7fU;
Td4[211] = 0xa9a9a9a9U;
Td4[212] = 0x19191919U;
Td4[213] = 0xb5b5b5b5U;
Td4[214] = 0x4a4a4a4aU;
Td4[215] = 0x0d0d0d0dU;
Td4[216] = 0x2d2d2d2dU;
Td4[217] = 0xe5e5e5e5U;
Td4[218] = 0x7a7a7a7aU;
Td4[219] = 0x9f9f9f9fU;
Td4[220] = 0x93939393U;
Td4[221] = 0xc9c9c9c9U;
Td4[222] = 0x9c9c9c9cU;
Td4[223] = 0xefefefefU;
Td4[224] = 0xa0a0a0a0U;
Td4[225] = 0xe0e0e0e0U;
Td4[226] = 0x3b3b3b3bU;
Td4[227] = 0x4d4d4d4dU;
Td4[228] = 0xaeaeaeaeU;
Td4[229] = 0x2a2a2a2aU;
Td4[230] = 0xf5f5f5f5U;
Td4[231] = 0xb0b0b0b0U;
Td4[232] = 0xc8c8c8c8U;
Td4[233] = 0xebebebebU;
Td4[234] = 0xbbbbbbbbU;
Td4[235] = 0x3c3c3c3cU;
Td4[236] = 0x83838383U;
Td4[237] = 0x53535353U;
Td4[238] = 0x99999999U;
Td4[239] = 0x61616161U;
Td4[240] = 0x17171717U;
Td4[241] = 0x2b2b2b2bU;
Td4[242] = 0x04040404U;
Td4[243] = 0x7e7e7e7eU;
Td4[244] = 0xbabababaU;
Td4[245] = 0x77777777U;
Td4[246] = 0xd6d6d6d6U;
Td4[247] = 0x26262626U;
Td4[248] = 0xe1e1e1e1U;
Td4[249] = 0x69696969U;
Td4[250] = 0x14141414U;
Td4[251] = 0x63636363U;
Td4[252] = 0x55555555U;
Td4[253] = 0x21212121U;
Td4[254] = 0x0c0c0c0cU;
Td4[255] = 0x7d7d7d7dU;
Te0 = malloc(sizeof(uint32_t) * 256)
Te0[0] = 0xc66363a5U;
Te0[1] = 0xf87c7c84U;
Te0[2] = 0xee777799U;
Te0[3] = 0xf67b7b8dU;
Te0[4] = 0xfff2f20dU;
Te0[5] = 0xd66b6bbdU;
Te0[6] = 0xde6f6fb1U;
Te0[7] = 0x91c5c554U;
Te0[8] = 0x60303050U;
Te0[9] = 0x02010103U;
Te0[10] = 0xce6767a9U;
Te0[11] = 0x562b2b7dU;
Te0[12] = 0xe7fefe19U;
Te0[13] = 0xb5d7d762U;
Te0[14] = 0x4dababe6U;
Te0[15] = 0xec76769aU;
Te0[16] = 0x8fcaca45U;
Te0[17] = 0x1f82829dU;
Te0[18] = 0x89c9c940U;
Te0[19] = 0xfa7d7d87U;
Te0[20] = 0xeffafa15U;
Te0[21] = 0xb25959ebU;
Te0[22] = 0x8e4747c9U;
Te0[23] = 0xfbf0f00bU;
Te0[24] = 0x41adadecU;
Te0[25] = 0xb3d4d467U;
Te0[26] = 0x5fa2a2fdU;
Te0[27] = 0x45afafeaU;
Te0[28] = 0x239c9cbfU;
Te0[29] = 0x53a4a4f7U;
Te0[30] = 0xe4727296U;
Te0[31] = 0x9bc0c05bU;
Te0[32] = 0x75b7b7c2U;
Te0[33] = 0xe1fdfd1cU;
Te0[34] = 0x3d9393aeU;
Te0[35] = 0x4c26266aU;
Te0[36] = 0x6c36365aU;
Te0[37] = 0x7e3f3f41U;
Te0[38] = 0xf5f7f702U;
Te0[39] = 0x83cccc4fU;
Te0[40] = 0x6834345cU;
Te0[41] = 0x51a5a5f4U;
Te0[42] = 0xd1e5e534U;
Te0[43] = 0xf9f1f108U;
Te0[44] = 0xe2717193U;
Te0[45] = 0xabd8d873U;
Te0[46] = 0x62313153U;
Te0[47] = 0x2a15153fU;
Te0[48] = 0x0804040cU;
Te0[49] = 0x95c7c752U;
Te0[50] = 0x46232365U;
Te0[51] = 0x9dc3c35eU;
Te0[52] = 0x30181828U;
Te0[53] = 0x379696a1U;
Te0[54] = 0x0a05050fU;
Te0[55] = 0x2f9a9ab5U;
Te0[56] = 0x0e070709U;
Te0[57] = 0x24121236U;
Te0[58] = 0x1b80809bU;
Te0[59] = 0xdfe2e23dU;
Te0[60] = 0xcdebeb26U;
Te0[61] = 0x4e272769U;
Te0[62] = 0x7fb2b2cdU;
Te0[63] = 0xea75759fU;
Te0[64] = 0x1209091bU;
Te0[65] = 0x1d83839eU;
Te0[66] = 0x582c2c74U;
Te0[67] = 0x341a1a2eU;
Te0[68] = 0x361b1b2dU;
Te0[69] = 0xdc6e6eb2U;
Te0[70] = 0xb45a5aeeU;
Te0[71] = 0x5ba0a0fbU;
Te0[72] = 0xa45252f6U;
Te0[73] = 0x763b3b4dU;
Te0[74] = 0xb7d6d661U;
Te0[75] = 0x7db3b3ceU;
Te0[76] = 0x5229297bU;
Te0[77] = 0xdde3e33eU;
Te0[78] = 0x5e2f2f71U;
Te0[79] = 0x13848497U;
Te0[80] = 0xa65353f5U;
Te0[81] = 0xb9d1d168U;
Te0[82] = 0x00000000U;
Te0[83] = 0xc1eded2cU;
Te0[84] = 0x40202060U;
Te0[85] = 0xe3fcfc1fU;
Te0[86] = 0x79b1b1c8U;
Te0[87] = 0xb65b5bedU;
Te0[88] = 0xd46a6abeU;
Te0[89] = 0x8dcbcb46U;
Te0[90] = 0x67bebed9U;
Te0[91] = 0x7239394bU;
Te0[92] = 0x944a4adeU;
Te0[93] = 0x984c4cd4U;
Te0[94] = 0xb05858e8U;
Te0[95] = 0x85cfcf4aU;
Te0[96] = 0xbbd0d06bU;
Te0[97] = 0xc5efef2aU;
Te0[98] = 0x4faaaae5U;
Te0[99] = 0xedfbfb16U;
Te0[100] = 0x864343c5U;
Te0[101] = 0x9a4d4dd7U;
Te0[102] = 0x66333355U;
Te0[103] = 0x11858594U;
Te0[104] = 0x8a4545cfU;
Te0[105] = 0xe9f9f910U;
Te0[106] = 0x04020206U;
Te0[107] = 0xfe7f7f81U;
Te0[108] = 0xa05050f0U;
Te0[109] = 0x783c3c44U;
Te0[110] = 0x259f9fbaU;
Te0[111] = 0x4ba8a8e3U;
Te0[112] = 0xa25151f3U;
Te0[113] = 0x5da3a3feU;
Te0[114] = 0x804040c0U;
Te0[115] = 0x058f8f8aU;
Te0[116] = 0x3f9292adU;
Te0[117] = 0x219d9dbcU;
Te0[118] = 0x70383848U;
Te0[119] = 0xf1f5f504U;
Te0[120] = 0x63bcbcdfU;
Te0[121] = 0x77b6b6c1U;
Te0[122] = 0xafdada75U;
Te0[123] = 0x42212163U;
Te0[124] = 0x20101030U;
Te0[125] = 0xe5ffff1aU;
Te0[126] = 0xfdf3f30eU;
Te0[127] = 0xbfd2d26dU;
Te0[128] = 0x81cdcd4cU;
Te0[129] = 0x180c0c14U;
Te0[130] = 0x26131335U;
Te0[131] = 0xc3ecec2fU;
Te0[132] = 0xbe5f5fe1U;
Te0[133] = 0x359797a2U;
Te0[134] = 0x884444ccU;
Te0[135] = 0x2e171739U;
Te0[136] = 0x93c4c457U;
Te0[137] = 0x55a7a7f2U;
Te0[138] = 0xfc7e7e82U;
Te0[139] = 0x7a3d3d47U;
Te0[140] = 0xc86464acU;
Te0[141] = 0xba5d5de7U;
Te0[142] = 0x3219192bU;
Te0[143] = 0xe6737395U;
Te0[144] = 0xc06060a0U;
Te0[145] = 0x19818198U;
Te0[146] = 0x9e4f4fd1U;
Te0[147] = 0xa3dcdc7fU;
Te0[148] = 0x44222266U;
Te0[149] = 0x542a2a7eU;
Te0[150] = 0x3b9090abU;
Te0[151] = 0x0b888883U;
Te0[152] = 0x8c4646caU;
Te0[153] = 0xc7eeee29U;
Te0[154] = 0x6bb8b8d3U;
Te0[155] = 0x2814143cU;
Te0[156] = 0xa7dede79U;
Te0[157] = 0xbc5e5ee2U;
Te0[158] = 0x160b0b1dU;
Te0[159] = 0xaddbdb76U;
Te0[160] = 0xdbe0e03bU;
Te0[161] = 0x64323256U;
Te0[162] = 0x743a3a4eU;
Te0[163] = 0x140a0a1eU;
Te0[164] = 0x924949dbU;
Te0[165] = 0x0c06060aU;
Te0[166] = 0x4824246cU;
Te0[167] = 0xb85c5ce4U;
Te0[168] = 0x9fc2c25dU;
Te0[169] = 0xbdd3d36eU;
Te0[170] = 0x43acacefU;
Te0[171] = 0xc46262a6U;
Te0[172] = 0x399191a8U;
Te0[173] = 0x319595a4U;
Te0[174] = 0xd3e4e437U;
Te0[175] = 0xf279798bU;
Te0[176] = 0xd5e7e732U;
Te0[177] = 0x8bc8c843U;
Te0[178] = 0x6e373759U;
Te0[179] = 0xda6d6db7U;
Te0[180] = 0x018d8d8cU;
Te0[181] = 0xb1d5d564U;
Te0[182] = 0x9c4e4ed2U;
Te0[183] = 0x49a9a9e0U;
Te0[184] = 0xd86c6cb4U;
Te0[185] = 0xac5656faU;
Te0[186] = 0xf3f4f407U;
Te0[187] = 0xcfeaea25U;
Te0[188] = 0xca6565afU;
Te0[189] = 0xf47a7a8eU;
Te0[190] = 0x47aeaee9U;
Te0[191] = 0x10080818U;
Te0[192] = 0x6fbabad5U;
Te0[193] = 0xf0787888U;
Te0[194] = 0x4a25256fU;
Te0[195] = 0x5c2e2e72U;
Te0[196] = 0x381c1c24U;
Te0[197] = 0x57a6a6f1U;
Te0[198] = 0x73b4b4c7U;
Te0[199] = 0x97c6c651U;
Te0[200] = 0xcbe8e823U;
Te0[201] = 0xa1dddd7cU;
Te0[202] = 0xe874749cU;
Te0[203] = 0x3e1f1f21U;
Te0[204] = 0x964b4bddU;
Te0[205] = 0x61bdbddcU;
Te0[206] = 0x0d8b8b86U;
Te0[207] = 0x0f8a8a85U;
Te0[208] = 0xe0707090U;
Te0[209] = 0x7c3e3e42U;
Te0[210] = 0x71b5b5c4U;
Te0[211] = 0xcc6666aaU;
Te0[212] = 0x904848d8U;
Te0[213] = 0x06030305U;
Te0[214] = 0xf7f6f601U;
Te0[215] = 0x1c0e0e12U;
Te0[216] = 0xc26161a3U;
Te0[217] = 0x6a35355fU;
Te0[218] = 0xae5757f9U;
Te0[219] = 0x69b9b9d0U;
Te0[220] = 0x17868691U;
Te0[221] = 0x99c1c158U;
Te0[222] = 0x3a1d1d27U;
Te0[223] = 0x279e9eb9U;
Te0[224] = 0xd9e1e138U;
Te0[225] = 0xebf8f813U;
Te0[226] = 0x2b9898b3U;
Te0[227] = 0x22111133U;
Te0[228] = 0xd26969bbU;
Te0[229] = 0xa9d9d970U;
Te0[230] = 0x078e8e89U;
Te0[231] = 0x339494a7U;
Te0[232] = 0x2d9b9bb6U;
Te0[233] = 0x3c1e1e22U;
Te0[234] = 0x15878792U;
Te0[235] = 0xc9e9e920U;
Te0[236] = 0x87cece49U;
Te0[237] = 0xaa5555ffU;
Te0[238] = 0x50282878U;
Te0[239] = 0xa5dfdf7aU;
Te0[240] = 0x038c8c8fU;
Te0[241] = 0x59a1a1f8U;
Te0[242] = 0x09898980U;
Te0[243] = 0x1a0d0d17U;
Te0[244] = 0x65bfbfdaU;
Te0[245] = 0xd7e6e631U;
Te0[246] = 0x844242c6U;
Te0[247] = 0xd06868b8U;
Te0[248] = 0x824141c3U;
Te0[249] = 0x299999b0U;
Te0[250] = 0x5a2d2d77U;
Te0[251] = 0x1e0f0f11U;
Te0[252] = 0x7bb0b0cbU;
Te0[253] = 0xa85454fcU;
Te0[254] = 0x6dbbbbd6U;
Te0[255] = 0x2c16163aU;
Te1 = malloc(sizeof(uint32_t) * 256)
Te1[0] = 0xa5c66363U;
Te1[1] = 0x84f87c7cU;
Te1[2] = 0x99ee7777U;
Te1[3] = 0x8df67b7bU;
Te1[4] = 0x0dfff2f2U;
Te1[5] = 0xbdd66b6bU;
Te1[6] = 0xb1de6f6fU;
Te1[7] = 0x5491c5c5U;
Te1[8] = 0x50603030U;
Te1[9] = 0x03020101U;
Te1[10] = 0xa9ce6767U;
Te1[11] = 0x7d562b2bU;
Te1[12] = 0x19e7fefeU;
Te1[13] = 0x62b5d7d7U;
Te1[14] = 0xe64dababU;
Te1[15] = 0x9aec7676U;
Te1[16] = 0x458fcacaU;
Te1[17] = 0x9d1f8282U;
Te1[18] = 0x4089c9c9U;
Te1[19] = 0x87fa7d7dU;
Te1[20] = 0x15effafaU;
Te1[21] = 0xebb25959U;
Te1[22] = 0xc98e4747U;
Te1[23] = 0x0bfbf0f0U;
Te1[24] = 0xec41adadU;
Te1[25] = 0x67b3d4d4U;
Te1[26] = 0xfd5fa2a2U;
Te1[27] = 0xea45afafU;
Te1[28] = 0xbf239c9cU;
Te1[29] = 0xf753a4a4U;
Te1[30] = 0x96e47272U;
Te1[31] = 0x5b9bc0c0U;
Te1[32] = 0xc275b7b7U;
Te1[33] = 0x1ce1fdfdU;
Te1[34] = 0xae3d9393U;
Te1[35] = 0x6a4c2626U;
Te1[36] = 0x5a6c3636U;
Te1[37] = 0x417e3f3fU;
Te1[38] = 0x02f5f7f7U;
Te1[39] = 0x4f83ccccU;
Te1[40] = 0x5c683434U;
Te1[41] = 0xf451a5a5U;
Te1[42] = 0x34d1e5e5U;
Te1[43] = 0x08f9f1f1U;
Te1[44] = 0x93e27171U;
Te1[45] = 0x73abd8d8U;
Te1[46] = 0x53623131U;
Te1[47] = 0x3f2a1515U;
Te1[48] = 0x0c080404U;
Te1[49] = 0x5295c7c7U;
Te1[50] = 0x65462323U;
Te1[51] = 0x5e9dc3c3U;
Te1[52] = 0x28301818U;
Te1[53] = 0xa1379696U;
Te1[54] = 0x0f0a0505U;
Te1[55] = 0xb52f9a9aU;
Te1[56] = 0x090e0707U;
Te1[57] = 0x36241212U;
Te1[58] = 0x9b1b8080U;
Te1[59] = 0x3ddfe2e2U;
Te1[60] = 0x26cdebebU;
Te1[61] = 0x694e2727U;
Te1[62] = 0xcd7fb2b2U;
Te1[63] = 0x9fea7575U;
Te1[64] = 0x1b120909U;
Te1[65] = 0x9e1d8383U;
Te1[66] = 0x74582c2cU;
Te1[67] = 0x2e341a1aU;
Te1[68] = 0x2d361b1bU;
Te1[69] = 0xb2dc6e6eU;
Te1[70] = 0xeeb45a5aU;
Te1[71] = 0xfb5ba0a0U;
Te1[72] = 0xf6a45252U;
Te1[73] = 0x4d763b3bU;
Te1[74] = 0x61b7d6d6U;
Te1[75] = 0xce7db3b3U;
Te1[76] = 0x7b522929U;
Te1[77] = 0x3edde3e3U;
Te1[78] = 0x715e2f2fU;
Te1[79] = 0x97138484U;
Te1[80] = 0xf5a65353U;
Te1[81] = 0x68b9d1d1U;
Te1[82] = 0x00000000U;
Te1[83] = 0x2cc1ededU;
Te1[84] = 0x60402020U;
Te1[85] = 0x1fe3fcfcU;
Te1[86] = 0xc879b1b1U;
Te1[87] = 0xedb65b5bU;
Te1[88] = 0xbed46a6aU;
Te1[89] = 0x468dcbcbU;
Te1[90] = 0xd967bebeU;
Te1[91] = 0x4b723939U;
Te1[92] = 0xde944a4aU;
Te1[93] = 0xd4984c4cU;
Te1[94] = 0xe8b05858U;
Te1[95] = 0x4a85cfcfU;
Te1[96] = 0x6bbbd0d0U;
Te1[97] = 0x2ac5efefU;
Te1[98] = 0xe54faaaaU;
Te1[99] = 0x16edfbfbU;
Te1[100] = 0xc5864343U;
Te1[101] = 0xd79a4d4dU;
Te1[102] = 0x55663333U;
Te1[103] = 0x94118585U;
Te1[104] = 0xcf8a4545U;
Te1[105] = 0x10e9f9f9U;
Te1[106] = 0x06040202U;
Te1[107] = 0x81fe7f7fU;
Te1[108] = 0xf0a05050U;
Te1[109] = 0x44783c3cU;
Te1[110] = 0xba259f9fU;
Te1[111] = 0xe34ba8a8U;
Te1[112] = 0xf3a25151U;
Te1[113] = 0xfe5da3a3U;
Te1[114] = 0xc0804040U;
Te1[115] = 0x8a058f8fU;
Te1[116] = 0xad3f9292U;
Te1[117] = 0xbc219d9dU;
Te1[118] = 0x48703838U;
Te1[119] = 0x04f1f5f5U;
Te1[120] = 0xdf63bcbcU;
Te1[121] = 0xc177b6b6U;
Te1[122] = 0x75afdadaU;
Te1[123] = 0x63422121U;
Te1[124] = 0x30201010U;
Te1[125] = 0x1ae5ffffU;
Te1[126] = 0x0efdf3f3U;
Te1[127] = 0x6dbfd2d2U;
Te1[128] = 0x4c81cdcdU;
Te1[129] = 0x14180c0cU;
Te1[130] = 0x35261313U;
Te1[131] = 0x2fc3ececU;
Te1[132] = 0xe1be5f5fU;
Te1[133] = 0xa2359797U;
Te1[134] = 0xcc884444U;
Te1[135] = 0x392e1717U;
Te1[136] = 0x5793c4c4U;
Te1[137] = 0xf255a7a7U;
Te1[138] = 0x82fc7e7eU;
Te1[139] = 0x477a3d3dU;
Te1[140] = 0xacc86464U;
Te1[141] = 0xe7ba5d5dU;
Te1[142] = 0x2b321919U;
Te1[143] = 0x95e67373U;
Te1[144] = 0xa0c06060U;
Te1[145] = 0x98198181U;
Te1[146] = 0xd19e4f4fU;
Te1[147] = 0x7fa3dcdcU;
Te1[148] = 0x66442222U;
Te1[149] = 0x7e542a2aU;
Te1[150] = 0xab3b9090U;
Te1[151] = 0x830b8888U;
Te1[152] = 0xca8c4646U;
Te1[153] = 0x29c7eeeeU;
Te1[154] = 0xd36bb8b8U;
Te1[155] = 0x3c281414U;
Te1[156] = 0x79a7dedeU;
Te1[157] = 0xe2bc5e5eU;
Te1[158] = 0x1d160b0bU;
Te1[159] = 0x76addbdbU;
Te1[160] = 0x3bdbe0e0U;
Te1[161] = 0x56643232U;
Te1[162] = 0x4e743a3aU;
Te1[163] = 0x1e140a0aU;
Te1[164] = 0xdb924949U;
Te1[165] = 0x0a0c0606U;
Te1[166] = 0x6c482424U;
Te1[167] = 0xe4b85c5cU;
Te1[168] = 0x5d9fc2c2U;
Te1[169] = 0x6ebdd3d3U;
Te1[170] = 0xef43acacU;
Te1[171] = 0xa6c46262U;
Te1[172] = 0xa8399191U;
Te1[173] = 0xa4319595U;
Te1[174] = 0x37d3e4e4U;
Te1[175] = 0x8bf27979U;
Te1[176] = 0x32d5e7e7U;
Te1[177] = 0x438bc8c8U;
Te1[178] = 0x596e3737U;
Te1[179] = 0xb7da6d6dU;
Te1[180] = 0x8c018d8dU;
Te1[181] = 0x64b1d5d5U;
Te1[182] = 0xd29c4e4eU;
Te1[183] = 0xe049a9a9U;
Te1[184] = 0xb4d86c6cU;
Te1[185] = 0xfaac5656U;
Te1[186] = 0x07f3f4f4U;
Te1[187] = 0x25cfeaeaU;
Te1[188] = 0xafca6565U;
Te1[189] = 0x8ef47a7aU;
Te1[190] = 0xe947aeaeU;
Te1[191] = 0x18100808U;
Te1[192] = 0xd56fbabaU;
Te1[193] = 0x88f07878U;
Te1[194] = 0x6f4a2525U;
Te1[195] = 0x725c2e2eU;
Te1[196] = 0x24381c1cU;
Te1[197] = 0xf157a6a6U;
Te1[198] = 0xc773b4b4U;
Te1[199] = 0x5197c6c6U;
Te1[200] = 0x23cbe8e8U;
Te1[201] = 0x7ca1ddddU;
Te1[202] = 0x9ce87474U;
Te1[203] = 0x213e1f1fU;
Te1[204] = 0xdd964b4bU;
Te1[205] = 0xdc61bdbdU;
Te1[206] = 0x860d8b8bU;
Te1[207] = 0x850f8a8aU;
Te1[208] = 0x90e07070U;
Te1[209] = 0x427c3e3eU;
Te1[210] = 0xc471b5b5U;
Te1[211] = 0xaacc6666U;
Te1[212] = 0xd8904848U;
Te1[213] = 0x05060303U;
Te1[214] = 0x01f7f6f6U;
Te1[215] = 0x121c0e0eU;
Te1[216] = 0xa3c26161U;
Te1[217] = 0x5f6a3535U;
Te1[218] = 0xf9ae5757U;
Te1[219] = 0xd069b9b9U;
Te1[220] = 0x91178686U;
Te1[221] = 0x5899c1c1U;
Te1[222] = 0x273a1d1dU;
Te1[223] = 0xb9279e9eU;
Te1[224] = 0x38d9e1e1U;
Te1[225] = 0x13ebf8f8U;
Te1[226] = 0xb32b9898U;
Te1[227] = 0x33221111U;
Te1[228] = 0xbbd26969U;
Te1[229] = 0x70a9d9d9U;
Te1[230] = 0x89078e8eU;
Te1[231] = 0xa7339494U;
Te1[232] = 0xb62d9b9bU;
Te1[233] = 0x223c1e1eU;
Te1[234] = 0x92158787U;
Te1[235] = 0x20c9e9e9U;
Te1[236] = 0x4987ceceU;
Te1[237] = 0xffaa5555U;
Te1[238] = 0x78502828U;
Te1[239] = 0x7aa5dfdfU;
Te1[240] = 0x8f038c8cU;
Te1[241] = 0xf859a1a1U;
Te1[242] = 0x80098989U;
Te1[243] = 0x171a0d0dU;
Te1[244] = 0xda65bfbfU;
Te1[245] = 0x31d7e6e6U;
Te1[246] = 0xc6844242U;
Te1[247] = 0xb8d06868U;
Te1[248] = 0xc3824141U;
Te1[249] = 0xb0299999U;
Te1[250] = 0x775a2d2dU;
Te1[251] = 0x111e0f0fU;
Te1[252] = 0xcb7bb0b0U;
Te1[253] = 0xfca85454U;
Te1[254] = 0xd66dbbbbU;
Te1[255] = 0x3a2c1616U;
Te2 = malloc(sizeof(uint32_t) * 256)
Te2[0] = 0x63a5c663U;
Te2[1] = 0x7c84f87cU;
Te2[2] = 0x7799ee77U;
Te2[3] = 0x7b8df67bU;
Te2[4] = 0xf20dfff2U;
Te2[5] = 0x6bbdd66bU;
Te2[6] = 0x6fb1de6fU;
Te2[7] = 0xc55491c5U;
Te2[8] = 0x30506030U;
Te2[9] = 0x01030201U;
Te2[10] = 0x67a9ce67U;
Te2[11] = 0x2b7d562bU;
Te2[12] = 0xfe19e7feU;
Te2[13] = 0xd762b5d7U;
Te2[14] = 0xabe64dabU;
Te2[15] = 0x769aec76U;
Te2[16] = 0xca458fcaU;
Te2[17] = 0x829d1f82U;
Te2[18] = 0xc94089c9U;
Te2[19] = 0x7d87fa7dU;
Te2[20] = 0xfa15effaU;
Te2[21] = 0x59ebb259U;
Te2[22] = 0x47c98e47U;
Te2[23] = 0xf00bfbf0U;
Te2[24] = 0xadec41adU;
Te2[25] = 0xd467b3d4U;
Te2[26] = 0xa2fd5fa2U;
Te2[27] = 0xafea45afU;
Te2[28] = 0x9cbf239cU;
Te2[29] = 0xa4f753a4U;
Te2[30] = 0x7296e472U;
Te2[31] = 0xc05b9bc0U;
Te2[32] = 0xb7c275b7U;
Te2[33] = 0xfd1ce1fdU;
Te2[34] = 0x93ae3d93U;
Te2[35] = 0x266a4c26U;
Te2[36] = 0x365a6c36U;
Te2[37] = 0x3f417e3fU;
Te2[38] = 0xf702f5f7U;
Te2[39] = 0xcc4f83ccU;
Te2[40] = 0x345c6834U;
Te2[41] = 0xa5f451a5U;
Te2[42] = 0xe534d1e5U;
Te2[43] = 0xf108f9f1U;
Te2[44] = 0x7193e271U;
Te2[45] = 0xd873abd8U;
Te2[46] = 0x31536231U;
Te2[47] = 0x153f2a15U;
Te2[48] = 0x040c0804U;
Te2[49] = 0xc75295c7U;
Te2[50] = 0x23654623U;
Te2[51] = 0xc35e9dc3U;
Te2[52] = 0x18283018U;
Te2[53] = 0x96a13796U;
Te2[54] = 0x050f0a05U;
Te2[55] = 0x9ab52f9aU;
Te2[56] = 0x07090e07U;
Te2[57] = 0x12362412U;
Te2[58] = 0x809b1b80U;
Te2[59] = 0xe23ddfe2U;
Te2[60] = 0xeb26cdebU;
Te2[61] = 0x27694e27U;
Te2[62] = 0xb2cd7fb2U;
Te2[63] = 0x759fea75U;
Te2[64] = 0x091b1209U;
Te2[65] = 0x839e1d83U;
Te2[66] = 0x2c74582cU;
Te2[67] = 0x1a2e341aU;
Te2[68] = 0x1b2d361bU;
Te2[69] = 0x6eb2dc6eU;
Te2[70] = 0x5aeeb45aU;
Te2[71] = 0xa0fb5ba0U;
Te2[72] = 0x52f6a452U;
Te2[73] = 0x3b4d763bU;
Te2[74] = 0xd661b7d6U;
Te2[75] = 0xb3ce7db3U;
Te2[76] = 0x297b5229U;
Te2[77] = 0xe33edde3U;
Te2[78] = 0x2f715e2fU;
Te2[79] = 0x84971384U;
Te2[80] = 0x53f5a653U;
Te2[81] = 0xd168b9d1U;
Te2[82] = 0x00000000U;
Te2[83] = 0xed2cc1edU;
Te2[84] = 0x20604020U;
Te2[85] = 0xfc1fe3fcU;
Te2[86] = 0xb1c879b1U;
Te2[87] = 0x5bedb65bU;
Te2[88] = 0x6abed46aU;
Te2[89] = 0xcb468dcbU;
Te2[90] = 0xbed967beU;
Te2[91] = 0x394b7239U;
Te2[92] = 0x4ade944aU;
Te2[93] = 0x4cd4984cU;
Te2[94] = 0x58e8b058U;
Te2[95] = 0xcf4a85cfU;
Te2[96] = 0xd06bbbd0U;
Te2[97] = 0xef2ac5efU;
Te2[98] = 0xaae54faaU;
Te2[99] = 0xfb16edfbU;
Te2[100] = 0x43c58643U;
Te2[101] = 0x4dd79a4dU;
Te2[102] = 0x33556633U;
Te2[103] = 0x85941185U;
Te2[104] = 0x45cf8a45U;
Te2[105] = 0xf910e9f9U;
Te2[106] = 0x02060402U;
Te2[107] = 0x7f81fe7fU;
Te2[108] = 0x50f0a050U;
Te2[109] = 0x3c44783cU;
Te2[110] = 0x9fba259fU;
Te2[111] = 0xa8e34ba8U;
Te2[112] = 0x51f3a251U;
Te2[113] = 0xa3fe5da3U;
Te2[114] = 0x40c08040U;
Te2[115] = 0x8f8a058fU;
Te2[116] = 0x92ad3f92U;
Te2[117] = 0x9dbc219dU;
Te2[118] = 0x38487038U;
Te2[119] = 0xf504f1f5U;
Te2[120] = 0xbcdf63bcU;
Te2[121] = 0xb6c177b6U;
Te2[122] = 0xda75afdaU;
Te2[123] = 0x21634221U;
Te2[124] = 0x10302010U;
Te2[125] = 0xff1ae5ffU;
Te2[126] = 0xf30efdf3U;
Te2[127] = 0xd26dbfd2U;
Te2[128] = 0xcd4c81cdU;
Te2[129] = 0x0c14180cU;
Te2[130] = 0x13352613U;
Te2[131] = 0xec2fc3ecU;
Te2[132] = 0x5fe1be5fU;
Te2[133] = 0x97a23597U;
Te2[134] = 0x44cc8844U;
Te2[135] = 0x17392e17U;
Te2[136] = 0xc45793c4U;
Te2[137] = 0xa7f255a7U;
Te2[138] = 0x7e82fc7eU;
Te2[139] = 0x3d477a3dU;
Te2[140] = 0x64acc864U;
Te2[141] = 0x5de7ba5dU;
Te2[142] = 0x192b3219U;
Te2[143] = 0x7395e673U;
Te2[144] = 0x60a0c060U;
Te2[145] = 0x81981981U;
Te2[146] = 0x4fd19e4fU;
Te2[147] = 0xdc7fa3dcU;
Te2[148] = 0x22664422U;
Te2[149] = 0x2a7e542aU;
Te2[150] = 0x90ab3b90U;
Te2[151] = 0x88830b88U;
Te2[152] = 0x46ca8c46U;
Te2[153] = 0xee29c7eeU;
Te2[154] = 0xb8d36bb8U;
Te2[155] = 0x143c2814U;
Te2[156] = 0xde79a7deU;
Te2[157] = 0x5ee2bc5eU;
Te2[158] = 0x0b1d160bU;
Te2[159] = 0xdb76addbU;
Te2[160] = 0xe03bdbe0U;
Te2[161] = 0x32566432U;
Te2[162] = 0x3a4e743aU;
Te2[163] = 0x0a1e140aU;
Te2[164] = 0x49db9249U;
Te2[165] = 0x060a0c06U;
Te2[166] = 0x246c4824U;
Te2[167] = 0x5ce4b85cU;
Te2[168] = 0xc25d9fc2U;
Te2[169] = 0xd36ebdd3U;
Te2[170] = 0xacef43acU;
Te2[171] = 0x62a6c462U;
Te2[172] = 0x91a83991U;
Te2[173] = 0x95a43195U;
Te2[174] = 0xe437d3e4U;
Te2[175] = 0x798bf279U;
Te2[176] = 0xe732d5e7U;
Te2[177] = 0xc8438bc8U;
Te2[178] = 0x37596e37U;
Te2[179] = 0x6db7da6dU;
Te2[180] = 0x8d8c018dU;
Te2[181] = 0xd564b1d5U;
Te2[182] = 0x4ed29c4eU;
Te2[183] = 0xa9e049a9U;
Te2[184] = 0x6cb4d86cU;
Te2[185] = 0x56faac56U;
Te2[186] = 0xf407f3f4U;
Te2[187] = 0xea25cfeaU;
Te2[188] = 0x65afca65U;
Te2[189] = 0x7a8ef47aU;
Te2[190] = 0xaee947aeU;
Te2[191] = 0x08181008U;
Te2[192] = 0xbad56fbaU;
Te2[193] = 0x7888f078U;
Te2[194] = 0x256f4a25U;
Te2[195] = 0x2e725c2eU;
Te2[196] = 0x1c24381cU;
Te2[197] = 0xa6f157a6U;
Te2[198] = 0xb4c773b4U;
Te2[199] = 0xc65197c6U;
Te2[200] = 0xe823cbe8U;
Te2[201] = 0xdd7ca1ddU;
Te2[202] = 0x749ce874U;
Te2[203] = 0x1f213e1fU;
Te2[204] = 0x4bdd964bU;
Te2[205] = 0xbddc61bdU;
Te2[206] = 0x8b860d8bU;
Te2[207] = 0x8a850f8aU;
Te2[208] = 0x7090e070U;
Te2[209] = 0x3e427c3eU;
Te2[210] = 0xb5c471b5U;
Te2[211] = 0x66aacc66U;
Te2[212] = 0x48d89048U;
Te2[213] = 0x03050603U;
Te2[214] = 0xf601f7f6U;
Te2[215] = 0x0e121c0eU;
Te2[216] = 0x61a3c261U;
Te2[217] = 0x355f6a35U;
Te2[218] = 0x57f9ae57U;
Te2[219] = 0xb9d069b9U;
Te2[220] = 0x86911786U;
Te2[221] = 0xc15899c1U;
Te2[222] = 0x1d273a1dU;
Te2[223] = 0x9eb9279eU;
Te2[224] = 0xe138d9e1U;
Te2[225] = 0xf813ebf8U;
Te2[226] = 0x98b32b98U;
Te2[227] = 0x11332211U;
Te2[228] = 0x69bbd269U;
Te2[229] = 0xd970a9d9U;
Te2[230] = 0x8e89078eU;
Te2[231] = 0x94a73394U;
Te2[232] = 0x9bb62d9bU;
Te2[233] = 0x1e223c1eU;
Te2[234] = 0x87921587U;
Te2[235] = 0xe920c9e9U;
Te2[236] = 0xce4987ceU;
Te2[237] = 0x55ffaa55U;
Te2[238] = 0x28785028U;
Te2[239] = 0xdf7aa5dfU;
Te2[240] = 0x8c8f038cU;
Te2[241] = 0xa1f859a1U;
Te2[242] = 0x89800989U;
Te2[243] = 0x0d171a0dU;
Te2[244] = 0xbfda65bfU;
Te2[245] = 0xe631d7e6U;
Te2[246] = 0x42c68442U;
Te2[247] = 0x68b8d068U;
Te2[248] = 0x41c38241U;
Te2[249] = 0x99b02999U;
Te2[250] = 0x2d775a2dU;
Te2[251] = 0x0f111e0fU;
Te2[252] = 0xb0cb7bb0U;
Te2[253] = 0x54fca854U;
Te2[254] = 0xbbd66dbbU;
Te2[255] = 0x163a2c16U;
Te3 = malloc(sizeof(uint32_t) * 256)
Te3[0] = 0x6363a5c6U;
Te3[1] = 0x7c7c84f8U;
Te3[2] = 0x777799eeU;
Te3[3] = 0x7b7b8df6U;
Te3[4] = 0xf2f20dffU;
Te3[5] = 0x6b6bbdd6U;
Te3[6] = 0x6f6fb1deU;
Te3[7] = 0xc5c55491U;
Te3[8] = 0x30305060U;
Te3[9] = 0x01010302U;
Te3[10] = 0x6767a9ceU;
Te3[11] = 0x2b2b7d56U;
Te3[12] = 0xfefe19e7U;
Te3[13] = 0xd7d762b5U;
Te3[14] = 0xababe64dU;
Te3[15] = 0x76769aecU;
Te3[16] = 0xcaca458fU;
Te3[17] = 0x82829d1fU;
Te3[18] = 0xc9c94089U;
Te3[19] = 0x7d7d87faU;
Te3[20] = 0xfafa15efU;
Te3[21] = 0x5959ebb2U;
Te3[22] = 0x4747c98eU;
Te3[23] = 0xf0f00bfbU;
Te3[24] = 0xadadec41U;
Te3[25] = 0xd4d467b3U;
Te3[26] = 0xa2a2fd5fU;
Te3[27] = 0xafafea45U;
Te3[28] = 0x9c9cbf23U;
Te3[29] = 0xa4a4f753U;
Te3[30] = 0x727296e4U;
Te3[31] = 0xc0c05b9bU;
Te3[32] = 0xb7b7c275U;
Te3[33] = 0xfdfd1ce1U;
Te3[34] = 0x9393ae3dU;
Te3[35] = 0x26266a4cU;
Te3[36] = 0x36365a6cU;
Te3[37] = 0x3f3f417eU;
Te3[38] = 0xf7f702f5U;
Te3[39] = 0xcccc4f83U;
Te3[40] = 0x34345c68U;
Te3[41] = 0xa5a5f451U;
Te3[42] = 0xe5e534d1U;
Te3[43] = 0xf1f108f9U;
Te3[44] = 0x717193e2U;
Te3[45] = 0xd8d873abU;
Te3[46] = 0x31315362U;
Te3[47] = 0x15153f2aU;
Te3[48] = 0x04040c08U;
Te3[49] = 0xc7c75295U;
Te3[50] = 0x23236546U;
Te3[51] = 0xc3c35e9dU;
Te3[52] = 0x18182830U;
Te3[53] = 0x9696a137U;
Te3[54] = 0x05050f0aU;
Te3[55] = 0x9a9ab52fU;
Te3[56] = 0x0707090eU;
Te3[57] = 0x12123624U;
Te3[58] = 0x80809b1bU;
Te3[59] = 0xe2e23ddfU;
Te3[60] = 0xebeb26cdU;
Te3[61] = 0x2727694eU;
Te3[62] = 0xb2b2cd7fU;
Te3[63] = 0x75759feaU;
Te3[64] = 0x09091b12U;
Te3[65] = 0x83839e1dU;
Te3[66] = 0x2c2c7458U;
Te3[67] = 0x1a1a2e34U;
Te3[68] = 0x1b1b2d36U;
Te3[69] = 0x6e6eb2dcU;
Te3[70] = 0x5a5aeeb4U;
Te3[71] = 0xa0a0fb5bU;
Te3[72] = 0x5252f6a4U;
Te3[73] = 0x3b3b4d76U;
Te3[74] = 0xd6d661b7U;
Te3[75] = 0xb3b3ce7dU;
Te3[76] = 0x29297b52U;
Te3[77] = 0xe3e33eddU;
Te3[78] = 0x2f2f715eU;
Te3[79] = 0x84849713U;
Te3[80] = 0x5353f5a6U;
Te3[81] = 0xd1d168b9U;
Te3[82] = 0x00000000U;
Te3[83] = 0xeded2cc1U;
Te3[84] = 0x20206040U;
Te3[85] = 0xfcfc1fe3U;
Te3[86] = 0xb1b1c879U;
Te3[87] = 0x5b5bedb6U;
Te3[88] = 0x6a6abed4U;
Te3[89] = 0xcbcb468dU;
Te3[90] = 0xbebed967U;
Te3[91] = 0x39394b72U;
Te3[92] = 0x4a4ade94U;
Te3[93] = 0x4c4cd498U;
Te3[94] = 0x5858e8b0U;
Te3[95] = 0xcfcf4a85U;
Te3[96] = 0xd0d06bbbU;
Te3[97] = 0xefef2ac5U;
Te3[98] = 0xaaaae54fU;
Te3[99] = 0xfbfb16edU;
Te3[100] = 0x4343c586U;
Te3[101] = 0x4d4dd79aU;
Te3[102] = 0x33335566U;
Te3[103] = 0x85859411U;
Te3[104] = 0x4545cf8aU;
Te3[105] = 0xf9f910e9U;
Te3[106] = 0x02020604U;
Te3[107] = 0x7f7f81feU;
Te3[108] = 0x5050f0a0U;
Te3[109] = 0x3c3c4478U;
Te3[110] = 0x9f9fba25U;
Te3[111] = 0xa8a8e34bU;
Te3[112] = 0x5151f3a2U;
Te3[113] = 0xa3a3fe5dU;
Te3[114] = 0x4040c080U;
Te3[115] = 0x8f8f8a05U;
Te3[116] = 0x9292ad3fU;
Te3[117] = 0x9d9dbc21U;
Te3[118] = 0x38384870U;
Te3[119] = 0xf5f504f1U;
Te3[120] = 0xbcbcdf63U;
Te3[121] = 0xb6b6c177U;
Te3[122] = 0xdada75afU;
Te3[123] = 0x21216342U;
Te3[124] = 0x10103020U;
Te3[125] = 0xffff1ae5U;
Te3[126] = 0xf3f30efdU;
Te3[127] = 0xd2d26dbfU;
Te3[128] = 0xcdcd4c81U;
Te3[129] = 0x0c0c1418U;
Te3[130] = 0x13133526U;
Te3[131] = 0xecec2fc3U;
Te3[132] = 0x5f5fe1beU;
Te3[133] = 0x9797a235U;
Te3[134] = 0x4444cc88U;
Te3[135] = 0x1717392eU;
Te3[136] = 0xc4c45793U;
Te3[137] = 0xa7a7f255U;
Te3[138] = 0x7e7e82fcU;
Te3[139] = 0x3d3d477aU;
Te3[140] = 0x6464acc8U;
Te3[141] = 0x5d5de7baU;
Te3[142] = 0x19192b32U;
Te3[143] = 0x737395e6U;
Te3[144] = 0x6060a0c0U;
Te3[145] = 0x81819819U;
Te3[146] = 0x4f4fd19eU;
Te3[147] = 0xdcdc7fa3U;
Te3[148] = 0x22226644U;
Te3[149] = 0x2a2a7e54U;
Te3[150] = 0x9090ab3bU;
Te3[151] = 0x8888830bU;
Te3[152] = 0x4646ca8cU;
Te3[153] = 0xeeee29c7U;
Te3[154] = 0xb8b8d36bU;
Te3[155] = 0x14143c28U;
Te3[156] = 0xdede79a7U;
Te3[157] = 0x5e5ee2bcU;
Te3[158] = 0x0b0b1d16U;
Te3[159] = 0xdbdb76adU;
Te3[160] = 0xe0e03bdbU;
Te3[161] = 0x32325664U;
Te3[162] = 0x3a3a4e74U;
Te3[163] = 0x0a0a1e14U;
Te3[164] = 0x4949db92U;
Te3[165] = 0x06060a0cU;
Te3[166] = 0x24246c48U;
Te3[167] = 0x5c5ce4b8U;
Te3[168] = 0xc2c25d9fU;
Te3[169] = 0xd3d36ebdU;
Te3[170] = 0xacacef43U;
Te3[171] = 0x6262a6c4U;
Te3[172] = 0x9191a839U;
Te3[173] = 0x9595a431U;
Te3[174] = 0xe4e437d3U;
Te3[175] = 0x79798bf2U;
Te3[176] = 0xe7e732d5U;
Te3[177] = 0xc8c8438bU;
Te3[178] = 0x3737596eU;
Te3[179] = 0x6d6db7daU;
Te3[180] = 0x8d8d8c01U;
Te3[181] = 0xd5d564b1U;
Te3[182] = 0x4e4ed29cU;
Te3[183] = 0xa9a9e049U;
Te3[184] = 0x6c6cb4d8U;
Te3[185] = 0x5656faacU;
Te3[186] = 0xf4f407f3U;
Te3[187] = 0xeaea25cfU;
Te3[188] = 0x6565afcaU;
Te3[189] = 0x7a7a8ef4U;
Te3[190] = 0xaeaee947U;
Te3[191] = 0x08081810U;
Te3[192] = 0xbabad56fU;
Te3[193] = 0x787888f0U;
Te3[194] = 0x25256f4aU;
Te3[195] = 0x2e2e725cU;
Te3[196] = 0x1c1c2438U;
Te3[197] = 0xa6a6f157U;
Te3[198] = 0xb4b4c773U;
Te3[199] = 0xc6c65197U;
Te3[200] = 0xe8e823cbU;
Te3[201] = 0xdddd7ca1U;
Te3[202] = 0x74749ce8U;
Te3[203] = 0x1f1f213eU;
Te3[204] = 0x4b4bdd96U;
Te3[205] = 0xbdbddc61U;
Te3[206] = 0x8b8b860dU;
Te3[207] = 0x8a8a850fU;
Te3[208] = 0x707090e0U;
Te3[209] = 0x3e3e427cU;
Te3[210] = 0xb5b5c471U;
Te3[211] = 0x6666aaccU;
Te3[212] = 0x4848d890U;
Te3[213] = 0x03030506U;
Te3[214] = 0xf6f601f7U;
Te3[215] = 0x0e0e121cU;
Te3[216] = 0x6161a3c2U;
Te3[217] = 0x35355f6aU;
Te3[218] = 0x5757f9aeU;
Te3[219] = 0xb9b9d069U;
Te3[220] = 0x86869117U;
Te3[221] = 0xc1c15899U;
Te3[222] = 0x1d1d273aU;
Te3[223] = 0x9e9eb927U;
Te3[224] = 0xe1e138d9U;
Te3[225] = 0xf8f813ebU;
Te3[226] = 0x9898b32bU;
Te3[227] = 0x11113322U;
Te3[228] = 0x6969bbd2U;
Te3[229] = 0xd9d970a9U;
Te3[230] = 0x8e8e8907U;
Te3[231] = 0x9494a733U;
Te3[232] = 0x9b9bb62dU;
Te3[233] = 0x1e1e223cU;
Te3[234] = 0x87879215U;
Te3[235] = 0xe9e920c9U;
Te3[236] = 0xcece4987U;
Te3[237] = 0x5555ffaaU;
Te3[238] = 0x28287850U;
Te3[239] = 0xdfdf7aa5U;
Te3[240] = 0x8c8c8f03U;
Te3[241] = 0xa1a1f859U;
Te3[242] = 0x89898009U;
Te3[243] = 0x0d0d171aU;
Te3[244] = 0xbfbfda65U;
Te3[245] = 0xe6e631d7U;
Te3[246] = 0x4242c684U;
Te3[247] = 0x6868b8d0U;
Te3[248] = 0x4141c382U;
Te3[249] = 0x9999b029U;
Te3[250] = 0x2d2d775aU;
Te3[251] = 0x0f0f111eU;
Te3[252] = 0xb0b0cb7bU;
Te3[253] = 0x5454fca8U;
Te3[254] = 0xbbbbd66dU;
Te3[255] = 0x16163a2cU;
Te4 = malloc(sizeof(uint32_t) * 256)
Te4[0] = 0x63636363U;
Te4[1] = 0x7c7c7c7cU;
Te4[2] = 0x77777777U;
Te4[3] = 0x7b7b7b7bU;
Te4[4] = 0xf2f2f2f2U;
Te4[5] = 0x6b6b6b6bU;
Te4[6] = 0x6f6f6f6fU;
Te4[7] = 0xc5c5c5c5U;
Te4[8] = 0x30303030U;
Te4[9] = 0x01010101U;
Te4[10] = 0x67676767U;
Te4[11] = 0x2b2b2b2bU;
Te4[12] = 0xfefefefeU;
Te4[13] = 0xd7d7d7d7U;
Te4[14] = 0xababababU;
Te4[15] = 0x76767676U;
Te4[16] = 0xcacacacaU;
Te4[17] = 0x82828282U;
Te4[18] = 0xc9c9c9c9U;
Te4[19] = 0x7d7d7d7dU;
Te4[20] = 0xfafafafaU;
Te4[21] = 0x59595959U;
Te4[22] = 0x47474747U;
Te4[23] = 0xf0f0f0f0U;
Te4[24] = 0xadadadadU;
Te4[25] = 0xd4d4d4d4U;
Te4[26] = 0xa2a2a2a2U;
Te4[27] = 0xafafafafU;
Te4[28] = 0x9c9c9c9cU;
Te4[29] = 0xa4a4a4a4U;
Te4[30] = 0x72727272U;
Te4[31] = 0xc0c0c0c0U;
Te4[32] = 0xb7b7b7b7U;
Te4[33] = 0xfdfdfdfdU;
Te4[34] = 0x93939393U;
Te4[35] = 0x26262626U;
Te4[36] = 0x36363636U;
Te4[37] = 0x3f3f3f3fU;
Te4[38] = 0xf7f7f7f7U;
Te4[39] = 0xccccccccU;
Te4[40] = 0x34343434U;
Te4[41] = 0xa5a5a5a5U;
Te4[42] = 0xe5e5e5e5U;
Te4[43] = 0xf1f1f1f1U;
Te4[44] = 0x71717171U;
Te4[45] = 0xd8d8d8d8U;
Te4[46] = 0x31313131U;
Te4[47] = 0x15151515U;
Te4[48] = 0x04040404U;
Te4[49] = 0xc7c7c7c7U;
Te4[50] = 0x23232323U;
Te4[51] = 0xc3c3c3c3U;
Te4[52] = 0x18181818U;
Te4[53] = 0x96969696U;
Te4[54] = 0x05050505U;
Te4[55] = 0x9a9a9a9aU;
Te4[56] = 0x07070707U;
Te4[57] = 0x12121212U;
Te4[58] = 0x80808080U;
Te4[59] = 0xe2e2e2e2U;
Te4[60] = 0xebebebebU;
Te4[61] = 0x27272727U;
Te4[62] = 0xb2b2b2b2U;
Te4[63] = 0x75757575U;
Te4[64] = 0x09090909U;
Te4[65] = 0x83838383U;
Te4[66] = 0x2c2c2c2cU;
Te4[67] = 0x1a1a1a1aU;
Te4[68] = 0x1b1b1b1bU;
Te4[69] = 0x6e6e6e6eU;
Te4[70] = 0x5a5a5a5aU;
Te4[71] = 0xa0a0a0a0U;
Te4[72] = 0x52525252U;
Te4[73] = 0x3b3b3b3bU;
Te4[74] = 0xd6d6d6d6U;
Te4[75] = 0xb3b3b3b3U;
Te4[76] = 0x29292929U;
Te4[77] = 0xe3e3e3e3U;
Te4[78] = 0x2f2f2f2fU;
Te4[79] = 0x84848484U;
Te4[80] = 0x53535353U;
Te4[81] = 0xd1d1d1d1U;
Te4[82] = 0x00000000U;
Te4[83] = 0xededededU;
Te4[84] = 0x20202020U;
Te4[85] = 0xfcfcfcfcU;
Te4[86] = 0xb1b1b1b1U;
Te4[87] = 0x5b5b5b5bU;
Te4[88] = 0x6a6a6a6aU;
Te4[89] = 0xcbcbcbcbU;
Te4[90] = 0xbebebebeU;
Te4[91] = 0x39393939U;
Te4[92] = 0x4a4a4a4aU;
Te4[93] = 0x4c4c4c4cU;
Te4[94] = 0x58585858U;
Te4[95] = 0xcfcfcfcfU;
Te4[96] = 0xd0d0d0d0U;
Te4[97] = 0xefefefefU;
Te4[98] = 0xaaaaaaaaU;
Te4[99] = 0xfbfbfbfbU;
Te4[100] = 0x43434343U;
Te4[101] = 0x4d4d4d4dU;
Te4[102] = 0x33333333U;
Te4[103] = 0x85858585U;
Te4[104] = 0x45454545U;
Te4[105] = 0xf9f9f9f9U;
Te4[106] = 0x02020202U;
Te4[107] = 0x7f7f7f7fU;
Te4[108] = 0x50505050U;
Te4[109] = 0x3c3c3c3cU;
Te4[110] = 0x9f9f9f9fU;
Te4[111] = 0xa8a8a8a8U;
Te4[112] = 0x51515151U;
Te4[113] = 0xa3a3a3a3U;
Te4[114] = 0x40404040U;
Te4[115] = 0x8f8f8f8fU;
Te4[116] = 0x92929292U;
Te4[117] = 0x9d9d9d9dU;
Te4[118] = 0x38383838U;
Te4[119] = 0xf5f5f5f5U;
Te4[120] = 0xbcbcbcbcU;
Te4[121] = 0xb6b6b6b6U;
Te4[122] = 0xdadadadaU;
Te4[123] = 0x21212121U;
Te4[124] = 0x10101010U;
Te4[125] = 0xffffffffU;
Te4[126] = 0xf3f3f3f3U;
Te4[127] = 0xd2d2d2d2U;
Te4[128] = 0xcdcdcdcdU;
Te4[129] = 0x0c0c0c0cU;
Te4[130] = 0x13131313U;
Te4[131] = 0xececececU;
Te4[132] = 0x5f5f5f5fU;
Te4[133] = 0x97979797U;
Te4[134] = 0x44444444U;
Te4[135] = 0x17171717U;
Te4[136] = 0xc4c4c4c4U;
Te4[137] = 0xa7a7a7a7U;
Te4[138] = 0x7e7e7e7eU;
Te4[139] = 0x3d3d3d3dU;
Te4[140] = 0x64646464U;
Te4[141] = 0x5d5d5d5dU;
Te4[142] = 0x19191919U;
Te4[143] = 0x73737373U;
Te4[144] = 0x60606060U;
Te4[145] = 0x81818181U;
Te4[146] = 0x4f4f4f4fU;
Te4[147] = 0xdcdcdcdcU;
Te4[148] = 0x22222222U;
Te4[149] = 0x2a2a2a2aU;
Te4[150] = 0x90909090U;
Te4[151] = 0x88888888U;
Te4[152] = 0x46464646U;
Te4[153] = 0xeeeeeeeeU;
Te4[154] = 0xb8b8b8b8U;
Te4[155] = 0x14141414U;
Te4[156] = 0xdedededeU;
Te4[157] = 0x5e5e5e5eU;
Te4[158] = 0x0b0b0b0bU;
Te4[159] = 0xdbdbdbdbU;
Te4[160] = 0xe0e0e0e0U;
Te4[161] = 0x32323232U;
Te4[162] = 0x3a3a3a3aU;
Te4[163] = 0x0a0a0a0aU;
Te4[164] = 0x49494949U;
Te4[165] = 0x06060606U;
Te4[166] = 0x24242424U;
Te4[167] = 0x5c5c5c5cU;
Te4[168] = 0xc2c2c2c2U;
Te4[169] = 0xd3d3d3d3U;
Te4[170] = 0xacacacacU;
Te4[171] = 0x62626262U;
Te4[172] = 0x91919191U;
Te4[173] = 0x95959595U;
Te4[174] = 0xe4e4e4e4U;
Te4[175] = 0x79797979U;
Te4[176] = 0xe7e7e7e7U;
Te4[177] = 0xc8c8c8c8U;
Te4[178] = 0x37373737U;
Te4[179] = 0x6d6d6d6dU;
Te4[180] = 0x8d8d8d8dU;
Te4[181] = 0xd5d5d5d5U;
Te4[182] = 0x4e4e4e4eU;
Te4[183] = 0xa9a9a9a9U;
Te4[184] = 0x6c6c6c6cU;
Te4[185] = 0x56565656U;
Te4[186] = 0xf4f4f4f4U;
Te4[187] = 0xeaeaeaeaU;
Te4[188] = 0x65656565U;
Te4[189] = 0x7a7a7a7aU;
Te4[190] = 0xaeaeaeaeU;
Te4[191] = 0x08080808U;
Te4[192] = 0xbabababaU;
Te4[193] = 0x78787878U;
Te4[194] = 0x25252525U;
Te4[195] = 0x2e2e2e2eU;
Te4[196] = 0x1c1c1c1cU;
Te4[197] = 0xa6a6a6a6U;
Te4[198] = 0xb4b4b4b4U;
Te4[199] = 0xc6c6c6c6U;
Te4[200] = 0xe8e8e8e8U;
Te4[201] = 0xddddddddU;
Te4[202] = 0x74747474U;
Te4[203] = 0x1f1f1f1fU;
Te4[204] = 0x4b4b4b4bU;
Te4[205] = 0xbdbdbdbdU;
Te4[206] = 0x8b8b8b8bU;
Te4[207] = 0x8a8a8a8aU;
Te4[208] = 0x70707070U;
Te4[209] = 0x3e3e3e3eU;
Te4[210] = 0xb5b5b5b5U;
Te4[211] = 0x66666666U;
Te4[212] = 0x48484848U;
Te4[213] = 0x03030303U;
Te4[214] = 0xf6f6f6f6U;
Te4[215] = 0x0e0e0e0eU;
Te4[216] = 0x61616161U;
Te4[217] = 0x35353535U;
Te4[218] = 0x57575757U;
Te4[219] = 0xb9b9b9b9U;
Te4[220] = 0x86868686U;
Te4[221] = 0xc1c1c1c1U;
Te4[222] = 0x1d1d1d1dU;
Te4[223] = 0x9e9e9e9eU;
Te4[224] = 0xe1e1e1e1U;
Te4[225] = 0xf8f8f8f8U;
Te4[226] = 0x98989898U;
Te4[227] = 0x11111111U;
Te4[228] = 0x69696969U;
Te4[229] = 0xd9d9d9d9U;
Te4[230] = 0x8e8e8e8eU;
Te4[231] = 0x94949494U;
Te4[232] = 0x9b9b9b9bU;
Te4[233] = 0x1e1e1e1eU;
Te4[234] = 0x87878787U;
Te4[235] = 0xe9e9e9e9U;
Te4[236] = 0xcecececeU;
Te4[237] = 0x55555555U;
Te4[238] = 0x28282828U;
Te4[239] = 0xdfdfdfdfU;
Te4[240] = 0x8c8c8c8cU;
Te4[241] = 0xa1a1a1a1U;
Te4[242] = 0x89898989U;
Te4[243] = 0x0d0d0d0dU;
Te4[244] = 0xbfbfbfbfU;
Te4[245] = 0xe6e6e6e6U;
Te4[246] = 0x42424242U;
Te4[247] = 0x68686868U;
Te4[248] = 0x41414141U;
Te4[249] = 0x99999999U;
Te4[250] = 0x2d2d2d2dU;
Te4[251] = 0x0f0f0f0fU;
Te4[252] = 0xb0b0b0b0U;
Te4[253] = 0x54545454U;
Te4[254] = 0xbbbbbbbbU;
Te4[255] = 0x16161616U;
rcon = malloc(sizeof(uint32_t) * 10)
rcon[0] = 0x01000000;
rcon[1] = 0x02000000;
rcon[2] = 0x04000000;
rcon[3] = 0x08000000;
rcon[4] = 0x10000000;
rcon[5] = 0x20000000;
rcon[6] = 0x40000000;
rcon[7] = 0x80000000;
rcon[8] = 0x1B000000;
rcon[9] = 0x36000000;
}

#ifndef FREESTANDING_CRYPTO

CAMLprim value
mc_aes_rk_size_generic (value rounds) {
  return Val_int (RKLENGTH (keybits_of_r (Int_val (rounds))) * sizeof(uint32_t));
}

CAMLprim value
mc_aes_derive_e_key_generic (value key, value off1, value rk, value rounds) {
  mc_rijndaelSetupEncrypt (_ba_uint32 (rk),
                           _ba_uint8_off (key, off1),
                           keybits_of_r (Int_val (rounds)));
  return Val_unit;
}

CAMLprim value
mc_aes_derive_d_key_generic (value key, value off1, value kr, value rounds, value __unused (rk)) {
  mc_rijndaelSetupDecrypt (_ba_uint32 (kr),
                           _ba_uint8_off (key, off1),
                           keybits_of_r (Int_val (rounds)));
  return Val_unit;
}

CAMLprim value
mc_aes_enc_generic (value src, value off1, value dst, value off2, value rk, value rounds, value blocks) {
  _mc_aes_enc_blocks ( _ba_uint8_off (src, off1),
                       _ba_uint8_off (dst, off2),
                       _ba_uint32 (rk),
                       Int_val (rounds),
                       Int_val (blocks) );
  return Val_unit;
}

CAMLprim value
mc_aes_dec_generic (value src, value off1, value dst, value off2, value rk, value rounds, value blocks) {
  _mc_aes_dec_blocks ( _ba_uint8_off (src, off1),
                       _ba_uint8_off (dst, off2),
                       _ba_uint32 (rk),
                       Int_val (rounds),
                       Int_val (blocks) );
  return Val_unit;
}

#endif // FREESTANDING_CRYPTO