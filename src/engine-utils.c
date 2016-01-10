/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include "common.h"
#include "rp.h"
#include "engine.h"
#include "engine-algo.h"
#include "engine-utils.h"

#include "des-sse2.c"
#include "descrypt-sse2.c"

const char BASE64A_TAB[64] =
{
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
  'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
  'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  '+', '/'
};

const char BASE64B_TAB[64] =
{
  '.', '/',
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
  'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
  'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'
};

char base64a_int2char (int i)
{
  return BASE64A_TAB[i & 0x3f];
}

int base64a_char2int (char c)
{
  char *p = strchr (BASE64A_TAB, c);

  if (p == NULL) return (-1);

  return (p - BASE64A_TAB);
}

char base64b_int2char (int i)
{
  return BASE64B_TAB[i & 0x3f];
}

int base64b_char2int (char c)
{
  char *p = strchr (BASE64B_TAB, c);

  if (p == NULL) return (-1);

  return (p - BASE64B_TAB);
}

char int_to_itoa64 (const char c)
{
       if (c == 0) return '.';
  else if (c == 1) return '/';
  else if (c < 12) return '0' + c - 2;
  else if (c < 38) return 'A' + c - 12;
  else if (c < 64) return 'a' + c - 38;

  return 0;
}

char int_to_base64 (const char c)
{
       if (c  < 26) return 'A' + c;
  else if (c  < 52) return 'a' + c - 26;
  else if (c  < 62) return '0' + c - 52;
  else if (c == 62) return '+';
  else if (c == 63) return '/';

  return 0;
}

char itoa64_to_int (const char c)
{
       if (c == '.') return 0;
  else if (c == '/') return 1;
  else if ((c >= '0') && (c <= '9')) return c - '0' + 2;
  else if ((c >= 'A') && (c <= 'Z')) return c - 'A' + 12;
  else if ((c >= 'a') && (c <= 'z')) return c - 'a' + 38;

  return 0;
}

char base64_to_int (const char c)
{
       if ((c >= 'A') && (c <= 'Z')) return c - 'A';
  else if ((c >= 'a') && (c <= 'z')) return c - 'a' + 26;
  else if ((c >= '0') && (c <= '9')) return c - '0' + 52;
  else if (c == '+') return 62;
  else if (c == '/') return 63;

  return 0;
}

char int_to_bf64 (const char c)
{
       if (c ==  0) return '.';
  else if (c ==  1) return '/';
  else if (c  < 28) return 'A' + c - 2;
  else if (c  < 54) return 'a' + c - 28;
  else if (c  < 64) return '0' + c - 54;

  return 0;
}

char bf64_to_int (const char c)
{
       if (c == '.') return 0;
  else if (c == '/') return 1;
  else if ((c >= 'A') && (c <= 'Z')) return c - 'A' +  2;
  else if ((c >= 'a') && (c <= 'z')) return c - 'a' + 28;
  else if ((c >= '0') && (c <= '9')) return c - '0' + 54;

  return 0;
}

int base64_decode (char (*f) (const char), char *in_buf, int in_len, char *out_buf)
{
  char *in_ptr = in_buf;

  char *out_ptr = out_buf;

  int i,out_len;

  for (i = 0; i < in_len; i += 4)
  {
    char out_val0 = f (in_ptr[0] & 0x7f);
    char out_val1 = f (in_ptr[1] & 0x7f);
    char out_val2 = f (in_ptr[2] & 0x7f);
    char out_val3 = f (in_ptr[3] & 0x7f);

    out_ptr[0] = ((out_val0 << 2) & 0xfc) | ((out_val1 >> 4) & 0x03);
    out_ptr[1] = ((out_val1 << 4) & 0xf0) | ((out_val2 >> 2) & 0x0f);
    out_ptr[2] = ((out_val2 << 6) & 0xc0) | ((out_val3 >> 0) & 0x3f);

    in_ptr  += 4;
    out_ptr += 3;
  }

  for (i = 0; i < in_len; i++)
  {
    if (in_buf[i] != '=') continue;

    in_len = i;
  }

  out_len = (in_len * 6) / 8;

  return out_len;
}

int base64_encode (char (*f) (const char), char *in_buf, int in_len, char *out_buf)
{
  char *in_ptr = in_buf;

  char *out_ptr = out_buf;

  int i,out_len;

  for (i = 0; i < in_len; i += 3)
  {
    char out_val0 = f  ((in_ptr[0] >> 2) & 0x3f);
    char out_val1 = f (((in_ptr[0] << 4) & 0x30)
                      |((in_ptr[1] >> 4) & 0x0f));
    char out_val2 = f (((in_ptr[1] << 2) & 0x3c)
                      |((in_ptr[2] >> 6) & 0x03));
    char out_val3 = f  ((in_ptr[2] >> 0) & 0x3f);

    out_ptr[0] = out_val0 & 0x7f;
    out_ptr[1] = out_val1 & 0x7f;
    out_ptr[2] = out_val2 & 0x7f;
    out_ptr[3] = out_val3 & 0x7f;

    in_ptr  += 3;
    out_ptr += 4;
  }

  out_len = (in_len * 8) / 6;

  for (i = 0; i < (3 - (in_len % 3)); i++)
  {
    out_len++;

    out_buf[out_len] = '=';
  }

  return out_len;
}

void descrypt_decode (unsigned char digest[DIGEST_SIZE_DESCRYPT], unsigned char buf[HASH_SIZE_DESCRYPT])
{
  char tmp_buf[100];
  uint tmp_digest[2];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  base64_decode (itoa64_to_int, (char*)buf, 11, tmp_buf);

  memcpy (tmp_digest, tmp_buf, 8);

  uint32_t tt;

  IP (tmp_digest[0], tmp_digest[1], tt);

  tmp_digest[0] = ROTR32 (tmp_digest[0], 31);
  tmp_digest[1] = ROTR32 (tmp_digest[1], 31);

  memcpy (digest, tmp_digest, 8);
}

void descrypt_encode (unsigned char digest[DIGEST_SIZE_DESCRYPT], unsigned char buf[HASH_SIZE_DESCRYPT])
{
  uint tmp_digest[2];
  char tmp_buf[16];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  memcpy (tmp_digest, digest, 8);

  tmp_digest[0] = ROTL32 (tmp_digest[0], 31);
  tmp_digest[1] = ROTL32 (tmp_digest[1], 31);

  uint32_t tt;

  FP (tmp_digest[1], tmp_digest[0], tt);

  memcpy (tmp_buf, &tmp_digest, 8);

  base64_encode (int_to_itoa64, tmp_buf, 8, (char*)buf);
}

void phpass_decode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_PHPASS])
{
  int l;

  l  = base64b_char2int (buf[ 0]) <<  0;
  l |= base64b_char2int (buf[ 1]) <<  6;
  l |= base64b_char2int (buf[ 2]) << 12;
  l |= base64b_char2int (buf[ 3]) << 18;

  digest[ 0] = (l >>  0) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[ 2] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[ 4]) <<  0;
  l |= base64b_char2int (buf[ 5]) <<  6;
  l |= base64b_char2int (buf[ 6]) << 12;
  l |= base64b_char2int (buf[ 7]) << 18;

  digest[ 3] = (l >>  0) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[ 5] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[ 8]) <<  0;
  l |= base64b_char2int (buf[ 9]) <<  6;
  l |= base64b_char2int (buf[10]) << 12;
  l |= base64b_char2int (buf[11]) << 18;

  digest[ 6] = (l >>  0) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[ 8] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[12]) <<  0;
  l |= base64b_char2int (buf[13]) <<  6;
  l |= base64b_char2int (buf[14]) << 12;
  l |= base64b_char2int (buf[15]) << 18;

  digest[ 9] = (l >>  0) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[11] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[16]) <<  0;
  l |= base64b_char2int (buf[17]) <<  6;
  l |= base64b_char2int (buf[18]) << 12;
  l |= base64b_char2int (buf[19]) << 18;

  digest[12] = (l >>  0) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[14] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[20]) <<  0;
  l |= base64b_char2int (buf[21]) <<  6;

  digest[15] = (l >>  0) & 0xff;
}

void phpass_encode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_PHPASS])
{
  int l;

  l = (digest[ 0] << 0) | (digest[ 1] << 8) | (digest[ 2] << 16);

  buf[ 0] = base64b_int2char (l); l >>= 6;
  buf[ 1] = base64b_int2char (l); l >>= 6;
  buf[ 2] = base64b_int2char (l); l >>= 6;
  buf[ 3] = base64b_int2char (l);

  l = (digest[ 3] << 0) | (digest[ 4] << 8) | (digest[ 5] << 16);

  buf[ 4] = base64b_int2char (l); l >>= 6;
  buf[ 5] = base64b_int2char (l); l >>= 6;
  buf[ 6] = base64b_int2char (l); l >>= 6;
  buf[ 7] = base64b_int2char (l);

  l = (digest[ 6] << 0) | (digest[ 7] << 8) | (digest[ 8] << 16);

  buf[ 8] = base64b_int2char (l); l >>= 6;
  buf[ 9] = base64b_int2char (l); l >>= 6;
  buf[10] = base64b_int2char (l); l >>= 6;
  buf[11] = base64b_int2char (l);

  l = (digest[ 9] << 0) | (digest[10] << 8) | (digest[11] << 16);

  buf[12] = base64b_int2char (l); l >>= 6;
  buf[13] = base64b_int2char (l); l >>= 6;
  buf[14] = base64b_int2char (l); l >>= 6;
  buf[15] = base64b_int2char (l);

  l = (digest[12] << 0) | (digest[13] << 8) | (digest[14] << 16);

  buf[16] = base64b_int2char (l); l >>= 6;
  buf[17] = base64b_int2char (l); l >>= 6;
  buf[18] = base64b_int2char (l); l >>= 6;
  buf[19] = base64b_int2char (l);

  l = (digest[15] << 0);

  buf[20] = base64b_int2char (l); l >>= 6;
  buf[21] = base64b_int2char (l);
}

void md5unix_decode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_MD5UNIX])
{
  int l;

  l  = base64b_char2int (buf[ 0]) <<  0;
  l |= base64b_char2int (buf[ 1]) <<  6;
  l |= base64b_char2int (buf[ 2]) << 12;
  l |= base64b_char2int (buf[ 3]) << 18;

  digest[ 0] = (l >> 16) & 0xff;
  digest[ 6] = (l >>  8) & 0xff;
  digest[12] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[ 4]) <<  0;
  l |= base64b_char2int (buf[ 5]) <<  6;
  l |= base64b_char2int (buf[ 6]) << 12;
  l |= base64b_char2int (buf[ 7]) << 18;

  digest[ 1] = (l >> 16) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[13] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[ 8]) <<  0;
  l |= base64b_char2int (buf[ 9]) <<  6;
  l |= base64b_char2int (buf[10]) << 12;
  l |= base64b_char2int (buf[11]) << 18;

  digest[ 2] = (l >> 16) & 0xff;
  digest[ 8] = (l >>  8) & 0xff;
  digest[14] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[12]) <<  0;
  l |= base64b_char2int (buf[13]) <<  6;
  l |= base64b_char2int (buf[14]) << 12;
  l |= base64b_char2int (buf[15]) << 18;

  digest[ 3] = (l >> 16) & 0xff;
  digest[ 9] = (l >>  8) & 0xff;
  digest[15] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[16]) <<  0;
  l |= base64b_char2int (buf[17]) <<  6;
  l |= base64b_char2int (buf[18]) << 12;
  l |= base64b_char2int (buf[19]) << 18;

  digest[ 4] = (l >> 16) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[ 5] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[20]) <<  0;
  l |= base64b_char2int (buf[21]) <<  6;

  digest[11] = (l >>  0) & 0xff;
}

void md5unix_encode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_MD5UNIX])
{
  int l;

  l = (digest[ 0] << 16) | (digest[ 6] << 8) | (digest[12] << 0);

  buf[ 0] = base64b_int2char (l); l >>= 6;
  buf[ 1] = base64b_int2char (l); l >>= 6;
  buf[ 2] = base64b_int2char (l); l >>= 6;
  buf[ 3] = base64b_int2char (l); l >>= 6;

  l = (digest[ 1] << 16) | (digest[ 7] << 8) | (digest[13] << 0);

  buf[ 4] = base64b_int2char (l); l >>= 6;
  buf[ 5] = base64b_int2char (l); l >>= 6;
  buf[ 6] = base64b_int2char (l); l >>= 6;
  buf[ 7] = base64b_int2char (l); l >>= 6;

  l = (digest[ 2] << 16) | (digest[ 8] << 8) | (digest[14] << 0);

  buf[ 8] = base64b_int2char (l); l >>= 6;
  buf[ 9] = base64b_int2char (l); l >>= 6;
  buf[10] = base64b_int2char (l); l >>= 6;
  buf[11] = base64b_int2char (l); l >>= 6;

  l = (digest[ 3] << 16) | (digest[ 9] << 8) | (digest[15] << 0);

  buf[12] = base64b_int2char (l); l >>= 6;
  buf[13] = base64b_int2char (l); l >>= 6;
  buf[14] = base64b_int2char (l); l >>= 6;
  buf[15] = base64b_int2char (l); l >>= 6;

  l = (digest[ 4] << 16) | (digest[10] << 8) | (digest[ 5] << 0);

  buf[16] = base64b_int2char (l); l >>= 6;
  buf[17] = base64b_int2char (l); l >>= 6;
  buf[18] = base64b_int2char (l); l >>= 6;
  buf[19] = base64b_int2char (l); l >>= 6;

  l = (digest[11] << 0);

  buf[20] = base64b_int2char (l); l >>= 6;
  buf[21] = base64b_int2char (l); l >>= 6;
}

void md5sun_decode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_MD5SUN])
{
  int l;

  l  = base64b_char2int (buf[ 0]) <<  0;
  l |= base64b_char2int (buf[ 1]) <<  6;
  l |= base64b_char2int (buf[ 2]) << 12;
  l |= base64b_char2int (buf[ 3]) << 18;

  digest[ 0] = (l >> 16) & 0xff;
  digest[ 6] = (l >>  8) & 0xff;
  digest[12] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[ 4]) <<  0;
  l |= base64b_char2int (buf[ 5]) <<  6;
  l |= base64b_char2int (buf[ 6]) << 12;
  l |= base64b_char2int (buf[ 7]) << 18;

  digest[ 1] = (l >> 16) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[13] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[ 8]) <<  0;
  l |= base64b_char2int (buf[ 9]) <<  6;
  l |= base64b_char2int (buf[10]) << 12;
  l |= base64b_char2int (buf[11]) << 18;

  digest[ 2] = (l >> 16) & 0xff;
  digest[ 8] = (l >>  8) & 0xff;
  digest[14] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[12]) <<  0;
  l |= base64b_char2int (buf[13]) <<  6;
  l |= base64b_char2int (buf[14]) << 12;
  l |= base64b_char2int (buf[15]) << 18;

  digest[ 3] = (l >> 16) & 0xff;
  digest[ 9] = (l >>  8) & 0xff;
  digest[15] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[16]) <<  0;
  l |= base64b_char2int (buf[17]) <<  6;
  l |= base64b_char2int (buf[18]) << 12;
  l |= base64b_char2int (buf[19]) << 18;

  digest[ 4] = (l >> 16) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[ 5] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[20]) <<  0;
  l |= base64b_char2int (buf[21]) <<  6;

  digest[11] = (l >>  0) & 0xff;
}

void md5sun_encode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_MD5SUN])
{
  int l;

  l = (digest[ 0] << 16) | (digest[ 6] << 8) | (digest[12] << 0);

  buf[ 0] = base64b_int2char (l); l >>= 6;
  buf[ 1] = base64b_int2char (l); l >>= 6;
  buf[ 2] = base64b_int2char (l); l >>= 6;
  buf[ 3] = base64b_int2char (l); l >>= 6;

  l = (digest[ 1] << 16) | (digest[ 7] << 8) | (digest[13] << 0);

  buf[ 4] = base64b_int2char (l); l >>= 6;
  buf[ 5] = base64b_int2char (l); l >>= 6;
  buf[ 6] = base64b_int2char (l); l >>= 6;
  buf[ 7] = base64b_int2char (l); l >>= 6;

  l = (digest[ 2] << 16) | (digest[ 8] << 8) | (digest[14] << 0);

  buf[ 8] = base64b_int2char (l); l >>= 6;
  buf[ 9] = base64b_int2char (l); l >>= 6;
  buf[10] = base64b_int2char (l); l >>= 6;
  buf[11] = base64b_int2char (l); l >>= 6;

  l = (digest[ 3] << 16) | (digest[ 9] << 8) | (digest[15] << 0);

  buf[12] = base64b_int2char (l); l >>= 6;
  buf[13] = base64b_int2char (l); l >>= 6;
  buf[14] = base64b_int2char (l); l >>= 6;
  buf[15] = base64b_int2char (l); l >>= 6;

  l = (digest[ 4] << 16) | (digest[10] << 8) | (digest[ 5] << 0);

  buf[16] = base64b_int2char (l); l >>= 6;
  buf[17] = base64b_int2char (l); l >>= 6;
  buf[18] = base64b_int2char (l); l >>= 6;
  buf[19] = base64b_int2char (l); l >>= 6;

  l = (digest[11] << 0);

  buf[20] = base64b_int2char (l); l >>= 6;
  buf[21] = base64b_int2char (l); l >>= 6;
}

void md5apr_decode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_MD5APR])
{
  int l;

  l  = base64b_char2int (buf[ 0]) <<  0;
  l |= base64b_char2int (buf[ 1]) <<  6;
  l |= base64b_char2int (buf[ 2]) << 12;
  l |= base64b_char2int (buf[ 3]) << 18;

  digest[ 0] = (l >> 16) & 0xff;
  digest[ 6] = (l >>  8) & 0xff;
  digest[12] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[ 4]) <<  0;
  l |= base64b_char2int (buf[ 5]) <<  6;
  l |= base64b_char2int (buf[ 6]) << 12;
  l |= base64b_char2int (buf[ 7]) << 18;

  digest[ 1] = (l >> 16) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[13] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[ 8]) <<  0;
  l |= base64b_char2int (buf[ 9]) <<  6;
  l |= base64b_char2int (buf[10]) << 12;
  l |= base64b_char2int (buf[11]) << 18;

  digest[ 2] = (l >> 16) & 0xff;
  digest[ 8] = (l >>  8) & 0xff;
  digest[14] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[12]) <<  0;
  l |= base64b_char2int (buf[13]) <<  6;
  l |= base64b_char2int (buf[14]) << 12;
  l |= base64b_char2int (buf[15]) << 18;

  digest[ 3] = (l >> 16) & 0xff;
  digest[ 9] = (l >>  8) & 0xff;
  digest[15] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[16]) <<  0;
  l |= base64b_char2int (buf[17]) <<  6;
  l |= base64b_char2int (buf[18]) << 12;
  l |= base64b_char2int (buf[19]) << 18;

  digest[ 4] = (l >> 16) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[ 5] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[20]) <<  0;
  l |= base64b_char2int (buf[21]) <<  6;

  digest[11] = (l >>  0) & 0xff;
}

void md5apr_encode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_MD5APR])
{
  int l;

  l = (digest[ 0] << 16) | (digest[ 6] << 8) | (digest[12] << 0);

  buf[ 0] = base64b_int2char (l); l >>= 6;
  buf[ 1] = base64b_int2char (l); l >>= 6;
  buf[ 2] = base64b_int2char (l); l >>= 6;
  buf[ 3] = base64b_int2char (l); l >>= 6;

  l = (digest[ 1] << 16) | (digest[ 7] << 8) | (digest[13] << 0);

  buf[ 4] = base64b_int2char (l); l >>= 6;
  buf[ 5] = base64b_int2char (l); l >>= 6;
  buf[ 6] = base64b_int2char (l); l >>= 6;
  buf[ 7] = base64b_int2char (l); l >>= 6;

  l = (digest[ 2] << 16) | (digest[ 8] << 8) | (digest[14] << 0);

  buf[ 8] = base64b_int2char (l); l >>= 6;
  buf[ 9] = base64b_int2char (l); l >>= 6;
  buf[10] = base64b_int2char (l); l >>= 6;
  buf[11] = base64b_int2char (l); l >>= 6;

  l = (digest[ 3] << 16) | (digest[ 9] << 8) | (digest[15] << 0);

  buf[12] = base64b_int2char (l); l >>= 6;
  buf[13] = base64b_int2char (l); l >>= 6;
  buf[14] = base64b_int2char (l); l >>= 6;
  buf[15] = base64b_int2char (l); l >>= 6;

  l = (digest[ 4] << 16) | (digest[10] << 8) | (digest[ 5] << 0);

  buf[16] = base64b_int2char (l); l >>= 6;
  buf[17] = base64b_int2char (l); l >>= 6;
  buf[18] = base64b_int2char (l); l >>= 6;
  buf[19] = base64b_int2char (l); l >>= 6;

  l = (digest[11] << 0);

  buf[20] = base64b_int2char (l); l >>= 6;
  buf[21] = base64b_int2char (l); l >>= 6;
}

void sha512unix_decode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char buf[HASH_SIZE_SHA512UNIX])
{
  int l;

  l  = base64b_char2int (buf[ 0]) <<  0;
  l |= base64b_char2int (buf[ 1]) <<  6;
  l |= base64b_char2int (buf[ 2]) << 12;
  l |= base64b_char2int (buf[ 3]) << 18;

  digest[ 0] = (l >> 16) & 0xff;
  digest[21] = (l >>  8) & 0xff;
  digest[42] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[ 4]) <<  0;
  l |= base64b_char2int (buf[ 5]) <<  6;
  l |= base64b_char2int (buf[ 6]) << 12;
  l |= base64b_char2int (buf[ 7]) << 18;

  digest[22] = (l >> 16) & 0xff;
  digest[43] = (l >>  8) & 0xff;
  digest[ 1] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[ 8]) <<  0;
  l |= base64b_char2int (buf[ 9]) <<  6;
  l |= base64b_char2int (buf[10]) << 12;
  l |= base64b_char2int (buf[11]) << 18;

  digest[44] = (l >> 16) & 0xff;
  digest[ 2] = (l >>  8) & 0xff;
  digest[23] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[12]) <<  0;
  l |= base64b_char2int (buf[13]) <<  6;
  l |= base64b_char2int (buf[14]) << 12;
  l |= base64b_char2int (buf[15]) << 18;

  digest[ 3] = (l >> 16) & 0xff;
  digest[24] = (l >>  8) & 0xff;
  digest[45] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[16]) <<  0;
  l |= base64b_char2int (buf[17]) <<  6;
  l |= base64b_char2int (buf[18]) << 12;
  l |= base64b_char2int (buf[19]) << 18;

  digest[25] = (l >> 16) & 0xff;
  digest[46] = (l >>  8) & 0xff;
  digest[ 4] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[20]) <<  0;
  l |= base64b_char2int (buf[21]) <<  6;
  l |= base64b_char2int (buf[22]) << 12;
  l |= base64b_char2int (buf[23]) << 18;

  digest[47] = (l >> 16) & 0xff;
  digest[ 5] = (l >>  8) & 0xff;
  digest[26] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[24]) <<  0;
  l |= base64b_char2int (buf[25]) <<  6;
  l |= base64b_char2int (buf[26]) << 12;
  l |= base64b_char2int (buf[27]) << 18;

  digest[ 6] = (l >> 16) & 0xff;
  digest[27] = (l >>  8) & 0xff;
  digest[48] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[28]) <<  0;
  l |= base64b_char2int (buf[29]) <<  6;
  l |= base64b_char2int (buf[30]) << 12;
  l |= base64b_char2int (buf[31]) << 18;

  digest[28] = (l >> 16) & 0xff;
  digest[49] = (l >>  8) & 0xff;
  digest[ 7] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[32]) <<  0;
  l |= base64b_char2int (buf[33]) <<  6;
  l |= base64b_char2int (buf[34]) << 12;
  l |= base64b_char2int (buf[35]) << 18;

  digest[50] = (l >> 16) & 0xff;
  digest[ 8] = (l >>  8) & 0xff;
  digest[29] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[36]) <<  0;
  l |= base64b_char2int (buf[37]) <<  6;
  l |= base64b_char2int (buf[38]) << 12;
  l |= base64b_char2int (buf[39]) << 18;

  digest[ 9] = (l >> 16) & 0xff;
  digest[30] = (l >>  8) & 0xff;
  digest[51] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[40]) <<  0;
  l |= base64b_char2int (buf[41]) <<  6;
  l |= base64b_char2int (buf[42]) << 12;
  l |= base64b_char2int (buf[43]) << 18;

  digest[31] = (l >> 16) & 0xff;
  digest[52] = (l >>  8) & 0xff;
  digest[10] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[44]) <<  0;
  l |= base64b_char2int (buf[45]) <<  6;
  l |= base64b_char2int (buf[46]) << 12;
  l |= base64b_char2int (buf[47]) << 18;

  digest[53] = (l >> 16) & 0xff;
  digest[11] = (l >>  8) & 0xff;
  digest[32] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[48]) <<  0;
  l |= base64b_char2int (buf[49]) <<  6;
  l |= base64b_char2int (buf[50]) << 12;
  l |= base64b_char2int (buf[51]) << 18;

  digest[12] = (l >> 16) & 0xff;
  digest[33] = (l >>  8) & 0xff;
  digest[54] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[52]) <<  0;
  l |= base64b_char2int (buf[53]) <<  6;
  l |= base64b_char2int (buf[54]) << 12;
  l |= base64b_char2int (buf[55]) << 18;

  digest[34] = (l >> 16) & 0xff;
  digest[55] = (l >>  8) & 0xff;
  digest[13] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[56]) <<  0;
  l |= base64b_char2int (buf[57]) <<  6;
  l |= base64b_char2int (buf[58]) << 12;
  l |= base64b_char2int (buf[59]) << 18;

  digest[56] = (l >> 16) & 0xff;
  digest[14] = (l >>  8) & 0xff;
  digest[35] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[60]) <<  0;
  l |= base64b_char2int (buf[61]) <<  6;
  l |= base64b_char2int (buf[62]) << 12;
  l |= base64b_char2int (buf[63]) << 18;

  digest[15] = (l >> 16) & 0xff;
  digest[36] = (l >>  8) & 0xff;
  digest[57] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[64]) <<  0;
  l |= base64b_char2int (buf[65]) <<  6;
  l |= base64b_char2int (buf[66]) << 12;
  l |= base64b_char2int (buf[67]) << 18;

  digest[37] = (l >> 16) & 0xff;
  digest[58] = (l >>  8) & 0xff;
  digest[16] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[68]) <<  0;
  l |= base64b_char2int (buf[69]) <<  6;
  l |= base64b_char2int (buf[70]) << 12;
  l |= base64b_char2int (buf[71]) << 18;

  digest[59] = (l >> 16) & 0xff;
  digest[17] = (l >>  8) & 0xff;
  digest[38] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[72]) <<  0;
  l |= base64b_char2int (buf[73]) <<  6;
  l |= base64b_char2int (buf[74]) << 12;
  l |= base64b_char2int (buf[75]) << 18;

  digest[18] = (l >> 16) & 0xff;
  digest[39] = (l >>  8) & 0xff;
  digest[60] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[76]) <<  0;
  l |= base64b_char2int (buf[77]) <<  6;
  l |= base64b_char2int (buf[78]) << 12;
  l |= base64b_char2int (buf[79]) << 18;

  digest[40] = (l >> 16) & 0xff;
  digest[61] = (l >>  8) & 0xff;
  digest[19] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[80]) <<  0;
  l |= base64b_char2int (buf[81]) <<  6;
  l |= base64b_char2int (buf[82]) << 12;
  l |= base64b_char2int (buf[83]) << 18;

  digest[62] = (l >> 16) & 0xff;
  digest[20] = (l >>  8) & 0xff;
  digest[41] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[84]) <<  0;
  l |= base64b_char2int (buf[85]) <<  6;

  digest[63] = (l >>  0) & 0xff;
}

void sha512unix_encode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char buf[HASH_SIZE_SHA512UNIX])
{
  int l;

  l = (digest[ 0] << 16) | (digest[21] << 8) | (digest[42] << 0);

  buf[ 0] = base64b_int2char (l); l >>= 6;
  buf[ 1] = base64b_int2char (l); l >>= 6;
  buf[ 2] = base64b_int2char (l); l >>= 6;
  buf[ 3] = base64b_int2char (l); l >>= 6;

  l = (digest[22] << 16) | (digest[43] << 8) | (digest[ 1] << 0);

  buf[ 4] = base64b_int2char (l); l >>= 6;
  buf[ 5] = base64b_int2char (l); l >>= 6;
  buf[ 6] = base64b_int2char (l); l >>= 6;
  buf[ 7] = base64b_int2char (l); l >>= 6;

  l = (digest[44] << 16) | (digest[ 2] << 8) | (digest[23] << 0);

  buf[ 8] = base64b_int2char (l); l >>= 6;
  buf[ 9] = base64b_int2char (l); l >>= 6;
  buf[10] = base64b_int2char (l); l >>= 6;
  buf[11] = base64b_int2char (l); l >>= 6;

  l = (digest[ 3] << 16) | (digest[24] << 8) | (digest[45] << 0);

  buf[12] = base64b_int2char (l); l >>= 6;
  buf[13] = base64b_int2char (l); l >>= 6;
  buf[14] = base64b_int2char (l); l >>= 6;
  buf[15] = base64b_int2char (l); l >>= 6;

  l = (digest[25] << 16) | (digest[46] << 8) | (digest[ 4] << 0);

  buf[16] = base64b_int2char (l); l >>= 6;
  buf[17] = base64b_int2char (l); l >>= 6;
  buf[18] = base64b_int2char (l); l >>= 6;
  buf[19] = base64b_int2char (l); l >>= 6;

  l = (digest[47] << 16) | (digest[ 5] << 8) | (digest[26] << 0);

  buf[20] = base64b_int2char (l); l >>= 6;
  buf[21] = base64b_int2char (l); l >>= 6;
  buf[22] = base64b_int2char (l); l >>= 6;
  buf[23] = base64b_int2char (l); l >>= 6;

  l = (digest[ 6] << 16) | (digest[27] << 8) | (digest[48] << 0);

  buf[24] = base64b_int2char (l); l >>= 6;
  buf[25] = base64b_int2char (l); l >>= 6;
  buf[26] = base64b_int2char (l); l >>= 6;
  buf[27] = base64b_int2char (l); l >>= 6;

  l = (digest[28] << 16) | (digest[49] << 8) | (digest[ 7] << 0);

  buf[28] = base64b_int2char (l); l >>= 6;
  buf[29] = base64b_int2char (l); l >>= 6;
  buf[30] = base64b_int2char (l); l >>= 6;
  buf[31] = base64b_int2char (l); l >>= 6;

  l = (digest[50] << 16) | (digest[ 8] << 8) | (digest[29] << 0);

  buf[32] = base64b_int2char (l); l >>= 6;
  buf[33] = base64b_int2char (l); l >>= 6;
  buf[34] = base64b_int2char (l); l >>= 6;
  buf[35] = base64b_int2char (l); l >>= 6;

  l = (digest[ 9] << 16) | (digest[30] << 8) | (digest[51] << 0);

  buf[36] = base64b_int2char (l); l >>= 6;
  buf[37] = base64b_int2char (l); l >>= 6;
  buf[38] = base64b_int2char (l); l >>= 6;
  buf[39] = base64b_int2char (l); l >>= 6;

  l = (digest[31] << 16) | (digest[52] << 8) | (digest[10] << 0);

  buf[40] = base64b_int2char (l); l >>= 6;
  buf[41] = base64b_int2char (l); l >>= 6;
  buf[42] = base64b_int2char (l); l >>= 6;
  buf[43] = base64b_int2char (l); l >>= 6;

  l = (digest[53] << 16) | (digest[11] << 8) | (digest[32] << 0);

  buf[44] = base64b_int2char (l); l >>= 6;
  buf[45] = base64b_int2char (l); l >>= 6;
  buf[46] = base64b_int2char (l); l >>= 6;
  buf[47] = base64b_int2char (l); l >>= 6;

  l = (digest[12] << 16) | (digest[33] << 8) | (digest[54] << 0);

  buf[48] = base64b_int2char (l); l >>= 6;
  buf[49] = base64b_int2char (l); l >>= 6;
  buf[50] = base64b_int2char (l); l >>= 6;
  buf[51] = base64b_int2char (l); l >>= 6;

  l = (digest[34] << 16) | (digest[55] << 8) | (digest[13] << 0);

  buf[52] = base64b_int2char (l); l >>= 6;
  buf[53] = base64b_int2char (l); l >>= 6;
  buf[54] = base64b_int2char (l); l >>= 6;
  buf[55] = base64b_int2char (l); l >>= 6;

  l = (digest[56] << 16) | (digest[14] << 8) | (digest[35] << 0);

  buf[56] = base64b_int2char (l); l >>= 6;
  buf[57] = base64b_int2char (l); l >>= 6;
  buf[58] = base64b_int2char (l); l >>= 6;
  buf[59] = base64b_int2char (l); l >>= 6;

  l = (digest[15] << 16) | (digest[36] << 8) | (digest[57] << 0);

  buf[60] = base64b_int2char (l); l >>= 6;
  buf[61] = base64b_int2char (l); l >>= 6;
  buf[62] = base64b_int2char (l); l >>= 6;
  buf[63] = base64b_int2char (l); l >>= 6;

  l = (digest[37] << 16) | (digest[58] << 8) | (digest[16] << 0);

  buf[64] = base64b_int2char (l); l >>= 6;
  buf[65] = base64b_int2char (l); l >>= 6;
  buf[66] = base64b_int2char (l); l >>= 6;
  buf[67] = base64b_int2char (l); l >>= 6;

  l = (digest[59] << 16) | (digest[17] << 8) | (digest[38] << 0);

  buf[68] = base64b_int2char (l); l >>= 6;
  buf[69] = base64b_int2char (l); l >>= 6;
  buf[70] = base64b_int2char (l); l >>= 6;
  buf[71] = base64b_int2char (l); l >>= 6;

  l = (digest[18] << 16) | (digest[39] << 8) | (digest[60] << 0);

  buf[72] = base64b_int2char (l); l >>= 6;
  buf[73] = base64b_int2char (l); l >>= 6;
  buf[74] = base64b_int2char (l); l >>= 6;
  buf[75] = base64b_int2char (l); l >>= 6;

  l = (digest[40] << 16) | (digest[61] << 8) | (digest[19] << 0);

  buf[76] = base64b_int2char (l); l >>= 6;
  buf[77] = base64b_int2char (l); l >>= 6;
  buf[78] = base64b_int2char (l); l >>= 6;
  buf[79] = base64b_int2char (l); l >>= 6;

  l = (digest[62] << 16) | (digest[20] << 8) | (digest[41] << 0);

  buf[80] = base64b_int2char (l); l >>= 6;
  buf[81] = base64b_int2char (l); l >>= 6;
  buf[82] = base64b_int2char (l); l >>= 6;
  buf[83] = base64b_int2char (l); l >>= 6;

  l = 0 | (digest[63] << 0);

  buf[84] = base64b_int2char (l); l >>= 6;
  buf[85] = base64b_int2char (l); l >>= 6;
}

void sha1b64_decode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char buf[HASH_SIZE_SHA1B64])
{
  int l;

  l  = base64a_char2int (buf[ 3]) <<  0;
  l |= base64a_char2int (buf[ 2]) <<  6;
  l |= base64a_char2int (buf[ 1]) << 12;
  l |= base64a_char2int (buf[ 0]) << 18;

  digest[ 2] = (l >>  0) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[ 0] = (l >> 16) & 0xff;

  l  = base64a_char2int (buf[ 7]) <<  0;
  l |= base64a_char2int (buf[ 6]) <<  6;
  l |= base64a_char2int (buf[ 5]) << 12;
  l |= base64a_char2int (buf[ 4]) << 18;

  digest[ 5] = (l >>  0) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[ 3] = (l >> 16) & 0xff;

  l  = base64a_char2int (buf[11]) <<  0;
  l |= base64a_char2int (buf[10]) <<  6;
  l |= base64a_char2int (buf[ 9]) << 12;
  l |= base64a_char2int (buf[ 8]) << 18;

  digest[ 8] = (l >>  0) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[ 6] = (l >> 16) & 0xff;

  l  = base64a_char2int (buf[15]) <<  0;
  l |= base64a_char2int (buf[14]) <<  6;
  l |= base64a_char2int (buf[13]) << 12;
  l |= base64a_char2int (buf[12]) << 18;

  digest[11] = (l >>  0) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[ 9] = (l >> 16) & 0xff;

  l  = base64a_char2int (buf[19]) <<  0;
  l |= base64a_char2int (buf[18]) <<  6;
  l |= base64a_char2int (buf[17]) << 12;
  l |= base64a_char2int (buf[16]) << 18;

  digest[14] = (l >>  0) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[12] = (l >> 16) & 0xff;

  l  = base64a_char2int (buf[23]) <<  0;
  l |= base64a_char2int (buf[22]) <<  6;
  l |= base64a_char2int (buf[21]) << 12;
  l |= base64a_char2int (buf[20]) << 18;

  digest[17] = (l >>  0) & 0xff;
  digest[16] = (l >>  8) & 0xff;
  digest[15] = (l >> 16) & 0xff;

  l  = 0;
  l |= base64a_char2int (buf[26]) <<  6;
  l |= base64a_char2int (buf[25]) << 12;
  l |= base64a_char2int (buf[24]) << 18;

  digest[19] = (l >>  8) & 0xff;
  digest[18] = (l >> 16) & 0xff;
}

void sha1b64_encode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char buf[HASH_SIZE_SHA1B64])
{
  int l;

  l = (digest[ 0] << 16) | (digest[ 1] << 8) | (digest[ 2] << 0);

  buf[ 3] = base64a_int2char (l); l >>= 6;
  buf[ 2] = base64a_int2char (l); l >>= 6;
  buf[ 1] = base64a_int2char (l); l >>= 6;
  buf[ 0] = base64a_int2char (l);

  l = (digest[ 3] << 16) | (digest[ 4] << 8) | (digest[ 5] << 0);

  buf[ 7] = base64a_int2char (l); l >>= 6;
  buf[ 6] = base64a_int2char (l); l >>= 6;
  buf[ 5] = base64a_int2char (l); l >>= 6;
  buf[ 4] = base64a_int2char (l);

  l = (digest[ 6] << 16) | (digest[ 7] << 8) | (digest[ 8] << 0);

  buf[11] = base64a_int2char (l); l >>= 6;
  buf[10] = base64a_int2char (l); l >>= 6;
  buf[ 9] = base64a_int2char (l); l >>= 6;
  buf[ 8] = base64a_int2char (l);

  l = (digest[ 9] << 16) | (digest[10] << 8) | (digest[11] << 0);

  buf[15] = base64a_int2char (l); l >>= 6;
  buf[14] = base64a_int2char (l); l >>= 6;
  buf[13] = base64a_int2char (l); l >>= 6;
  buf[12] = base64a_int2char (l);

  l = (digest[12] << 16) | (digest[13] << 8) | (digest[14] << 0);

  buf[19] = base64a_int2char (l); l >>= 6;
  buf[18] = base64a_int2char (l); l >>= 6;
  buf[17] = base64a_int2char (l); l >>= 6;
  buf[16] = base64a_int2char (l);

  l = (digest[15] << 16) | (digest[16] << 8) | (digest[17] << 0);

  buf[23] = base64a_int2char (l); l >>= 6;
  buf[22] = base64a_int2char (l); l >>= 6;
  buf[21] = base64a_int2char (l); l >>= 6;
  buf[20] = base64a_int2char (l);

  l = (digest[18] << 16) | (digest[19] << 8);

  buf[27] = '=';                  l >>= 6;
  buf[26] = base64a_int2char (l); l >>= 6;
  buf[25] = base64a_int2char (l); l >>= 6;
  buf[24] = base64a_int2char (l);
}

void sha1b64s_decode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char salt[BLOCK_SIZE], uint32_t in_len, uint32_t *out_len, char *buf)
{
  char tmp_buf[in_len / 4 * 3];

  *out_len = base64_decode (base64_to_int, buf, in_len, tmp_buf);

  memcpy (digest, tmp_buf, 20);

  memcpy (salt, tmp_buf + 20, *out_len - 20);

  // substract sha1 length from total output
  *out_len -= 20;
}

void sha1b64s_encode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char salt[BLOCK_SIZE], uint32_t salt_len, char *buf)
{
  char tmp_buf[20 + salt_len + 3];

  memcpy (tmp_buf, digest, 20);

  memcpy (tmp_buf + 20, salt, salt_len);

  memset (tmp_buf + 20 + salt_len, 0, 3);

  uint32_t out_len;

  out_len = base64_encode (int_to_base64, tmp_buf, 20 + salt_len, buf);

  buf[out_len + 1] = 0;
}

void sha256b64_decode (unsigned char digest[DIGEST_SIZE_SHA256], unsigned char buf[HASH_SIZE_SHA256B64])
{
  int l;

  l  = base64a_char2int (buf[ 3]) <<  0;
  l |= base64a_char2int (buf[ 2]) <<  6;
  l |= base64a_char2int (buf[ 1]) << 12;
  l |= base64a_char2int (buf[ 0]) << 18;

  digest[ 2] = (l >>  0) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[ 0] = (l >> 16) & 0xff;

  l  = base64a_char2int (buf[ 7]) <<  0;
  l |= base64a_char2int (buf[ 6]) <<  6;
  l |= base64a_char2int (buf[ 5]) << 12;
  l |= base64a_char2int (buf[ 4]) << 18;

  digest[ 5] = (l >>  0) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[ 3] = (l >> 16) & 0xff;

  l  = base64a_char2int (buf[11]) <<  0;
  l |= base64a_char2int (buf[10]) <<  6;
  l |= base64a_char2int (buf[ 9]) << 12;
  l |= base64a_char2int (buf[ 8]) << 18;

  digest[ 8] = (l >>  0) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[ 6] = (l >> 16) & 0xff;

  l  = base64a_char2int (buf[15]) <<  0;
  l |= base64a_char2int (buf[14]) <<  6;
  l |= base64a_char2int (buf[13]) << 12;
  l |= base64a_char2int (buf[12]) << 18;

  digest[11] = (l >>  0) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[ 9] = (l >> 16) & 0xff;

  l  = base64a_char2int (buf[19]) <<  0;
  l |= base64a_char2int (buf[18]) <<  6;
  l |= base64a_char2int (buf[17]) << 12;
  l |= base64a_char2int (buf[16]) << 18;

  digest[14] = (l >>  0) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[12] = (l >> 16) & 0xff;

  l  = base64a_char2int (buf[23]) <<  0;
  l |= base64a_char2int (buf[22]) <<  6;
  l |= base64a_char2int (buf[21]) << 12;
  l |= base64a_char2int (buf[20]) << 18;

  digest[17] = (l >>  0) & 0xff;
  digest[16] = (l >>  8) & 0xff;
  digest[15] = (l >> 16) & 0xff;

  l  = base64a_char2int (buf[27]) <<  0;
  l |= base64a_char2int (buf[26]) <<  6;
  l |= base64a_char2int (buf[25]) << 12;
  l |= base64a_char2int (buf[24]) << 18;

  digest[20] = (l >>  0) & 0xff;
  digest[19] = (l >>  8) & 0xff;
  digest[18] = (l >> 16) & 0xff;

  l  = base64a_char2int (buf[31]) <<  0;
  l |= base64a_char2int (buf[30]) <<  6;
  l |= base64a_char2int (buf[29]) << 12;
  l |= base64a_char2int (buf[28]) << 18;

  digest[23] = (l >>  0) & 0xff;
  digest[22] = (l >>  8) & 0xff;
  digest[21] = (l >> 16) & 0xff;

  l  = base64a_char2int (buf[35]) <<  0;
  l |= base64a_char2int (buf[34]) <<  6;
  l |= base64a_char2int (buf[33]) << 12;
  l |= base64a_char2int (buf[32]) << 18;

  digest[26] = (l >>  0) & 0xff;
  digest[25] = (l >>  8) & 0xff;
  digest[24] = (l >> 16) & 0xff;

  l  = base64a_char2int (buf[39]) <<  0;
  l |= base64a_char2int (buf[38]) <<  6;
  l |= base64a_char2int (buf[37]) << 12;
  l |= base64a_char2int (buf[36]) << 18;

  digest[29] = (l >>  0) & 0xff;
  digest[28] = (l >>  8) & 0xff;
  digest[27] = (l >> 16) & 0xff;

  l  = 0;
  l |= base64a_char2int (buf[42]) <<  6;
  l |= base64a_char2int (buf[41]) << 12;
  l |= base64a_char2int (buf[40]) << 18;

  digest[32] = (l >>  0) & 0xff;
  digest[31] = (l >>  8) & 0xff;
  digest[30] = (l >> 16) & 0xff;
}

void sha256b64_encode (unsigned char digest[DIGEST_SIZE_SHA256], unsigned char buf[HASH_SIZE_SHA256B64])
{
  int l;

  l = (digest[ 0] << 16) | (digest[ 1] << 8) | (digest[ 2] << 0);

  buf[ 3] = base64a_int2char (l); l >>= 6;
  buf[ 2] = base64a_int2char (l); l >>= 6;
  buf[ 1] = base64a_int2char (l); l >>= 6;
  buf[ 0] = base64a_int2char (l);

  l = (digest[ 3] << 16) | (digest[ 4] << 8) | (digest[ 5] << 0);

  buf[ 7] = base64a_int2char (l); l >>= 6;
  buf[ 6] = base64a_int2char (l); l >>= 6;
  buf[ 5] = base64a_int2char (l); l >>= 6;
  buf[ 4] = base64a_int2char (l);

  l = (digest[ 6] << 16) | (digest[ 7] << 8) | (digest[ 8] << 0);

  buf[11] = base64a_int2char (l); l >>= 6;
  buf[10] = base64a_int2char (l); l >>= 6;
  buf[ 9] = base64a_int2char (l); l >>= 6;
  buf[ 8] = base64a_int2char (l);

  l = (digest[ 9] << 16) | (digest[10] << 8) | (digest[11] << 0);

  buf[15] = base64a_int2char (l); l >>= 6;
  buf[14] = base64a_int2char (l); l >>= 6;
  buf[13] = base64a_int2char (l); l >>= 6;
  buf[12] = base64a_int2char (l);

  l = (digest[12] << 16) | (digest[13] << 8) | (digest[14] << 0);

  buf[19] = base64a_int2char (l); l >>= 6;
  buf[18] = base64a_int2char (l); l >>= 6;
  buf[17] = base64a_int2char (l); l >>= 6;
  buf[16] = base64a_int2char (l);

  l = (digest[15] << 16) | (digest[16] << 8) | (digest[17] << 0);

  buf[23] = base64a_int2char (l); l >>= 6;
  buf[22] = base64a_int2char (l); l >>= 6;
  buf[21] = base64a_int2char (l); l >>= 6;
  buf[20] = base64a_int2char (l);

  l = (digest[18] << 16) | (digest[19] << 8) | (digest[20] << 0);

  buf[27] = base64a_int2char (l); l >>= 6;
  buf[26] = base64a_int2char (l); l >>= 6;
  buf[25] = base64a_int2char (l); l >>= 6;
  buf[24] = base64a_int2char (l);

  l = (digest[21] << 16) | (digest[22] << 8) | (digest[23] << 0);

  buf[31] = base64a_int2char (l); l >>= 6;
  buf[30] = base64a_int2char (l); l >>= 6;
  buf[29] = base64a_int2char (l); l >>= 6;
  buf[28] = base64a_int2char (l);

  l = (digest[24] << 16) | (digest[25] << 8) | (digest[26] << 0);

  buf[35] = base64a_int2char (l); l >>= 6;
  buf[34] = base64a_int2char (l); l >>= 6;
  buf[33] = base64a_int2char (l); l >>= 6;
  buf[32] = base64a_int2char (l);

  l = (digest[27] << 16) | (digest[28] << 8) | (digest[29] << 0);

  buf[39] = base64a_int2char (l); l >>= 6;
  buf[38] = base64a_int2char (l); l >>= 6;
  buf[37] = base64a_int2char (l); l >>= 6;
  buf[36] = base64a_int2char (l);

  l = (digest[30] << 16) | (digest[31] << 8) | (digest[32] << 0);

  buf[43] = '=';                  l >>= 6;
  buf[42] = base64a_int2char (l); l >>= 6;
  buf[41] = base64a_int2char (l); l >>= 6;
  buf[40] = base64a_int2char (l);
}

void sha1aix_decode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char buf[HASH_SIZE_SHA1AIX])
{
  int l;

  l  = base64b_char2int (buf[ 0]) <<  0;
  l |= base64b_char2int (buf[ 1]) <<  6;
  l |= base64b_char2int (buf[ 2]) << 12;
  l |= base64b_char2int (buf[ 3]) << 18;

  digest[ 2] = (l >>  0) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[ 0] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[ 4]) <<  0;
  l |= base64b_char2int (buf[ 5]) <<  6;
  l |= base64b_char2int (buf[ 6]) << 12;
  l |= base64b_char2int (buf[ 7]) << 18;

  digest[ 5] = (l >>  0) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[ 3] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[ 8]) <<  0;
  l |= base64b_char2int (buf[ 9]) <<  6;
  l |= base64b_char2int (buf[10]) << 12;
  l |= base64b_char2int (buf[11]) << 18;

  digest[ 8] = (l >>  0) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[ 6] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[12]) <<  0;
  l |= base64b_char2int (buf[13]) <<  6;
  l |= base64b_char2int (buf[14]) << 12;
  l |= base64b_char2int (buf[15]) << 18;

  digest[11] = (l >>  0) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[ 9] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[16]) <<  0;
  l |= base64b_char2int (buf[17]) <<  6;
  l |= base64b_char2int (buf[18]) << 12;
  l |= base64b_char2int (buf[19]) << 18;

  digest[14] = (l >>  0) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[12] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[20]) <<  0;
  l |= base64b_char2int (buf[21]) <<  6;
  l |= base64b_char2int (buf[22]) << 12;
  l |= base64b_char2int (buf[23]) << 18;

  digest[17] = (l >>  0) & 0xff;
  digest[16] = (l >>  8) & 0xff;
  digest[15] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[24]) <<  0;
  l |= base64b_char2int (buf[25]) <<  6;
  l |= base64b_char2int (buf[26]) << 12;

  digest[19] = (l >>  8) & 0xff;
  digest[18] = (l >> 16) & 0xff;
}

void sha1aix_encode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char buf[HASH_SIZE_SHA1AIX])
{
  int l;

  l = (digest[ 2] << 0) | (digest[ 1] << 8) | (digest[ 0] << 16);

  buf[ 0] = base64b_int2char (l); l >>= 6;
  buf[ 1] = base64b_int2char (l); l >>= 6;
  buf[ 2] = base64b_int2char (l); l >>= 6;
  buf[ 3] = base64b_int2char (l);

  l = (digest[ 5] << 0) | (digest[ 4] << 8) | (digest[ 3] << 16);

  buf[ 4] = base64b_int2char (l); l >>= 6;
  buf[ 5] = base64b_int2char (l); l >>= 6;
  buf[ 6] = base64b_int2char (l); l >>= 6;
  buf[ 7] = base64b_int2char (l);

  l = (digest[ 8] << 0) | (digest[ 7] << 8) | (digest[ 6] << 16);

  buf[ 8] = base64b_int2char (l); l >>= 6;
  buf[ 9] = base64b_int2char (l); l >>= 6;
  buf[10] = base64b_int2char (l); l >>= 6;
  buf[11] = base64b_int2char (l);

  l = (digest[11] << 0) | (digest[10] << 8) | (digest[ 9] << 16);

  buf[12] = base64b_int2char (l); l >>= 6;
  buf[13] = base64b_int2char (l); l >>= 6;
  buf[14] = base64b_int2char (l); l >>= 6;
  buf[15] = base64b_int2char (l);

  l = (digest[14] << 0) | (digest[13] << 8) | (digest[12] << 16);

  buf[16] = base64b_int2char (l); l >>= 6;
  buf[17] = base64b_int2char (l); l >>= 6;
  buf[18] = base64b_int2char (l); l >>= 6;
  buf[19] = base64b_int2char (l);

  l = (digest[17] << 0) | (digest[16] << 8) | (digest[15] << 16);

  buf[20] = base64b_int2char (l); l >>= 6;
  buf[21] = base64b_int2char (l); l >>= 6;
  buf[22] = base64b_int2char (l); l >>= 6;
  buf[23] = base64b_int2char (l);

  l =                 0 | (digest[19] << 8) | (digest[18] << 16);

  buf[24] = base64b_int2char (l); l >>= 6;
  buf[25] = base64b_int2char (l); l >>= 6;
  buf[26] = base64b_int2char (l);
}

void sha256aix_decode (unsigned char digest[DIGEST_SIZE_SHA256], unsigned char buf[HASH_SIZE_SHA256AIX])
{
  int l;

  l  = base64b_char2int (buf[ 0]) <<  0;
  l |= base64b_char2int (buf[ 1]) <<  6;
  l |= base64b_char2int (buf[ 2]) << 12;
  l |= base64b_char2int (buf[ 3]) << 18;

  digest[ 2] = (l >>  0) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[ 0] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[ 4]) <<  0;
  l |= base64b_char2int (buf[ 5]) <<  6;
  l |= base64b_char2int (buf[ 6]) << 12;
  l |= base64b_char2int (buf[ 7]) << 18;

  digest[ 5] = (l >>  0) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[ 3] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[ 8]) <<  0;
  l |= base64b_char2int (buf[ 9]) <<  6;
  l |= base64b_char2int (buf[10]) << 12;
  l |= base64b_char2int (buf[11]) << 18;

  digest[ 8] = (l >>  0) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[ 6] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[12]) <<  0;
  l |= base64b_char2int (buf[13]) <<  6;
  l |= base64b_char2int (buf[14]) << 12;
  l |= base64b_char2int (buf[15]) << 18;

  digest[11] = (l >>  0) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[ 9] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[16]) <<  0;
  l |= base64b_char2int (buf[17]) <<  6;
  l |= base64b_char2int (buf[18]) << 12;
  l |= base64b_char2int (buf[19]) << 18;

  digest[14] = (l >>  0) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[12] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[20]) <<  0;
  l |= base64b_char2int (buf[21]) <<  6;
  l |= base64b_char2int (buf[22]) << 12;
  l |= base64b_char2int (buf[23]) << 18;

  digest[17] = (l >>  0) & 0xff;
  digest[16] = (l >>  8) & 0xff;
  digest[15] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[24]) <<  0;
  l |= base64b_char2int (buf[25]) <<  6;
  l |= base64b_char2int (buf[26]) << 12;
  l |= base64b_char2int (buf[27]) << 18;

  digest[20] = (l >>  0) & 0xff;
  digest[19] = (l >>  8) & 0xff;
  digest[18] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[28]) <<  0;
  l |= base64b_char2int (buf[29]) <<  6;
  l |= base64b_char2int (buf[30]) << 12;
  l |= base64b_char2int (buf[31]) << 18;

  digest[23] = (l >>  0) & 0xff;
  digest[22] = (l >>  8) & 0xff;
  digest[21] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[32]) <<  0;
  l |= base64b_char2int (buf[33]) <<  6;
  l |= base64b_char2int (buf[34]) << 12;
  l |= base64b_char2int (buf[35]) << 18;

  digest[26] = (l >>  0) & 0xff;
  digest[25] = (l >>  8) & 0xff;
  digest[24] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[36]) <<  0;
  l |= base64b_char2int (buf[37]) <<  6;
  l |= base64b_char2int (buf[38]) << 12;
  l |= base64b_char2int (buf[39]) << 18;

  digest[29] = (l >>  0) & 0xff;
  digest[28] = (l >>  8) & 0xff;
  digest[27] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[40]) <<  0;
  l |= base64b_char2int (buf[41]) <<  6;
  l |= base64b_char2int (buf[42]) << 12;

  //digest[32] = (l >>  0) & 0xff;
  digest[31] = (l >>  8) & 0xff;
  digest[30] = (l >> 16) & 0xff;
}

void sha256aix_encode (unsigned char digest[DIGEST_SIZE_SHA256], unsigned char buf[HASH_SIZE_SHA256AIX])
{
  int l;

  l = (digest[ 2] << 0) | (digest[ 1] << 8) | (digest[ 0] << 16);

  buf[ 0] = base64b_int2char (l); l >>= 6;
  buf[ 1] = base64b_int2char (l); l >>= 6;
  buf[ 2] = base64b_int2char (l); l >>= 6;
  buf[ 3] = base64b_int2char (l);

  l = (digest[ 5] << 0) | (digest[ 4] << 8) | (digest[ 3] << 16);

  buf[ 4] = base64b_int2char (l); l >>= 6;
  buf[ 5] = base64b_int2char (l); l >>= 6;
  buf[ 6] = base64b_int2char (l); l >>= 6;
  buf[ 7] = base64b_int2char (l);

  l = (digest[ 8] << 0) | (digest[ 7] << 8) | (digest[ 6] << 16);

  buf[ 8] = base64b_int2char (l); l >>= 6;
  buf[ 9] = base64b_int2char (l); l >>= 6;
  buf[10] = base64b_int2char (l); l >>= 6;
  buf[11] = base64b_int2char (l);

  l = (digest[11] << 0) | (digest[10] << 8) | (digest[ 9] << 16);

  buf[12] = base64b_int2char (l); l >>= 6;
  buf[13] = base64b_int2char (l); l >>= 6;
  buf[14] = base64b_int2char (l); l >>= 6;
  buf[15] = base64b_int2char (l);

  l = (digest[14] << 0) | (digest[13] << 8) | (digest[12] << 16);

  buf[16] = base64b_int2char (l); l >>= 6;
  buf[17] = base64b_int2char (l); l >>= 6;
  buf[18] = base64b_int2char (l); l >>= 6;
  buf[19] = base64b_int2char (l);

  l = (digest[17] << 0) | (digest[16] << 8) | (digest[15] << 16);

  buf[20] = base64b_int2char (l); l >>= 6;
  buf[21] = base64b_int2char (l); l >>= 6;
  buf[22] = base64b_int2char (l); l >>= 6;
  buf[23] = base64b_int2char (l);

  l = (digest[20] << 0) | (digest[19] << 8) | (digest[18] << 16);

  buf[24] = base64b_int2char (l); l >>= 6;
  buf[25] = base64b_int2char (l); l >>= 6;
  buf[26] = base64b_int2char (l); l >>= 6;
  buf[27] = base64b_int2char (l);

  l = (digest[23] << 0) | (digest[22] << 8) | (digest[21] << 16);

  buf[28] = base64b_int2char (l); l >>= 6;
  buf[29] = base64b_int2char (l); l >>= 6;
  buf[30] = base64b_int2char (l); l >>= 6;
  buf[31] = base64b_int2char (l);

  l = (digest[26] << 0) | (digest[25] << 8) | (digest[24] << 16);

  buf[32] = base64b_int2char (l); l >>= 6;
  buf[33] = base64b_int2char (l); l >>= 6;
  buf[34] = base64b_int2char (l); l >>= 6;
  buf[35] = base64b_int2char (l);

  l = (digest[29] << 0) | (digest[28] << 8) | (digest[27] << 16);

  buf[36] = base64b_int2char (l); l >>= 6;
  buf[37] = base64b_int2char (l); l >>= 6;
  buf[38] = base64b_int2char (l); l >>= 6;
  buf[39] = base64b_int2char (l);

  l =                 0 | (digest[31] << 8) | (digest[30] << 16);

  buf[40] = base64b_int2char (l); l >>= 6;
  buf[41] = base64b_int2char (l); l >>= 6;
  buf[42] = base64b_int2char (l);
}

void sha512aix_decode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char buf[HASH_SIZE_SHA512AIX])
{
  int l;

  l  = base64b_char2int (buf[ 0]) <<  0;
  l |= base64b_char2int (buf[ 1]) <<  6;
  l |= base64b_char2int (buf[ 2]) << 12;
  l |= base64b_char2int (buf[ 3]) << 18;

  digest[ 2] = (l >>  0) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[ 0] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[ 4]) <<  0;
  l |= base64b_char2int (buf[ 5]) <<  6;
  l |= base64b_char2int (buf[ 6]) << 12;
  l |= base64b_char2int (buf[ 7]) << 18;

  digest[ 5] = (l >>  0) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[ 3] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[ 8]) <<  0;
  l |= base64b_char2int (buf[ 9]) <<  6;
  l |= base64b_char2int (buf[10]) << 12;
  l |= base64b_char2int (buf[11]) << 18;

  digest[ 8] = (l >>  0) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[ 6] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[12]) <<  0;
  l |= base64b_char2int (buf[13]) <<  6;
  l |= base64b_char2int (buf[14]) << 12;
  l |= base64b_char2int (buf[15]) << 18;

  digest[11] = (l >>  0) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[ 9] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[16]) <<  0;
  l |= base64b_char2int (buf[17]) <<  6;
  l |= base64b_char2int (buf[18]) << 12;
  l |= base64b_char2int (buf[19]) << 18;

  digest[14] = (l >>  0) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[12] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[20]) <<  0;
  l |= base64b_char2int (buf[21]) <<  6;
  l |= base64b_char2int (buf[22]) << 12;
  l |= base64b_char2int (buf[23]) << 18;

  digest[17] = (l >>  0) & 0xff;
  digest[16] = (l >>  8) & 0xff;
  digest[15] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[24]) <<  0;
  l |= base64b_char2int (buf[25]) <<  6;
  l |= base64b_char2int (buf[26]) << 12;
  l |= base64b_char2int (buf[27]) << 18;

  digest[20] = (l >>  0) & 0xff;
  digest[19] = (l >>  8) & 0xff;
  digest[18] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[28]) <<  0;
  l |= base64b_char2int (buf[29]) <<  6;
  l |= base64b_char2int (buf[30]) << 12;
  l |= base64b_char2int (buf[31]) << 18;

  digest[23] = (l >>  0) & 0xff;
  digest[22] = (l >>  8) & 0xff;
  digest[21] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[32]) <<  0;
  l |= base64b_char2int (buf[33]) <<  6;
  l |= base64b_char2int (buf[34]) << 12;
  l |= base64b_char2int (buf[35]) << 18;

  digest[26] = (l >>  0) & 0xff;
  digest[25] = (l >>  8) & 0xff;
  digest[24] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[36]) <<  0;
  l |= base64b_char2int (buf[37]) <<  6;
  l |= base64b_char2int (buf[38]) << 12;
  l |= base64b_char2int (buf[39]) << 18;

  digest[29] = (l >>  0) & 0xff;
  digest[28] = (l >>  8) & 0xff;
  digest[27] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[40]) <<  0;
  l |= base64b_char2int (buf[41]) <<  6;
  l |= base64b_char2int (buf[42]) << 12;
  l |= base64b_char2int (buf[43]) << 18;

  digest[32] = (l >>  0) & 0xff;
  digest[31] = (l >>  8) & 0xff;
  digest[30] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[44]) <<  0;
  l |= base64b_char2int (buf[45]) <<  6;
  l |= base64b_char2int (buf[46]) << 12;
  l |= base64b_char2int (buf[47]) << 18;

  digest[35] = (l >>  0) & 0xff;
  digest[34] = (l >>  8) & 0xff;
  digest[33] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[48]) <<  0;
  l |= base64b_char2int (buf[49]) <<  6;
  l |= base64b_char2int (buf[50]) << 12;
  l |= base64b_char2int (buf[51]) << 18;

  digest[38] = (l >>  0) & 0xff;
  digest[37] = (l >>  8) & 0xff;
  digest[36] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[52]) <<  0;
  l |= base64b_char2int (buf[53]) <<  6;
  l |= base64b_char2int (buf[54]) << 12;
  l |= base64b_char2int (buf[55]) << 18;

  digest[41] = (l >>  0) & 0xff;
  digest[40] = (l >>  8) & 0xff;
  digest[39] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[56]) <<  0;
  l |= base64b_char2int (buf[57]) <<  6;
  l |= base64b_char2int (buf[58]) << 12;
  l |= base64b_char2int (buf[59]) << 18;

  digest[44] = (l >>  0) & 0xff;
  digest[43] = (l >>  8) & 0xff;
  digest[42] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[60]) <<  0;
  l |= base64b_char2int (buf[61]) <<  6;
  l |= base64b_char2int (buf[62]) << 12;
  l |= base64b_char2int (buf[63]) << 18;

  digest[47] = (l >>  0) & 0xff;
  digest[46] = (l >>  8) & 0xff;
  digest[45] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[64]) <<  0;
  l |= base64b_char2int (buf[65]) <<  6;
  l |= base64b_char2int (buf[66]) << 12;
  l |= base64b_char2int (buf[67]) << 18;

  digest[50] = (l >>  0) & 0xff;
  digest[49] = (l >>  8) & 0xff;
  digest[48] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[68]) <<  0;
  l |= base64b_char2int (buf[69]) <<  6;
  l |= base64b_char2int (buf[70]) << 12;
  l |= base64b_char2int (buf[71]) << 18;

  digest[53] = (l >>  0) & 0xff;
  digest[52] = (l >>  8) & 0xff;
  digest[51] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[72]) <<  0;
  l |= base64b_char2int (buf[73]) <<  6;
  l |= base64b_char2int (buf[74]) << 12;
  l |= base64b_char2int (buf[75]) << 18;

  digest[56] = (l >>  0) & 0xff;
  digest[55] = (l >>  8) & 0xff;
  digest[54] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[76]) <<  0;
  l |= base64b_char2int (buf[77]) <<  6;
  l |= base64b_char2int (buf[78]) << 12;
  l |= base64b_char2int (buf[79]) << 18;

  digest[59] = (l >>  0) & 0xff;
  digest[58] = (l >>  8) & 0xff;
  digest[57] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[80]) <<  0;
  l |= base64b_char2int (buf[81]) <<  6;
  l |= base64b_char2int (buf[82]) << 12;
  l |= base64b_char2int (buf[83]) << 18;

  digest[62] = (l >>  0) & 0xff;
  digest[61] = (l >>  8) & 0xff;
  digest[60] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[84]) <<  0;
  l |= base64b_char2int (buf[85]) <<  6;

  digest[63] = (l >> 16) & 0xff;
}

void sha512aix_encode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char buf[HASH_SIZE_SHA512AIX])
{
  int l;

  l = (digest[ 2] << 0) | (digest[ 1] << 8) | (digest[ 0] << 16);

  buf[ 0] = base64b_int2char (l); l >>= 6;
  buf[ 1] = base64b_int2char (l); l >>= 6;
  buf[ 2] = base64b_int2char (l); l >>= 6;
  buf[ 3] = base64b_int2char (l);

  l = (digest[ 5] << 0) | (digest[ 4] << 8) | (digest[ 3] << 16);

  buf[ 4] = base64b_int2char (l); l >>= 6;
  buf[ 5] = base64b_int2char (l); l >>= 6;
  buf[ 6] = base64b_int2char (l); l >>= 6;
  buf[ 7] = base64b_int2char (l);

  l = (digest[ 8] << 0) | (digest[ 7] << 8) | (digest[ 6] << 16);

  buf[ 8] = base64b_int2char (l); l >>= 6;
  buf[ 9] = base64b_int2char (l); l >>= 6;
  buf[10] = base64b_int2char (l); l >>= 6;
  buf[11] = base64b_int2char (l);

  l = (digest[11] << 0) | (digest[10] << 8) | (digest[ 9] << 16);

  buf[12] = base64b_int2char (l); l >>= 6;
  buf[13] = base64b_int2char (l); l >>= 6;
  buf[14] = base64b_int2char (l); l >>= 6;
  buf[15] = base64b_int2char (l);

  l = (digest[14] << 0) | (digest[13] << 8) | (digest[12] << 16);

  buf[16] = base64b_int2char (l); l >>= 6;
  buf[17] = base64b_int2char (l); l >>= 6;
  buf[18] = base64b_int2char (l); l >>= 6;
  buf[19] = base64b_int2char (l);

  l = (digest[17] << 0) | (digest[16] << 8) | (digest[15] << 16);

  buf[20] = base64b_int2char (l); l >>= 6;
  buf[21] = base64b_int2char (l); l >>= 6;
  buf[22] = base64b_int2char (l); l >>= 6;
  buf[23] = base64b_int2char (l);

  l = (digest[20] << 0) | (digest[19] << 8) | (digest[18] << 16);

  buf[24] = base64b_int2char (l); l >>= 6;
  buf[25] = base64b_int2char (l); l >>= 6;
  buf[26] = base64b_int2char (l); l >>= 6;
  buf[27] = base64b_int2char (l);

  l = (digest[23] << 0) | (digest[22] << 8) | (digest[21] << 16);

  buf[28] = base64b_int2char (l); l >>= 6;
  buf[29] = base64b_int2char (l); l >>= 6;
  buf[30] = base64b_int2char (l); l >>= 6;
  buf[31] = base64b_int2char (l);

  l = (digest[26] << 0) | (digest[25] << 8) | (digest[24] << 16);

  buf[32] = base64b_int2char (l); l >>= 6;
  buf[33] = base64b_int2char (l); l >>= 6;
  buf[34] = base64b_int2char (l); l >>= 6;
  buf[35] = base64b_int2char (l);

  l = (digest[29] << 0) | (digest[28] << 8) | (digest[27] << 16);

  buf[36] = base64b_int2char (l); l >>= 6;
  buf[37] = base64b_int2char (l); l >>= 6;
  buf[38] = base64b_int2char (l); l >>= 6;
  buf[39] = base64b_int2char (l);

  l = (digest[32] << 0) | (digest[31] << 8) | (digest[30] << 16);

  buf[40] = base64b_int2char (l); l >>= 6;
  buf[41] = base64b_int2char (l); l >>= 6;
  buf[42] = base64b_int2char (l); l >>= 6;
  buf[43] = base64b_int2char (l);

  l = (digest[35] << 0) | (digest[34] << 8) | (digest[33] << 16);

  buf[44] = base64b_int2char (l); l >>= 6;
  buf[45] = base64b_int2char (l); l >>= 6;
  buf[46] = base64b_int2char (l); l >>= 6;
  buf[47] = base64b_int2char (l);

  l = (digest[38] << 0) | (digest[37] << 8) | (digest[36] << 16);

  buf[48] = base64b_int2char (l); l >>= 6;
  buf[49] = base64b_int2char (l); l >>= 6;
  buf[50] = base64b_int2char (l); l >>= 6;
  buf[51] = base64b_int2char (l);

  l = (digest[41] << 0) | (digest[40] << 8) | (digest[39] << 16);

  buf[52] = base64b_int2char (l); l >>= 6;
  buf[53] = base64b_int2char (l); l >>= 6;
  buf[54] = base64b_int2char (l); l >>= 6;
  buf[55] = base64b_int2char (l);

  l = (digest[44] << 0) | (digest[43] << 8) | (digest[42] << 16);

  buf[56] = base64b_int2char (l); l >>= 6;
  buf[57] = base64b_int2char (l); l >>= 6;
  buf[58] = base64b_int2char (l); l >>= 6;
  buf[59] = base64b_int2char (l);

  l = (digest[47] << 0) | (digest[46] << 8) | (digest[45] << 16);

  buf[60] = base64b_int2char (l); l >>= 6;
  buf[61] = base64b_int2char (l); l >>= 6;
  buf[62] = base64b_int2char (l); l >>= 6;
  buf[63] = base64b_int2char (l);

  l = (digest[50] << 0) | (digest[49] << 8) | (digest[48] << 16);

  buf[64] = base64b_int2char (l); l >>= 6;
  buf[65] = base64b_int2char (l); l >>= 6;
  buf[66] = base64b_int2char (l); l >>= 6;
  buf[67] = base64b_int2char (l);

  l = (digest[53] << 0) | (digest[52] << 8) | (digest[51] << 16);

  buf[68] = base64b_int2char (l); l >>= 6;
  buf[69] = base64b_int2char (l); l >>= 6;
  buf[70] = base64b_int2char (l); l >>= 6;
  buf[71] = base64b_int2char (l);

  l = (digest[56] << 0) | (digest[55] << 8) | (digest[54] << 16);

  buf[72] = base64b_int2char (l); l >>= 6;
  buf[73] = base64b_int2char (l); l >>= 6;
  buf[74] = base64b_int2char (l); l >>= 6;
  buf[75] = base64b_int2char (l);

  l = (digest[59] << 0) | (digest[58] << 8) | (digest[57] << 16);

  buf[76] = base64b_int2char (l); l >>= 6;
  buf[77] = base64b_int2char (l); l >>= 6;
  buf[78] = base64b_int2char (l); l >>= 6;
  buf[79] = base64b_int2char (l);

  l = (digest[62] << 0) | (digest[61] << 8) | (digest[60] << 16);

  buf[80] = base64b_int2char (l); l >>= 6;
  buf[81] = base64b_int2char (l); l >>= 6;
  buf[82] = base64b_int2char (l); l >>= 6;
  buf[83] = base64b_int2char (l);

  l =                 0 |                 0 | (digest[63] << 16);

  buf[84] = base64b_int2char (l); l >>= 6;
  buf[85] = base64b_int2char (l); l >>= 6;
}

void sha1fortigate_decode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char salt[BLOCK_SIZE], char *buf)
{
  char tmp_buf[SALT_SIZE_SHA1FORTIGATE + HASH_SIZE_SHA1];

  base64_decode (base64_to_int, buf, 44, tmp_buf);

  memcpy (salt, tmp_buf, SALT_SIZE_SHA1FORTIGATE);

  memcpy (digest, tmp_buf + SALT_SIZE_SHA1FORTIGATE, HASH_SIZE_SHA1);
}

void sha1fortigate_encode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char salt[BLOCK_SIZE], char *buf)
{
  char tmp_buf[SALT_SIZE_SHA1FORTIGATE + HASH_SIZE_SHA1FORTIGATE + 3];
  /* Salt */
  memcpy (tmp_buf, salt, SALT_SIZE_SHA1FORTIGATE);

  /* Digest */
  memcpy (tmp_buf + SALT_SIZE_SHA1FORTIGATE, digest, HASH_SIZE_SHA1FORTIGATE);

  memset (tmp_buf + SALT_SIZE_SHA1FORTIGATE + HASH_SIZE_SHA1FORTIGATE, 0, 3);

  base64_encode (int_to_base64, tmp_buf, SALT_SIZE_SHA1FORTIGATE + HASH_SIZE_SHA1FORTIGATE, buf);
}

void md5cisco_decode (char in_buf[HASH_SIZE_MD5CISCO], uint32_t out_buf[4])
{
  char *ptr_in = in_buf;

  uint32_t *ptr_out = out_buf;

  uint32_t j;

  for (j = 0; j < HASH_SIZE_MD5CISCO; j++)
  {
    *ptr_out += base64b_char2int (*ptr_in++);//<<  0
    *ptr_out += base64b_char2int (*ptr_in++)   <<  6;
    *ptr_out += base64b_char2int (*ptr_in++)   << 12;
    *ptr_out += base64b_char2int (*ptr_in++)   << 18;
    ptr_out += 1;
  }
}

void md5cisco_encode (uint32_t in_buf[4], unsigned char *out_buf)
{
  uint32_t *ptr_in = in_buf;

  unsigned char *ptr_out = out_buf;

  uint32_t j;

  for (j = 0; j < 4; j++)
  {
    *ptr_out++ = base64b_int2char (*ptr_in);//>>  0
    *ptr_out++ = base64b_int2char (*ptr_in    >>  6);
    *ptr_out++ = base64b_int2char (*ptr_in    >> 12);
    *ptr_out++ = base64b_int2char (*ptr_in    >> 18);
    ptr_in  += 1;
  }
}

void bcrypt_encode (char digest[DIGEST_SIZE_BCRYPT], char salt[16], char *bcrypt_str)
{
  base64_encode (int_to_bf64, salt, 16, bcrypt_str);
  base64_encode (int_to_bf64, digest, DIGEST_SIZE_BCRYPT, bcrypt_str + SALT_SIZE_MIN_BCRYPT);

  bcrypt_str[SALT_SIZE_MIN_BCRYPT + HASH_SIZE_BCRYPT] = 0;
}

void bcrypt_decode (char digest[DIGEST_SIZE_BCRYPT], char salt[16], char *hash_buf, char *salt_buf)
{
  base64_decode (bf64_to_int, salt_buf, SALT_SIZE_MIN_BCRYPT, salt);
  base64_decode (bf64_to_int, hash_buf, HASH_SIZE_BCRYPT, digest);
}

void sha256unix_decode (unsigned char digest[DIGEST_SIZE_SHA256], unsigned char buf[HASH_SIZE_SHA256UNIX])
{
  int l;

  l  = base64b_char2int (buf[ 0]) <<  0;
  l |= base64b_char2int (buf[ 1]) <<  6;
  l |= base64b_char2int (buf[ 2]) << 12;
  l |= base64b_char2int (buf[ 3]) << 18;

  digest[ 0] = (l >> 16) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[20] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[ 4]) <<  0;
  l |= base64b_char2int (buf[ 5]) <<  6;
  l |= base64b_char2int (buf[ 6]) << 12;
  l |= base64b_char2int (buf[ 7]) << 18;

  digest[21] = (l >> 16) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[11] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[ 8]) <<  0;
  l |= base64b_char2int (buf[ 9]) <<  6;
  l |= base64b_char2int (buf[10]) << 12;
  l |= base64b_char2int (buf[11]) << 18;

  digest[12] = (l >> 16) & 0xff;
  digest[22] = (l >>  8) & 0xff;
  digest[ 2] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[12]) <<  0;
  l |= base64b_char2int (buf[13]) <<  6;
  l |= base64b_char2int (buf[14]) << 12;
  l |= base64b_char2int (buf[15]) << 18;

  digest[ 3] = (l >> 16) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[23] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[16]) <<  0;
  l |= base64b_char2int (buf[17]) <<  6;
  l |= base64b_char2int (buf[18]) << 12;
  l |= base64b_char2int (buf[19]) << 18;

  digest[24] = (l >> 16) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[14] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[20]) <<  0;
  l |= base64b_char2int (buf[21]) <<  6;
  l |= base64b_char2int (buf[22]) << 12;
  l |= base64b_char2int (buf[23]) << 18;

  digest[15] = (l >> 16) & 0xff;
  digest[25] = (l >>  8) & 0xff;
  digest[ 5] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[24]) <<  0;
  l |= base64b_char2int (buf[25]) <<  6;
  l |= base64b_char2int (buf[26]) << 12;
  l |= base64b_char2int (buf[27]) << 18;

  digest[ 6] = (l >> 16) & 0xff;
  digest[16] = (l >>  8) & 0xff;
  digest[26] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[28]) <<  0;
  l |= base64b_char2int (buf[29]) <<  6;
  l |= base64b_char2int (buf[30]) << 12;
  l |= base64b_char2int (buf[31]) << 18;

  digest[27] = (l >> 16) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[17] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[32]) <<  0;
  l |= base64b_char2int (buf[33]) <<  6;
  l |= base64b_char2int (buf[34]) << 12;
  l |= base64b_char2int (buf[35]) << 18;

  digest[18] = (l >> 16) & 0xff;
  digest[28] = (l >>  8) & 0xff;
  digest[ 8] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[36]) <<  0;
  l |= base64b_char2int (buf[37]) <<  6;
  l |= base64b_char2int (buf[38]) << 12;
  l |= base64b_char2int (buf[39]) << 18;

  digest[ 9] = (l >> 16) & 0xff;
  digest[19] = (l >>  8) & 0xff;
  digest[29] = (l >>  0) & 0xff;

  l  = base64b_char2int (buf[40]) <<  0;
  l |= base64b_char2int (buf[41]) <<  6;
  l |= base64b_char2int (buf[42]) << 12;

 //digest[32] = (l >>  0) & 0xff;
  digest[31] = (l >>  8) & 0xff;
  digest[30] = (l >>  0) & 0xff;


}

void sha256unix_encode (unsigned char digest[DIGEST_SIZE_SHA256], unsigned char buf[HASH_SIZE_SHA256UNIX])
{
  int l;

  l = (digest[ 0] << 16) | (digest[10] << 8) | (digest[20] << 0);

  buf[ 0] = base64b_int2char (l); l >>= 6;
  buf[ 1] = base64b_int2char (l); l >>= 6;
  buf[ 2] = base64b_int2char (l); l >>= 6;
  buf[ 3] = base64b_int2char (l); l >>= 6;

  l = (digest[21] << 16) | (digest[ 1] << 8) | (digest[11] << 0);

  buf[ 4] = base64b_int2char (l); l >>= 6;
  buf[ 5] = base64b_int2char (l); l >>= 6;
  buf[ 6] = base64b_int2char (l); l >>= 6;
  buf[ 7] = base64b_int2char (l); l >>= 6;

  l = (digest[12] << 16) | (digest[22] << 8) | (digest[ 2] << 0);

  buf[ 8] = base64b_int2char (l); l >>= 6;
  buf[ 9] = base64b_int2char (l); l >>= 6;
  buf[10] = base64b_int2char (l); l >>= 6;
  buf[11] = base64b_int2char (l); l >>= 6;

  l = (digest[ 3] << 16) | (digest[13] << 8) | (digest[23] << 0);

  buf[12] = base64b_int2char (l); l >>= 6;
  buf[13] = base64b_int2char (l); l >>= 6;
  buf[14] = base64b_int2char (l); l >>= 6;
  buf[15] = base64b_int2char (l); l >>= 6;

  l = (digest[24] << 16) | (digest[ 4] << 8) | (digest[14] << 0);

  buf[16] = base64b_int2char (l); l >>= 6;
  buf[17] = base64b_int2char (l); l >>= 6;
  buf[18] = base64b_int2char (l); l >>= 6;
  buf[19] = base64b_int2char (l); l >>= 6;

  l = (digest[15] << 16) | (digest[25] << 8) | (digest[ 5] << 0);

  buf[20] = base64b_int2char (l); l >>= 6;
  buf[21] = base64b_int2char (l); l >>= 6;
  buf[22] = base64b_int2char (l); l >>= 6;
  buf[23] = base64b_int2char (l); l >>= 6;

  l = (digest[ 6] << 16) | (digest[16] << 8) | (digest[26] << 0);

  buf[24] = base64b_int2char (l); l >>= 6;
  buf[25] = base64b_int2char (l); l >>= 6;
  buf[26] = base64b_int2char (l); l >>= 6;
  buf[27] = base64b_int2char (l); l >>= 6;

  l = (digest[27] << 16) | (digest[ 7] << 8) | (digest[17] << 0);

  buf[28] = base64b_int2char (l); l >>= 6;
  buf[29] = base64b_int2char (l); l >>= 6;
  buf[30] = base64b_int2char (l); l >>= 6;
  buf[31] = base64b_int2char (l); l >>= 6;

  l = (digest[18] << 16) | (digest[28] << 8) | (digest[ 8] << 0);

  buf[32] = base64b_int2char (l); l >>= 6;
  buf[33] = base64b_int2char (l); l >>= 6;
  buf[34] = base64b_int2char (l); l >>= 6;
  buf[35] = base64b_int2char (l); l >>= 6;

  l = (digest[ 9] << 16) | (digest[19] << 8) | (digest[29] << 0);

  buf[36] = base64b_int2char (l); l >>= 6;
  buf[37] = base64b_int2char (l); l >>= 6;
  buf[38] = base64b_int2char (l); l >>= 6;
  buf[39] = base64b_int2char (l); l >>= 6;

  l =                  0 | (digest[31] << 8) | (digest[30] << 0);

  buf[40] = base64b_int2char (l); l >>= 6;
  buf[41] = base64b_int2char (l); l >>= 6;
  buf[42] = base64b_int2char (l);
}

void sha512b64s_decode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char salt[BLOCK_SIZE], uint32_t in_len, uint32_t *out_len, char *buf)
{
  char tmp_buf[in_len / 4 * 3];

  *out_len = base64_decode (base64_to_int, buf, in_len, tmp_buf);

  memcpy (digest, tmp_buf, 64);

  memcpy (salt, tmp_buf + 64, *out_len - 64);

  *out_len -= 64;
}

void sha512b64s_encode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char salt[BLOCK_SIZE], uint32_t salt_len, char *buf)
{
  char tmp_buf[64 + salt_len + 3];

  memcpy (tmp_buf, digest, 64);

  memcpy (tmp_buf + 64, salt, salt_len);

  memset (tmp_buf + 64 + salt_len, 0, 3);

  uint32_t out_len;

  out_len = base64_encode (int_to_base64, tmp_buf, 64 + salt_len, buf);

  buf[out_len + 1] = 0;
}

void drupal7_decode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char buf[HASH_SIZE_DRUPAL7])
{
  int l;

  l  = base64b_char2int (buf[ 0]) <<  0;
  l |= base64b_char2int (buf[ 1]) <<  6;
  l |= base64b_char2int (buf[ 2]) << 12;
  l |= base64b_char2int (buf[ 3]) << 18;

  digest[ 0] = (l >>  0) & 0xff;
  digest[ 1] = (l >>  8) & 0xff;
  digest[ 2] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[ 4]) <<  0;
  l |= base64b_char2int (buf[ 5]) <<  6;
  l |= base64b_char2int (buf[ 6]) << 12;
  l |= base64b_char2int (buf[ 7]) << 18;

  digest[ 3] = (l >>  0) & 0xff;
  digest[ 4] = (l >>  8) & 0xff;
  digest[ 5] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[ 8]) <<  0;
  l |= base64b_char2int (buf[ 9]) <<  6;
  l |= base64b_char2int (buf[10]) << 12;
  l |= base64b_char2int (buf[11]) << 18;

  digest[ 6] = (l >>  0) & 0xff;
  digest[ 7] = (l >>  8) & 0xff;
  digest[ 8] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[12]) <<  0;
  l |= base64b_char2int (buf[13]) <<  6;
  l |= base64b_char2int (buf[14]) << 12;
  l |= base64b_char2int (buf[15]) << 18;

  digest[ 9] = (l >>  0) & 0xff;
  digest[10] = (l >>  8) & 0xff;
  digest[11] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[16]) <<  0;
  l |= base64b_char2int (buf[17]) <<  6;
  l |= base64b_char2int (buf[18]) << 12;
  l |= base64b_char2int (buf[19]) << 18;

  digest[12] = (l >>  0) & 0xff;
  digest[13] = (l >>  8) & 0xff;
  digest[14] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[20]) <<  0;
  l |= base64b_char2int (buf[21]) <<  6;
  l |= base64b_char2int (buf[22]) << 12;
  l |= base64b_char2int (buf[23]) << 18;

  digest[15] = (l >>  0) & 0xff;
  digest[16] = (l >>  8) & 0xff;
  digest[17] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[24]) <<  0;
  l |= base64b_char2int (buf[25]) <<  6;
  l |= base64b_char2int (buf[26]) << 12;
  l |= base64b_char2int (buf[27]) << 18;

  digest[18] = (l >>  0) & 0xff;
  digest[19] = (l >>  8) & 0xff;
  digest[20] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[28]) <<  0;
  l |= base64b_char2int (buf[29]) <<  6;
  l |= base64b_char2int (buf[30]) << 12;
  l |= base64b_char2int (buf[31]) << 18;

  digest[21] = (l >>  0) & 0xff;
  digest[22] = (l >>  8) & 0xff;
  digest[23] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[32]) <<  0;
  l |= base64b_char2int (buf[33]) <<  6;
  l |= base64b_char2int (buf[34]) << 12;
  l |= base64b_char2int (buf[35]) << 18;

  digest[24] = (l >>  0) & 0xff;
  digest[25] = (l >>  8) & 0xff;
  digest[26] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[36]) <<  0;
  l |= base64b_char2int (buf[37]) <<  6;
  l |= base64b_char2int (buf[38]) << 12;
  l |= base64b_char2int (buf[39]) << 18;

  digest[27] = (l >>  0) & 0xff;
  digest[28] = (l >>  8) & 0xff;
  digest[29] = (l >> 16) & 0xff;

  l  = base64b_char2int (buf[40]) <<  0;
  l |= base64b_char2int (buf[41]) <<  6;
  l |= base64b_char2int (buf[42]) << 12;

  digest[30] = (l >>  0) & 0xff;
  digest[31] = (l >>  8) & 0xff;
}

void drupal7_encode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char buf[HASH_SIZE_DRUPAL7])
{
  int l;

  l = (digest[ 0] << 0) | (digest[ 1] << 8) | (digest[ 2] << 16);

  buf[ 0] = base64b_int2char (l); l >>= 6;
  buf[ 1] = base64b_int2char (l); l >>= 6;
  buf[ 2] = base64b_int2char (l); l >>= 6;
  buf[ 3] = base64b_int2char (l);

  l = (digest[ 3] << 0) | (digest[ 4] << 8) | (digest[ 5] << 16);

  buf[ 4] = base64b_int2char (l); l >>= 6;
  buf[ 5] = base64b_int2char (l); l >>= 6;
  buf[ 6] = base64b_int2char (l); l >>= 6;
  buf[ 7] = base64b_int2char (l);

  l = (digest[ 6] << 0) | (digest[ 7] << 8) | (digest[ 8] << 16);

  buf[ 8] = base64b_int2char (l); l >>= 6;
  buf[ 9] = base64b_int2char (l); l >>= 6;
  buf[10] = base64b_int2char (l); l >>= 6;
  buf[11] = base64b_int2char (l);

  l = (digest[ 9] << 0) | (digest[10] << 8) | (digest[11] << 16);

  buf[12] = base64b_int2char (l); l >>= 6;
  buf[13] = base64b_int2char (l); l >>= 6;
  buf[14] = base64b_int2char (l); l >>= 6;
  buf[15] = base64b_int2char (l);

  l = (digest[12] << 0) | (digest[13] << 8) | (digest[14] << 16);

  buf[16] = base64b_int2char (l); l >>= 6;
  buf[17] = base64b_int2char (l); l >>= 6;
  buf[18] = base64b_int2char (l); l >>= 6;
  buf[19] = base64b_int2char (l);

  l = (digest[15] << 0) | (digest[16] << 8) | (digest[17] << 16);

  buf[20] = base64b_int2char (l); l >>= 6;
  buf[21] = base64b_int2char (l); l >>= 6;
  buf[22] = base64b_int2char (l); l >>= 6;
  buf[23] = base64b_int2char (l);

  l = (digest[18] << 0) | (digest[19] << 8) | (digest[20] << 16);

  buf[24] = base64b_int2char (l); l >>= 6;
  buf[25] = base64b_int2char (l); l >>= 6;
  buf[26] = base64b_int2char (l); l >>= 6;
  buf[27] = base64b_int2char (l);

  l = (digest[21] << 0) | (digest[22] << 8) | (digest[23] << 16);

  buf[28] = base64b_int2char (l); l >>= 6;
  buf[29] = base64b_int2char (l); l >>= 6;
  buf[30] = base64b_int2char (l); l >>= 6;
  buf[31] = base64b_int2char (l);

  l = (digest[24] << 0) | (digest[25] << 8) | (digest[26] << 16);

  buf[32] = base64b_int2char (l); l >>= 6;
  buf[33] = base64b_int2char (l); l >>= 6;
  buf[34] = base64b_int2char (l); l >>= 6;
  buf[35] = base64b_int2char (l);

  l = (digest[27] << 0) | (digest[28] << 8) | (digest[29] << 16);

  buf[36] = base64b_int2char (l); l >>= 6;
  buf[37] = base64b_int2char (l); l >>= 6;
  buf[38] = base64b_int2char (l); l >>= 6;
  buf[39] = base64b_int2char (l);

  l = (digest[30] << 0) | (digest[31] << 8) | (digest[32] << 16);

  buf[40] = base64b_int2char (l); l >>= 6;
  buf[41] = base64b_int2char (l); l >>= 6;
  buf[42] = base64b_int2char (l);
}

/*
char hex_convert (char c)
{
  if ((c >= '0') && (c <= '9')) return (c - '0');
  if ((c >= 'A') && (c <= 'F')) return (c - 'A' + 10);
  if ((c >= 'a') && (c <= 'f')) return (c - 'a' + 10);

  return (-1);
}
*/

uint is_valid_hex_char (const char c)
{
  if ((c >= '0') && (c <= '9')) return 1;
  if ((c >= 'A') && (c <= 'F')) return 1;
  if ((c >= 'a') && (c <= 'f')) return 1;

  return 0;
}

char hex_convert (const char c)
{
  return (c & 15) + (c >> 6) * 9;
}

char hex_to_char (char hex[2])
{
  char v = 0;

  v |= (hex_convert (hex[1]) <<  0);
  v |= (hex_convert (hex[0]) <<  4);

  return (v);
}

uint32_t hex_to_uint (char hex[ 8])
{
  uint32_t v = 0;

  v |= ((uint32_t) hex_convert (hex[7]) <<  0);
  v |= ((uint32_t) hex_convert (hex[6]) <<  4);
  v |= ((uint32_t) hex_convert (hex[5]) <<  8);
  v |= ((uint32_t) hex_convert (hex[4]) << 12);
  v |= ((uint32_t) hex_convert (hex[3]) << 16);
  v |= ((uint32_t) hex_convert (hex[2]) << 20);
  v |= ((uint32_t) hex_convert (hex[1]) << 24);
  v |= ((uint32_t) hex_convert (hex[0]) << 28);

  return (v);
}

uint64_t hex_to_uint64 (char hex[16])
{
  uint64_t v = 0;

  v |= ((uint64_t) hex_convert (hex[15]) <<  0);
  v |= ((uint64_t) hex_convert (hex[14]) <<  4);
  v |= ((uint64_t) hex_convert (hex[13]) <<  8);
  v |= ((uint64_t) hex_convert (hex[12]) << 12);
  v |= ((uint64_t) hex_convert (hex[11]) << 16);
  v |= ((uint64_t) hex_convert (hex[10]) << 20);
  v |= ((uint64_t) hex_convert (hex[ 9]) << 24);
  v |= ((uint64_t) hex_convert (hex[ 8]) << 28);
  v |= ((uint64_t) hex_convert (hex[ 7]) << 32);
  v |= ((uint64_t) hex_convert (hex[ 6]) << 36);
  v |= ((uint64_t) hex_convert (hex[ 5]) << 40);
  v |= ((uint64_t) hex_convert (hex[ 4]) << 44);
  v |= ((uint64_t) hex_convert (hex[ 3]) << 48);
  v |= ((uint64_t) hex_convert (hex[ 2]) << 52);
  v |= ((uint64_t) hex_convert (hex[ 1]) << 56);
  v |= ((uint64_t) hex_convert (hex[ 0]) << 60);

  return (v);
}

void uint_to_hex_lower (uint32_t uint, char hex[8])
{
  hex[0] = uint >> 28 & 15;
  hex[1] = uint >> 24 & 15;
  hex[2] = uint >> 20 & 15;
  hex[3] = uint >> 16 & 15;
  hex[4] = uint >> 12 & 15;
  hex[5] = uint >>  8 & 15;
  hex[6] = uint >>  4 & 15;
  hex[7] = uint >>  0 & 15;

  uint32_t add;

  hex[0] += 6; add = ((hex[0] & 0x10) >> 4) * 39; hex[0] += 42 + add;
  hex[1] += 6; add = ((hex[1] & 0x10) >> 4) * 39; hex[1] += 42 + add;
  hex[2] += 6; add = ((hex[2] & 0x10) >> 4) * 39; hex[2] += 42 + add;
  hex[3] += 6; add = ((hex[3] & 0x10) >> 4) * 39; hex[3] += 42 + add;
  hex[4] += 6; add = ((hex[4] & 0x10) >> 4) * 39; hex[4] += 42 + add;
  hex[5] += 6; add = ((hex[5] & 0x10) >> 4) * 39; hex[5] += 42 + add;
  hex[6] += 6; add = ((hex[6] & 0x10) >> 4) * 39; hex[6] += 42 + add;
  hex[7] += 6; add = ((hex[7] & 0x10) >> 4) * 39; hex[7] += 42 + add;
}

void uint_to_hex_upper (uint32_t uint, char hex[8])
{
  hex[0] = uint >> 28 & 15;
  hex[1] = uint >> 24 & 15;
  hex[2] = uint >> 20 & 15;
  hex[3] = uint >> 16 & 15;
  hex[4] = uint >> 12 & 15;
  hex[5] = uint >>  8 & 15;
  hex[6] = uint >>  4 & 15;
  hex[7] = uint >>  0 & 15;

  uint32_t add;

  hex[0] += 6; add = ((hex[0] & 0x10) >> 4) * 7; hex[0] += 42 + add;
  hex[1] += 6; add = ((hex[1] & 0x10) >> 4) * 7; hex[1] += 42 + add;
  hex[2] += 6; add = ((hex[2] & 0x10) >> 4) * 7; hex[2] += 42 + add;
  hex[3] += 6; add = ((hex[3] & 0x10) >> 4) * 7; hex[3] += 42 + add;
  hex[4] += 6; add = ((hex[4] & 0x10) >> 4) * 7; hex[4] += 42 + add;
  hex[5] += 6; add = ((hex[5] & 0x10) >> 4) * 7; hex[5] += 42 + add;
  hex[6] += 6; add = ((hex[6] & 0x10) >> 4) * 7; hex[6] += 42 + add;
  hex[7] += 6; add = ((hex[7] & 0x10) >> 4) * 7; hex[7] += 42 + add;
}

void make_unicode (uint8_t *out, uint8_t *in, int size)
{
  while (size--)
  {
    *out++ = *in++;
    *out++ = 0;
  }
}

void make_unicode_upper (uint8_t *out, uint8_t *in, int size)
{
  while (size--)
  {
    *out++ = toupper (*in++);
    *out++ = 0;
  }
}

void plain_unicode (plain_t *in, plain_t *out)
{
  make_unicode (out[0].buf8, in[0].buf8, in[0].len);
  make_unicode (out[1].buf8, in[1].buf8, in[1].len);
  make_unicode (out[2].buf8, in[2].buf8, in[2].len);
  make_unicode (out[3].buf8, in[3].buf8, in[3].len);

  out[0].len = in[0].len * 2;
  out[1].len = in[1].len * 2;
  out[2].len = in[2].len * 2;
  out[3].len = in[3].len * 2;
}

void plain_unicode_and_upper (plain_t *in, plain_t *out)
{
  make_unicode_upper (out[0].buf8, in[0].buf8, in[0].len);
  make_unicode_upper (out[1].buf8, in[1].buf8, in[1].len);
  make_unicode_upper (out[2].buf8, in[2].buf8, in[2].len);
  make_unicode_upper (out[3].buf8, in[3].buf8, in[3].len);

  out[0].len = in[0].len * 2;
  out[1].len = in[1].len * 2;
  out[2].len = in[2].len * 2;
  out[3].len = in[3].len * 2;
}

// full featured

void md4_init_sse2 (digest_md4_sse2_t *digests)
{
  uint32_t *ptr = digests->buf32;

  *ptr++ = MD4M_A;
  *ptr++ = MD4M_A;
  *ptr++ = MD4M_A;
  *ptr++ = MD4M_A;
  *ptr++ = MD4M_B;
  *ptr++ = MD4M_B;
  *ptr++ = MD4M_B;
  *ptr++ = MD4M_B;
  *ptr++ = MD4M_C;
  *ptr++ = MD4M_C;
  *ptr++ = MD4M_C;
  *ptr++ = MD4M_C;
  *ptr++ = MD4M_D;
  *ptr++ = MD4M_D;
  *ptr++ = MD4M_D;
  *ptr   = MD4M_D;
}

void md5_init_sse2 (digest_md5_sse2_t *digests)
{
  uint32_t *ptr = digests->buf32;

  *ptr++ = MD5M_A;
  *ptr++ = MD5M_A;
  *ptr++ = MD5M_A;
  *ptr++ = MD5M_A;
  *ptr++ = MD5M_B;
  *ptr++ = MD5M_B;
  *ptr++ = MD5M_B;
  *ptr++ = MD5M_B;
  *ptr++ = MD5M_C;
  *ptr++ = MD5M_C;
  *ptr++ = MD5M_C;
  *ptr++ = MD5M_C;
  *ptr++ = MD5M_D;
  *ptr++ = MD5M_D;
  *ptr++ = MD5M_D;
  *ptr   = MD5M_D;
}

void sha1_init_sse2 (digest_sha1_sse2_t *digests)
{
  uint32_t *ptr = digests->buf32;

  *ptr++ = SHA1M_A;
  *ptr++ = SHA1M_A;
  *ptr++ = SHA1M_A;
  *ptr++ = SHA1M_A;
  *ptr++ = SHA1M_B;
  *ptr++ = SHA1M_B;
  *ptr++ = SHA1M_B;
  *ptr++ = SHA1M_B;
  *ptr++ = SHA1M_C;
  *ptr++ = SHA1M_C;
  *ptr++ = SHA1M_C;
  *ptr++ = SHA1M_C;
  *ptr++ = SHA1M_D;
  *ptr++ = SHA1M_D;
  *ptr++ = SHA1M_D;
  *ptr++ = SHA1M_D;
  *ptr++ = SHA1M_E;
  *ptr++ = SHA1M_E;
  *ptr++ = SHA1M_E;
  *ptr   = SHA1M_E;
}

void sha256_init_sse2 (digest_sha256_sse2_t *digests)
{
  uint32_t *ptr = digests->buf32;

  *ptr++ = SHA256M_A;
  *ptr++ = SHA256M_A;
  *ptr++ = SHA256M_A;
  *ptr++ = SHA256M_A;
  *ptr++ = SHA256M_B;
  *ptr++ = SHA256M_B;
  *ptr++ = SHA256M_B;
  *ptr++ = SHA256M_B;
  *ptr++ = SHA256M_C;
  *ptr++ = SHA256M_C;
  *ptr++ = SHA256M_C;
  *ptr++ = SHA256M_C;
  *ptr++ = SHA256M_D;
  *ptr++ = SHA256M_D;
  *ptr++ = SHA256M_D;
  *ptr++ = SHA256M_D;
  *ptr++ = SHA256M_E;
  *ptr++ = SHA256M_E;
  *ptr++ = SHA256M_E;
  *ptr++ = SHA256M_E;
  *ptr++ = SHA256M_F;
  *ptr++ = SHA256M_F;
  *ptr++ = SHA256M_F;
  *ptr++ = SHA256M_F;
  *ptr++ = SHA256M_G;
  *ptr++ = SHA256M_G;
  *ptr++ = SHA256M_G;
  *ptr++ = SHA256M_G;
  *ptr++ = SHA256M_H;
  *ptr++ = SHA256M_H;
  *ptr++ = SHA256M_H;
  *ptr   = SHA256M_H;
}

void sha512_init_sse2 (digest_sha512_sse2_t *digests)
{
  uint64_t *ptr = digests->buf64;

  *ptr++ = SHA512M_A;
  *ptr++ = SHA512M_A;
  *ptr++ = SHA512M_A;
  *ptr++ = SHA512M_A;
  *ptr++ = SHA512M_B;
  *ptr++ = SHA512M_B;
  *ptr++ = SHA512M_B;
  *ptr++ = SHA512M_B;
  *ptr++ = SHA512M_C;
  *ptr++ = SHA512M_C;
  *ptr++ = SHA512M_C;
  *ptr++ = SHA512M_C;
  *ptr++ = SHA512M_D;
  *ptr++ = SHA512M_D;
  *ptr++ = SHA512M_D;
  *ptr++ = SHA512M_D;
  *ptr++ = SHA512M_E;
  *ptr++ = SHA512M_E;
  *ptr++ = SHA512M_E;
  *ptr++ = SHA512M_E;
  *ptr++ = SHA512M_F;
  *ptr++ = SHA512M_F;
  *ptr++ = SHA512M_F;
  *ptr++ = SHA512M_F;
  *ptr++ = SHA512M_G;
  *ptr++ = SHA512M_G;
  *ptr++ = SHA512M_G;
  *ptr++ = SHA512M_G;
  *ptr++ = SHA512M_H;
  *ptr++ = SHA512M_H;
  *ptr++ = SHA512M_H;
  *ptr   = SHA512M_H;
}

void md4_update_sse2 (plain_t *plains_dst, digest_md4_sse2_t *digests, plain_t *plains_src)
{
  uint8_t *buf[4];

  buf[0] = plains_src[0].buf8;
  buf[1] = plains_src[1].buf8;
  buf[2] = plains_src[2].buf8;
  buf[3] = plains_src[3].buf8;

  int len[4];

  len[0] = plains_src[0].len;
  len[1] = plains_src[1].len;
  len[2] = plains_src[2].len;
  len[3] = plains_src[3].len;

  int left[4];

  left[0] = plains_dst[0].len & 0x3f;
  left[1] = plains_dst[1].len & 0x3f;
  left[2] = plains_dst[2].len & 0x3f;
  left[3] = plains_dst[3].len & 0x3f;

  int need_update = 0;

  plains_dst[0].len += len[0];
  plains_dst[1].len += len[1];
  plains_dst[2].len += len[2];
  plains_dst[3].len += len[3];

  int i;

  for (i = 0; i < 4; i++)
  {
    if ((left[i] + len[i]) < 64)
    {
      memcpy (plains_dst[i].buf8 + left[i], buf[i], len[i]);

      continue;
    }

    memcpy (plains_dst[i].buf8 + left[i], buf[i], 64 - left[i]);

    need_update |= 1 << i;
  }

  if (need_update == 0) return;

  // this is to not modify digests that do not require a transform
  // otherwise we will copy the tmp digests to the actual digests later

  digest_md4_sse2_t digests_tmp;

  memcpy (&digests_tmp, digests, sizeof (digest_md4_sse2_t));

  md4_transform (plains_dst, &digests_tmp);

  // usually a while () whould come next to iterate through the entire input buffer space
  // but in our case not since we can guarantee input buffer had just a maximum length of 64

  for (i = 0; i < 4; i++)
  {
    if (need_update & (1 << i))
    {
      digests->buf32[i +  0] = digests_tmp.buf32[i +  0];
      digests->buf32[i +  4] = digests_tmp.buf32[i +  4];
      digests->buf32[i +  8] = digests_tmp.buf32[i +  8];
      digests->buf32[i + 12] = digests_tmp.buf32[i + 12];

      buf[i] += 64 - left[i];
      len[i] -= 64 - left[i];

      memcpy (plains_dst[i].buf8, buf[i], len[i]);
    }
  }
}

void md5_update_sse2 (plain_t *plains_dst, digest_md5_sse2_t *digests, plain_t *plains_src)
{
  uint8_t *buf[4];

  buf[0] = plains_src[0].buf8;
  buf[1] = plains_src[1].buf8;
  buf[2] = plains_src[2].buf8;
  buf[3] = plains_src[3].buf8;

  int len[4];

  len[0] = plains_src[0].len;
  len[1] = plains_src[1].len;
  len[2] = plains_src[2].len;
  len[3] = plains_src[3].len;

  int left[4];

  left[0] = plains_dst[0].len & 0x3f;
  left[1] = plains_dst[1].len & 0x3f;
  left[2] = plains_dst[2].len & 0x3f;
  left[3] = plains_dst[3].len & 0x3f;

  int need_update = 0;

  plains_dst[0].len += len[0];
  plains_dst[1].len += len[1];
  plains_dst[2].len += len[2];
  plains_dst[3].len += len[3];

  int i;

  for (i = 0; i < 4; i++)
  {
    if ((left[i] + len[i]) < 64)
    {
      memcpy (plains_dst[i].buf8 + left[i], buf[i], len[i]);

      continue;
    }

    memcpy (plains_dst[i].buf8 + left[i], buf[i], 64 - left[i]);

    need_update |= 1 << i;
  }

  if (need_update == 0) return;

  // this is to not modify digests that do not require a transform
  // otherwise we will copy the tmp digests to the actual digests later

  digest_md5_sse2_t digests_tmp;

  memcpy (&digests_tmp, digests, sizeof (digest_md5_sse2_t));

  md5_transform (plains_dst, &digests_tmp);

  // usually a while () whould come next to iterate through the entire input buffer space
  // but in our case not since we can guarantee input buffer had just a maximum length of 64

  for (i = 0; i < 4; i++)
  {
    if (need_update & (1 << i))
    {
      digests->buf32[i +  0] = digests_tmp.buf32[i +  0];
      digests->buf32[i +  4] = digests_tmp.buf32[i +  4];
      digests->buf32[i +  8] = digests_tmp.buf32[i +  8];
      digests->buf32[i + 12] = digests_tmp.buf32[i + 12];

      buf[i] += 64 - left[i];
      len[i] -= 64 - left[i];

      memcpy (plains_dst[i].buf8, buf[i], len[i]);
    }
  }
}

void sha1_update_sse2 (plain_t *plains_dst, digest_sha1_sse2_t *digests, plain_t *plains_src)
{
  uint8_t *buf[4];

  buf[0] = plains_src[0].buf8;
  buf[1] = plains_src[1].buf8;
  buf[2] = plains_src[2].buf8;
  buf[3] = plains_src[3].buf8;

  int len[4];

  len[0] = plains_src[0].len;
  len[1] = plains_src[1].len;
  len[2] = plains_src[2].len;
  len[3] = plains_src[3].len;

  int left[4];

  left[0] = plains_dst[0].len & 0x3f;
  left[1] = plains_dst[1].len & 0x3f;
  left[2] = plains_dst[2].len & 0x3f;
  left[3] = plains_dst[3].len & 0x3f;

  int need_update = 0;

  plains_dst[0].len += len[0];
  plains_dst[1].len += len[1];
  plains_dst[2].len += len[2];
  plains_dst[3].len += len[3];

  int i;

  for (i = 0; i < 4; i++)
  {
    if ((left[i] + len[i]) < 64)
    {
      memcpy (plains_dst[i].buf8 + left[i], buf[i], len[i]);

      continue;
    }

    memcpy (plains_dst[i].buf8 + left[i], buf[i], 64 - left[i]);

    need_update |= 1 << i;
  }

  if (need_update == 0) return;

  // this is to not modify digests that do not require a transform
  // otherwise we will copy the tmp digests to the actual digests later

  digest_sha1_sse2_t digests_tmp;

  memcpy (&digests_tmp, digests, sizeof (digest_sha1_sse2_t));

  sha1_transform (plains_dst, &digests_tmp);

  // usually a while () whould come next to iterate through the entire input buffer space
  // but in our case not since we can guarantee input buffer had just a maximum length of 64

  for (i = 0; i < 4; i++)
  {
    if (need_update & (1 << i))
    {
      digests->buf32[i +  0] = digests_tmp.buf32[i +  0];
      digests->buf32[i +  4] = digests_tmp.buf32[i +  4];
      digests->buf32[i +  8] = digests_tmp.buf32[i +  8];
      digests->buf32[i + 12] = digests_tmp.buf32[i + 12];
      digests->buf32[i + 16] = digests_tmp.buf32[i + 16];

      buf[i] += 64 - left[i];
      len[i] -= 64 - left[i];

      memcpy (plains_dst[i].buf8, buf[i], len[i]);
    }
  }
}

void sha256_update_sse2 (plain_t *plains_dst, digest_sha256_sse2_t *digests, plain_t *plains_src)
{
  uint8_t *buf[4];

  buf[0] = plains_src[0].buf8;
  buf[1] = plains_src[1].buf8;
  buf[2] = plains_src[2].buf8;
  buf[3] = plains_src[3].buf8;

  int len[4];

  len[0] = plains_src[0].len;
  len[1] = plains_src[1].len;
  len[2] = plains_src[2].len;
  len[3] = plains_src[3].len;

  int left[4];

  left[0] = plains_dst[0].len & 0x3f;
  left[1] = plains_dst[1].len & 0x3f;
  left[2] = plains_dst[2].len & 0x3f;
  left[3] = plains_dst[3].len & 0x3f;

  int need_update = 0;

  plains_dst[0].len += len[0];
  plains_dst[1].len += len[1];
  plains_dst[2].len += len[2];
  plains_dst[3].len += len[3];

  int i;

  for (i = 0; i < 4; i++)
  {
    if ((left[i] + len[i]) < 64)
    {
      memcpy (plains_dst[i].buf8 + left[i], buf[i], len[i]);

      continue;
    }

    memcpy (plains_dst[i].buf8 + left[i], buf[i], 64 - left[i]);

    need_update |= 1 << i;
  }

  if (need_update == 0) return;

  // this is to not modify digests that do not require a transform
  // otherwise we will copy the tmp digests to the actual digests later

  digest_sha256_sse2_t digests_tmp;

  memcpy (&digests_tmp, digests, sizeof (digest_sha256_sse2_t));

  sha256_transform (plains_dst, &digests_tmp);

  // usually a while () whould come next to iterate through the entire input buffer space
  // but in our case not since we can guarantee input buffer had just a maximum length of 64

  for (i = 0; i < 4; i++)
  {
    if (need_update & (1 << i))
    {
      digests->buf32[i +  0] = digests_tmp.buf32[i +  0];
      digests->buf32[i +  4] = digests_tmp.buf32[i +  4];
      digests->buf32[i +  8] = digests_tmp.buf32[i +  8];
      digests->buf32[i + 12] = digests_tmp.buf32[i + 12];
      digests->buf32[i + 16] = digests_tmp.buf32[i + 16];
      digests->buf32[i + 20] = digests_tmp.buf32[i + 20];
      digests->buf32[i + 24] = digests_tmp.buf32[i + 24];
      digests->buf32[i + 28] = digests_tmp.buf32[i + 28];

      buf[i] += 64 - left[i];
      len[i] -= 64 - left[i];

      memcpy (plains_dst[i].buf8, buf[i], len[i]);
    }
  }
}

void sha512_update_sse2 (plain_t *plains_dst, digest_sha512_sse2_t *digests, plain_t *plains_src)
{
  uint8_t *buf[4];

  buf[0] = plains_src[0].buf8;
  buf[1] = plains_src[1].buf8;
  buf[2] = plains_src[2].buf8;
  buf[3] = plains_src[3].buf8;

  int len[4];

  len[0] = plains_src[0].len;
  len[1] = plains_src[1].len;
  len[2] = plains_src[2].len;
  len[3] = plains_src[3].len;

  int left[4];

  left[0] = plains_dst[0].len & 0x7f;
  left[1] = plains_dst[1].len & 0x7f;
  left[2] = plains_dst[2].len & 0x7f;
  left[3] = plains_dst[3].len & 0x7f;

  int need_update = 0;

  plains_dst[0].len += len[0];
  plains_dst[1].len += len[1];
  plains_dst[2].len += len[2];
  plains_dst[3].len += len[3];

  int i;

  for (i = 0; i < 4; i++)
  {
    if ((left[i] + len[i]) < 128)
    {
      memcpy (plains_dst[i].buf8 + left[i], buf[i], len[i]);

      continue;
    }

    memcpy (plains_dst[i].buf8 + left[i], buf[i], 128 - left[i]);

    need_update |= 1 << i;
  }

  if (need_update == 0) return;

  // this is to not modify digests that do not require a transform
  // otherwise we will copy the tmp digests to the actual digests later

  digest_sha512_sse2_t digests_tmp;

  memcpy (&digests_tmp, digests, sizeof (digest_sha512_sse2_t));

  sha512_transform (plains_dst, &digests_tmp);

  // usually a while () whould come next to iterate through the entire input buffer space
  // but in our case not since we can guarantee input buffer had just a maximum length of 128

  for (i = 0; i < 4; i++)
  {
    if (need_update & (1 << i))
    {
      digests->buf64[i +  0] = digests_tmp.buf64[i +  0];
      digests->buf64[i +  4] = digests_tmp.buf64[i +  4];
      digests->buf64[i +  8] = digests_tmp.buf64[i +  8];
      digests->buf64[i + 12] = digests_tmp.buf64[i + 12];
      digests->buf64[i + 16] = digests_tmp.buf64[i + 16];
      digests->buf64[i + 20] = digests_tmp.buf64[i + 20];
      digests->buf64[i + 24] = digests_tmp.buf64[i + 24];
      digests->buf64[i + 28] = digests_tmp.buf64[i + 28];

      buf[i] += 128 - left[i];
      len[i] -= 128 - left[i];

      memcpy (plains_dst[i].buf8, buf[i], len[i]);
    }
  }
}

void md4_final_sse2 (plain_t *plains, digest_md4_sse2_t *digests)
{
  uint8_t *buf[4];

  buf[0] = plains[0].buf8;
  buf[1] = plains[1].buf8;
  buf[2] = plains[2].buf8;
  buf[3] = plains[3].buf8;

  int len[4];

  len[0] = plains[0].len;
  len[1] = plains[1].len;
  len[2] = plains[2].len;
  len[3] = plains[3].len;

  int left[4];

  left[0] = len[0] & 0x3f;
  left[1] = len[1] & 0x3f;
  left[2] = len[2] & 0x3f;
  left[3] = len[3] & 0x3f;

  int need_update = 0;

  int i;

  for (i = 0; i < 4; i++)
  {
    memset (buf[i] + left[i], 0, 64 - left[i]);

    buf[i][left[i]] = 0x80;

    if (left[i] < 56)
    {
      plains[i].buf[14] = len[i] * 8;
      plains[i].buf[15] = 0;

      continue;
    }

    need_update |= 1 << i;
  }

  if (need_update)
  {
    digest_md4_sse2_t digests_tmp;

    memcpy (&digests_tmp, digests, sizeof (digest_md4_sse2_t));

    md4_transform (plains, &digests_tmp);

    for (i = 0; i < 4; i++)
    {
      if (need_update & (1 << i))
      {
        digests->buf32[i +  0] = digests_tmp.buf32[i +  0];
        digests->buf32[i +  4] = digests_tmp.buf32[i +  4];
        digests->buf32[i +  8] = digests_tmp.buf32[i +  8];
        digests->buf32[i + 12] = digests_tmp.buf32[i + 12];

        memset (buf[i], 0, 64);

        plains[i].buf[14] = len[i] * 8;
      }
    }
  }

  md4_transform (plains, digests);
}

void md5_final_sse2 (plain_t *plains, digest_md5_sse2_t *digests)
{
  uint8_t *buf[4];

  buf[0] = plains[0].buf8;
  buf[1] = plains[1].buf8;
  buf[2] = plains[2].buf8;
  buf[3] = plains[3].buf8;

  int len[4];

  len[0] = plains[0].len;
  len[1] = plains[1].len;
  len[2] = plains[2].len;
  len[3] = plains[3].len;

  int left[4];

  left[0] = len[0] & 0x3f;
  left[1] = len[1] & 0x3f;
  left[2] = len[2] & 0x3f;
  left[3] = len[3] & 0x3f;

  int need_update = 0;

  int i;

  for (i = 0; i < 4; i++)
  {
    memset (buf[i] + left[i], 0, 64 - left[i]);

    buf[i][left[i]] = 0x80;

    if (left[i] < 56)
    {
      plains[i].buf[14] = len[i] * 8;
      plains[i].buf[15] = 0;

      continue;
    }

    need_update |= 1 << i;
  }

  if (need_update)
  {
    digest_md5_sse2_t digests_tmp;

    memcpy (&digests_tmp, digests, sizeof (digest_md5_sse2_t));

    md5_transform (plains, &digests_tmp);

    for (i = 0; i < 4; i++)
    {
      if (need_update & (1 << i))
      {
        digests->buf32[i +  0] = digests_tmp.buf32[i +  0];
        digests->buf32[i +  4] = digests_tmp.buf32[i +  4];
        digests->buf32[i +  8] = digests_tmp.buf32[i +  8];
        digests->buf32[i + 12] = digests_tmp.buf32[i + 12];

        memset (buf[i], 0, 64);

        plains[i].buf[14] = len[i] * 8;
      }
    }
  }

  md5_transform (plains, digests);
}

void sha1_final_sse2 (plain_t *plains, digest_sha1_sse2_t *digests)
{
  uint8_t *buf[4];

  buf[0] = plains[0].buf8;
  buf[1] = plains[1].buf8;
  buf[2] = plains[2].buf8;
  buf[3] = plains[3].buf8;

  int len[4];

  len[0] = plains[0].len;
  len[1] = plains[1].len;
  len[2] = plains[2].len;
  len[3] = plains[3].len;

  int left[4];

  left[0] = len[0] & 0x3f;
  left[1] = len[1] & 0x3f;
  left[2] = len[2] & 0x3f;
  left[3] = len[3] & 0x3f;

  int need_update = 0;

  int i;

  for (i = 0; i < 4; i++)
  {
    memset (buf[i] + left[i], 0, 64 - left[i]);

    buf[i][left[i]] = 0x80;

    if (left[i] < 56)
    {
      plains[i].buf[14] = 0;
      plains[i].buf[15] = len[i] * 8;

      BYTESWAP (plains[i].buf[15]);

      continue;
    }

    need_update |= 1 << i;
  }

  if (need_update)
  {
    digest_sha1_sse2_t digests_tmp;

    memcpy (&digests_tmp, digests, sizeof (digest_sha1_sse2_t));

    sha1_transform (plains, &digests_tmp);

    for (i = 0; i < 4; i++)
    {
      if (need_update & (1 << i))
      {
        digests->buf32[i +  0] = digests_tmp.buf32[i +  0];
        digests->buf32[i +  4] = digests_tmp.buf32[i +  4];
        digests->buf32[i +  8] = digests_tmp.buf32[i +  8];
        digests->buf32[i + 12] = digests_tmp.buf32[i + 12];
        digests->buf32[i + 16] = digests_tmp.buf32[i + 16];

        memset (buf[i], 0, 64);

        plains[i].buf[15] = len[i] * 8;

        BYTESWAP (plains[i].buf[15]);
      }
    }
  }

  sha1_transform (plains, digests);
}

void sha256_final_sse2 (plain_t *plains, digest_sha256_sse2_t *digests)
{
  uint8_t *buf[4];

  buf[0] = plains[0].buf8;
  buf[1] = plains[1].buf8;
  buf[2] = plains[2].buf8;
  buf[3] = plains[3].buf8;

  int len[4];

  len[0] = plains[0].len;
  len[1] = plains[1].len;
  len[2] = plains[2].len;
  len[3] = plains[3].len;

  int left[4];

  left[0] = len[0] & 0x3f;
  left[1] = len[1] & 0x3f;
  left[2] = len[2] & 0x3f;
  left[3] = len[3] & 0x3f;

  int need_update = 0;

  int i;

  for (i = 0; i < 4; i++)
  {
    memset (buf[i] + left[i], 0, 64 - left[i]);

    buf[i][left[i]] = 0x80;

    if (left[i] < 56)
    {
      plains[i].buf[14] = 0;
      plains[i].buf[15] = len[i] * 8;

      BYTESWAP (plains[i].buf[15]);

      continue;
    }

    need_update |= 1 << i;
  }

  if (need_update)
  {
    digest_sha256_sse2_t digests_tmp;

    memcpy (&digests_tmp, digests, sizeof (digest_sha256_sse2_t));

    sha256_transform (plains, &digests_tmp);

    for (i = 0; i < 4; i++)
    {
      if (need_update & (1 << i))
      {
        digests->buf32[i +  0] = digests_tmp.buf32[i +  0];
        digests->buf32[i +  4] = digests_tmp.buf32[i +  4];
        digests->buf32[i +  8] = digests_tmp.buf32[i +  8];
        digests->buf32[i + 12] = digests_tmp.buf32[i + 12];
        digests->buf32[i + 16] = digests_tmp.buf32[i + 16];
        digests->buf32[i + 20] = digests_tmp.buf32[i + 20];
        digests->buf32[i + 24] = digests_tmp.buf32[i + 24];
        digests->buf32[i + 28] = digests_tmp.buf32[i + 28];

        memset (buf[i], 0, 64);

        plains[i].buf[15] = len[i] * 8;

        BYTESWAP (plains[i].buf[15]);
      }
    }
  }

  sha256_transform (plains, digests);
}

void sha256_init (hc_sha256_ctx *ctx)
{
  ctx->state[0] = SHA256M_A;
  ctx->state[1] = SHA256M_B;
  ctx->state[2] = SHA256M_C;
  ctx->state[3] = SHA256M_D;
  ctx->state[4] = SHA256M_E;
  ctx->state[5] = SHA256M_F;
  ctx->state[6] = SHA256M_G;
  ctx->state[7] = SHA256M_H;

  ctx->len = 0;
}

void sha256_update (hc_sha256_ctx *ctx, const char *buf, int len)
{
  int left = ctx->len & 0x3f;

  ctx->len += len;

  if (left + len < 64)
  {
    memcpy (ctx->buf + left, buf, len);

    return;
  }

  memcpy (ctx->buf + left, buf, 64 - left);

  BYTESWAP (ctx->w[ 0]);
  BYTESWAP (ctx->w[ 1]);
  BYTESWAP (ctx->w[ 2]);
  BYTESWAP (ctx->w[ 3]);
  BYTESWAP (ctx->w[ 4]);
  BYTESWAP (ctx->w[ 5]);
  BYTESWAP (ctx->w[ 6]);
  BYTESWAP (ctx->w[ 7]);
  BYTESWAP (ctx->w[ 8]);
  BYTESWAP (ctx->w[ 9]);
  BYTESWAP (ctx->w[10]);
  BYTESWAP (ctx->w[11]);
  BYTESWAP (ctx->w[12]);
  BYTESWAP (ctx->w[13]);
  BYTESWAP (ctx->w[14]);
  BYTESWAP (ctx->w[15]);

  hashcat_sha256 (ctx->state, ctx->w);

  buf += 64 - left;
  len -= 64 - left;

  while (len >= 64)
  {

    memcpy (ctx->buf, buf, 64);

    BYTESWAP (ctx->w[ 0]);
    BYTESWAP (ctx->w[ 1]);
    BYTESWAP (ctx->w[ 2]);
    BYTESWAP (ctx->w[ 3]);
    BYTESWAP (ctx->w[ 4]);
    BYTESWAP (ctx->w[ 5]);
    BYTESWAP (ctx->w[ 6]);
    BYTESWAP (ctx->w[ 7]);
    BYTESWAP (ctx->w[ 8]);
    BYTESWAP (ctx->w[ 9]);
    BYTESWAP (ctx->w[10]);
    BYTESWAP (ctx->w[11]);
    BYTESWAP (ctx->w[12]);
    BYTESWAP (ctx->w[13]);
    BYTESWAP (ctx->w[14]);
    BYTESWAP (ctx->w[15]);

    hashcat_sha256 (ctx->state, ctx->w);

    buf += 64;
    len -= 64;
  }

  memcpy (ctx->buf, buf, len);
}

void sha256_final (hc_sha256_ctx *ctx)
{
  int left = ctx->len & 0x3f;

  memset (ctx->buf + left, 0, 64 - left);

  ctx->buf[left] = 0x80;

  BYTESWAP (ctx->w[ 0]);
  BYTESWAP (ctx->w[ 1]);
  BYTESWAP (ctx->w[ 2]);
  BYTESWAP (ctx->w[ 3]);
  BYTESWAP (ctx->w[ 4]);
  BYTESWAP (ctx->w[ 5]);
  BYTESWAP (ctx->w[ 6]);
  BYTESWAP (ctx->w[ 7]);
  BYTESWAP (ctx->w[ 8]);
  BYTESWAP (ctx->w[ 9]);
  BYTESWAP (ctx->w[10]);
  BYTESWAP (ctx->w[11]);
  BYTESWAP (ctx->w[12]);
  BYTESWAP (ctx->w[13]);

  if (left >= 56)
  {
    BYTESWAP (ctx->w[14]);
    BYTESWAP (ctx->w[15]);

    hashcat_sha256 (ctx->state, ctx->w);

    ctx->w[ 0] = 0;
    ctx->w[ 1] = 0;
    ctx->w[ 2] = 0;
    ctx->w[ 3] = 0;
    ctx->w[ 4] = 0;
    ctx->w[ 5] = 0;
    ctx->w[ 6] = 0;
    ctx->w[ 7] = 0;
    ctx->w[ 8] = 0;
    ctx->w[ 9] = 0;
    ctx->w[10] = 0;
    ctx->w[11] = 0;
    ctx->w[12] = 0;
    ctx->w[13] = 0;
  }

  ctx->w[14] = 0;
  ctx->w[15] = ctx->len * 8;

  hashcat_sha256 (ctx->state, ctx->w);

  BYTESWAP (ctx->state[0]);
  BYTESWAP (ctx->state[1]);
  BYTESWAP (ctx->state[2]);
  BYTESWAP (ctx->state[3]);
  BYTESWAP (ctx->state[4]);
  BYTESWAP (ctx->state[5]);
  BYTESWAP (ctx->state[6]);
  BYTESWAP (ctx->state[7]);
}

void sha512_final_sse2 (plain_t *plains, digest_sha512_sse2_t *digests)
{
  uint8_t *buf[4];

  buf[0] = plains[0].buf8;
  buf[1] = plains[1].buf8;
  buf[2] = plains[2].buf8;
  buf[3] = plains[3].buf8;

  int len[4];

  len[0] = plains[0].len;
  len[1] = plains[1].len;
  len[2] = plains[2].len;
  len[3] = plains[3].len;

  int left[4];

  left[0] = len[0] & 0x7f;
  left[1] = len[1] & 0x7f;
  left[2] = len[2] & 0x7f;
  left[3] = len[3] & 0x7f;

  int need_update = 0;

  int i;

  for (i = 0; i < 4; i++)
  {
    memset (buf[i] + left[i], 0, 128 - left[i]);

    buf[i][left[i]] = 0x80;

    if (left[i] < 112)
    {
      plains[i].buf64[14] = 0;
      plains[i].buf64[15] = len[i] * 8;

      BYTESWAP64 (plains[i].buf64[15]);

      continue;
    }

    need_update |= 1 << i;
  }

  if (need_update)
  {
    digest_sha512_sse2_t digests_tmp;

    memcpy (&digests_tmp, digests, sizeof (digest_sha512_sse2_t));

    sha512_transform (plains, &digests_tmp);

    for (i = 0; i < 4; i++)
    {
      if (need_update & (1 << i))
      {
        digests->buf64[i +  0] = digests_tmp.buf64[i +  0];
        digests->buf64[i +  4] = digests_tmp.buf64[i +  4];
        digests->buf64[i +  8] = digests_tmp.buf64[i +  8];
        digests->buf64[i + 12] = digests_tmp.buf64[i + 12];
        digests->buf64[i + 16] = digests_tmp.buf64[i + 16];
        digests->buf64[i + 20] = digests_tmp.buf64[i + 20];
        digests->buf64[i + 24] = digests_tmp.buf64[i + 24];
        digests->buf64[i + 28] = digests_tmp.buf64[i + 28];

        memset (buf[i], 0, 128);

        plains[i].buf64[15] = len[i] * 8;

        BYTESWAP64 (plains[i].buf64[15]);
      }
    }
  }

  sha512_transform (plains, digests);
}

// ctx

void sha512_init (hc_sha512_ctx *ctx)
{
  ctx->state[0] = SHA512M_A;
  ctx->state[1] = SHA512M_B;
  ctx->state[2] = SHA512M_C;
  ctx->state[3] = SHA512M_D;
  ctx->state[4] = SHA512M_E;
  ctx->state[5] = SHA512M_F;
  ctx->state[6] = SHA512M_G;
  ctx->state[7] = SHA512M_H;

  ctx->len = 0;
}

void sha512_update (hc_sha512_ctx *ctx, const char *buf, int len)
{
  int left = ctx->len & 0x7f;

  ctx->len += len;

  if (left + len < 128)
  {
    memcpy (ctx->buf + left, buf, len);

    return;
  }

  memcpy (ctx->buf + left, buf, 128 - left);

  BYTESWAP64 (ctx->w[ 0]);
  BYTESWAP64 (ctx->w[ 1]);
  BYTESWAP64 (ctx->w[ 2]);
  BYTESWAP64 (ctx->w[ 3]);
  BYTESWAP64 (ctx->w[ 4]);
  BYTESWAP64 (ctx->w[ 5]);
  BYTESWAP64 (ctx->w[ 6]);
  BYTESWAP64 (ctx->w[ 7]);
  BYTESWAP64 (ctx->w[ 8]);
  BYTESWAP64 (ctx->w[ 9]);
  BYTESWAP64 (ctx->w[10]);
  BYTESWAP64 (ctx->w[11]);
  BYTESWAP64 (ctx->w[12]);
  BYTESWAP64 (ctx->w[13]);
  BYTESWAP64 (ctx->w[14]);
  BYTESWAP64 (ctx->w[15]);

  hashcat_sha512 (ctx->state, ctx->w);

  buf += 128 - left;
  len -= 128 - left;

  while (len >= 128)
  {
    memcpy (ctx->buf, buf, 128);

    BYTESWAP64 (ctx->w[ 0]);
    BYTESWAP64 (ctx->w[ 1]);
    BYTESWAP64 (ctx->w[ 2]);
    BYTESWAP64 (ctx->w[ 3]);
    BYTESWAP64 (ctx->w[ 4]);
    BYTESWAP64 (ctx->w[ 5]);
    BYTESWAP64 (ctx->w[ 6]);
    BYTESWAP64 (ctx->w[ 7]);
    BYTESWAP64 (ctx->w[ 8]);
    BYTESWAP64 (ctx->w[ 9]);
    BYTESWAP64 (ctx->w[10]);
    BYTESWAP64 (ctx->w[11]);
    BYTESWAP64 (ctx->w[12]);
    BYTESWAP64 (ctx->w[13]);
    BYTESWAP64 (ctx->w[14]);
    BYTESWAP64 (ctx->w[15]);

    hashcat_sha512 (ctx->state, ctx->w);

    buf += 128;
    len -= 128;
  }

  memcpy (ctx->buf, buf, len);
}

void sha512_final (hc_sha512_ctx *ctx)
{
  int left = ctx->len & 0x7f;

  memset (ctx->buf + left, 0, 128 - left);

  ctx->buf[left] = 0x80;

  BYTESWAP64 (ctx->w[ 0]);
  BYTESWAP64 (ctx->w[ 1]);
  BYTESWAP64 (ctx->w[ 2]);
  BYTESWAP64 (ctx->w[ 3]);
  BYTESWAP64 (ctx->w[ 4]);
  BYTESWAP64 (ctx->w[ 5]);
  BYTESWAP64 (ctx->w[ 6]);
  BYTESWAP64 (ctx->w[ 7]);
  BYTESWAP64 (ctx->w[ 8]);
  BYTESWAP64 (ctx->w[ 9]);
  BYTESWAP64 (ctx->w[10]);
  BYTESWAP64 (ctx->w[11]);
  BYTESWAP64 (ctx->w[12]);
  BYTESWAP64 (ctx->w[13]);

  if (left >= 112)
  {
    BYTESWAP64 (ctx->w[14]);
    BYTESWAP64 (ctx->w[15]);

    hashcat_sha512 (ctx->state, ctx->w);

    ctx->w[ 0] = 0;
    ctx->w[ 1] = 0;
    ctx->w[ 2] = 0;
    ctx->w[ 3] = 0;
    ctx->w[ 4] = 0;
    ctx->w[ 5] = 0;
    ctx->w[ 6] = 0;
    ctx->w[ 7] = 0;
    ctx->w[ 8] = 0;
    ctx->w[ 9] = 0;
    ctx->w[10] = 0;
    ctx->w[11] = 0;
    ctx->w[12] = 0;
    ctx->w[13] = 0;
  }

  ctx->w[14] = 0;
  ctx->w[15] = ctx->len * 8;

  hashcat_sha512 (ctx->state, ctx->w);

  BYTESWAP64 (ctx->state[0]);
  BYTESWAP64 (ctx->state[1]);
  BYTESWAP64 (ctx->state[2]);
  BYTESWAP64 (ctx->state[3]);
  BYTESWAP64 (ctx->state[4]);
  BYTESWAP64 (ctx->state[5]);
  BYTESWAP64 (ctx->state[6]);
  BYTESWAP64 (ctx->state[7]);
}

// max55

void md4_update_sse2_max55 (plain_t *plains_dst, plain_t *plains_src)
{
  int i;

  for (i = 0; i < 4; i++)
  {
    plain_t *src = plains_src + i;
    plain_t *dst = plains_dst + i;

    const uint32_t len = dst->len + src->len;

    if (len >= 56) continue;

    memcpy (dst->buf8 + dst->len, src->buf8, src->len);

    dst->len = len;
  }
}

void md5_update_sse2_max55 (plain_t *plains_dst, plain_t *plains_src)
{
  int i;

  for (i = 0; i < 4; i++)
  {
    plain_t *src = plains_src + i;
    plain_t *dst = plains_dst + i;

    const uint32_t len = dst->len + src->len;

    if (len >= 56) continue;

    memcpy (dst->buf8 + dst->len, src->buf8, src->len);

    dst->len = len;
  }
}

void sha1_update_sse2_max55 (plain_t *plains_dst, plain_t *plains_src)
{
  int i;

  for (i = 0; i < 4; i++)
  {
    plain_t *src = plains_src + i;
    plain_t *dst = plains_dst + i;

    const uint32_t len = dst->len + src->len;

    if (len >= 56) continue;

    memcpy (dst->buf8 + dst->len, src->buf8, src->len);

    dst->len = len;
  }
}

void sha256_update_sse2_max55 (plain_t *plains_dst, plain_t *plains_src)
{
  int i;

  for (i = 0; i < 4; i++)
  {
    plain_t *src = plains_src + i;
    plain_t *dst = plains_dst + i;

    const uint32_t len = dst->len + src->len;

    if (len >= 56) continue;

    memcpy (dst->buf8 + dst->len, src->buf8, src->len);

    dst->len = len;
  }
}

void md4_final_sse2_max55 (plain_t *plains, digest_md4_sse2_t *digests)
{
  int i;

  for (i = 0; i < 4; i++)
  {
    plain_t *ptr = plains + i;

    memset (ptr->buf8 + ptr->len, 0, 64 - ptr->len);

    ptr->buf8[ptr->len] = 0x80;

    ptr->buf[14] = ptr->len * 8;
  }

  md4_transform (plains, digests);
}

void md5_final_sse2_max55 (plain_t *plains, digest_md5_sse2_t *digests)
{
  int i;

  for (i = 0; i < 4; i++)
  {
    plain_t *ptr = plains + i;

    memset (ptr->buf8 + ptr->len, 0, 64 - ptr->len);

    ptr->buf8[ptr->len] = 0x80;

    ptr->buf[14] = ptr->len * 8;
  }

  md5_transform (plains, digests);
}

void sha1_final_sse2_max55 (plain_t *plains, digest_sha1_sse2_t *digests)
{
  int i;

  for (i = 0; i < 4; i++)
  {
    plain_t *ptr = plains + i;

    memset (ptr->buf8 + ptr->len, 0, 64 - ptr->len);

    ptr->buf8[ptr->len] = 0x80;

    ptr->buf[15] = ptr->len * 8;

    BYTESWAP (ptr->buf[15]);
  }

  sha1_transform (plains, digests);
}

void sha256_final_sse2_max55 (plain_t *plains, digest_sha256_sse2_t *digests)
{
  int i;

  for (i = 0; i < 4; i++)
  {
    plain_t *ptr = plains + i;

    memset (ptr->buf8 + ptr->len, 0, 64 - ptr->len);

    ptr->buf8[ptr->len] = 0x80;

    ptr->buf[15] = ptr->len * 8;

    BYTESWAP (ptr->buf[15]);
  }

  sha256_transform (plains, digests);
}

/**
 * old helper -- kill them with fire�����
 */

void descrypt_64 (plain_t *plains, digest_t *digests)
{
  uint32_t i, j;

  uint32_t digest[2][4] __attribute__ ((aligned (16)));
  uint32_t blocks[4][4] __attribute__ ((aligned (16)));

  for (j = 0; j < 4; j++)
  {
    for (i = 0; i < 4; i++)
    {
      blocks[i][j] = plains[j].buf[i];
    }
  }

  hashcat_descrypt_64_sse2 ((__m128i *)digest, (__m128i *)blocks);

  for (j = 0; j < 2; j++)
  {
    for (i = 0; i < 4; i++)
    {
      digests[i].buf.descrypt[j] = digest[j][i];
    }
  }
}


void sha512 (plain_t *plains, digest_t *digests)
{
  int j;

  for (j = 0; j < 4; j++)
  {
    uint64_t digest[8];

    digest[0] = SHA512M_A;
    digest[1] = SHA512M_B;
    digest[2] = SHA512M_C;
    digest[3] = SHA512M_D;
    digest[4] = SHA512M_E;
    digest[5] = SHA512M_F;
    digest[6] = SHA512M_G;
    digest[7] = SHA512M_H;

    int len = plains[j].len;

    uint64_t block[16];

    int off;

    int left;

    for (left = len, off = 0; left >= 128; left -= 128, off += 16)
    {
      int i;

      for (i = 0; i < 16; i++)
      {
        block[i] = plains[j].buf64[off + i];

        BYTESWAP64 (block[i]);
      }

      hashcat_sha512 (digest, block);
    }

    if (left >= 112)
    {
      int i;

      for (i = 0; i < 16; i++)
      {
        block[i] = plains[j].buf64[off + i];

        BYTESWAP64 (block[i]);
      }

      hashcat_sha512 (digest, block);

      for (i = 0; i < 14; i++)
      {
        block[i] = 0;
      }

      block[14] = 0;
      block[15] = len * 8;

      hashcat_sha512 (digest, block);
    }
    else
    {
      int i;

      for (i = 0; i < 14; i++)
      {
        block[i] = plains[j].buf64[off + i];

        BYTESWAP64 (block[i]);
      }

      block[14] = 0;
      block[15] = len * 8;

      hashcat_sha512 (digest, block);
    }

    digests[j].buf.sha512[0] = digest[0];
    digests[j].buf.sha512[1] = digest[1];
    digests[j].buf.sha512[2] = digest[2];
    digests[j].buf.sha512[3] = digest[3];
    digests[j].buf.sha512[4] = digest[4];
    digests[j].buf.sha512[5] = digest[5];
    digests[j].buf.sha512[6] = digest[6];
    digests[j].buf.sha512[7] = digest[7];
  }
}

void keccak (plain_t *plains, digest_t *digests)
{
  uint32_t i;
  uint32_t j;

  uint64_t digest_l[25][2] __attribute__ ((aligned (16)));
  uint64_t digest_r[25][2] __attribute__ ((aligned (16)));

  for (j = 0; j < 2; j++)
  {
    uint32_t j2 = j * 2;

    for (i = 0; i < 25; i++)
    {
      digest_l[i][j] = plains[j2 + 0].buf64[i];
      digest_r[i][j] = plains[j2 + 1].buf64[i];
    }
  }

  hashcat_keccak_64 ((__m128i *) digest_l);
  hashcat_keccak_64 ((__m128i *) digest_r);

  for (j = 0; j < 2; j++)
  {
    uint32_t j2 = j * 2;

    for (i = 0; i < 8; i++)
    {
      digests[j2 + 0].buf.keccak[i] = digest_l[i][j];
      digests[j2 + 1].buf.keccak[i] = digest_r[i][j];
    }
  }
}

void gost_64 (plain_t *plains, digest_t *digests)
{
  uint32_t digest[ 8][4] __attribute__ ((aligned (16)));
  uint32_t blocks[16][4] __attribute__ ((aligned (16)));

  uint32_t i, j;

  for (j = 0; j < 4; j++)
  {
    for (i = 0; i < 16; i++)
    {
      blocks[i][j] = plains[j].buf[i];
    }
  }

  //  SSE2
  hashcat_gost_64_sse2 ((__m128i *)digest, (__m128i *)blocks);

  //  normal
  //  hashcat_gost_64 (digest, blocks);

  for (j = 0; j < 8; j++)
  {
    for (i = 0; i < 4; i++)
    {
      digests[i].buf.gost[j] = digest[j][i];
    }
  }
}

// void bcrypt_64_sse2 (plain_t *plains, plain_t *salt, digest_bcrypt_sse2_t *digests)
// {
//   __m128i block_words[16];
//   __m128i block_salts[16];
//
//   uint32_t i;
//
//   for (i = 0; i < 4; i++) plains[i].buf[15] = plains[i].len;
//
//   transpose_to_di4_sse2 (plains[0].buf128, plains[1].buf128, plains[2].buf128, plains[3].buf128, block_words);
//   transpose_to_di4_sse2 (salt[0].buf128, salt[1].buf128, salt[2].buf128, salt[3].buf128, block_salts);
//
//   hashcat_bcrypt_64_sse2 (digests->buf128, block_words, block_salts);
// }

void bcrypt_64 (plain_t *plains, plain_t *salt, uint32_t iterations, digest_bcrypt_sse2_t *digests)
{
  #ifdef __AVX2__
  hashcat_bcrypt_64 (digests->buf128, plains, salt, iterations);
  #else
  hashcat_bcrypt_64 (digests->buf32, plains, salt, iterations);
  #endif
}

void transpose_to_di4_sse2 (const __m128i *s0, const __m128i *s1, const __m128i *s2, const __m128i *s3, __m128i *p2)
{
  int i;
  int j;

  for (i = 0, j = 0; i < 16; i += 4, j += 1)
  {
    // const __m128i i0 = s0[j];
    // const __m128i i1 = s1[j];
    // const __m128i i2 = s2[j];
    // const __m128i i3 = s3[j];

    #define i0 s0[j]
    #define i1 s1[j]
    #define i2 s2[j]
    #define i3 s3[j]

    const __m128i t0 = _mm_unpacklo_epi32 (i0, i1);
    const __m128i t1 = _mm_unpacklo_epi32 (i2, i3);
    const __m128i t2 = _mm_unpackhi_epi32 (i0, i1);
    const __m128i t3 = _mm_unpackhi_epi32 (i2, i3);

    p2[i + 0] = _mm_unpacklo_epi64 (t0, t1);
    p2[i + 1] = _mm_unpackhi_epi64 (t0, t1);
    p2[i + 2] = _mm_unpacklo_epi64 (t2, t3);
    p2[i + 3] = _mm_unpackhi_epi64 (t2, t3);
  }
}

void plain_init (plain_t *in)
{
  in->len = 0; in++;
  in->len = 0; in++;
  in->len = 0; in++;
  in->len = 0;
}

void plain_init_64 (plain_t *in)
{
  in->len = 0; in++;
  in->len = 0;
}

// transforms

void md4_transform (plain_t *plains, digest_md4_sse2_t *digests)
{
  __m128i block[16];

  transpose_to_di4_sse2 (plains[0].buf128, plains[1].buf128, plains[2].buf128, plains[3].buf128, block);

  hashcat_md4_64 (digests->buf128, block);
}

void md5_transform (plain_t *plains, digest_md5_sse2_t *digests)
{
  __m128i block[16];

  transpose_to_di4_sse2 (plains[0].buf128, plains[1].buf128, plains[2].buf128, plains[3].buf128, block);

  hashcat_md5_64 (digests->buf128, block);
}

void sha1_transform (plain_t *plains, digest_sha1_sse2_t *digests)
{
  __m128i block[16];

  transpose_to_di4_sse2 (plains[0].buf128, plains[1].buf128, plains[2].buf128, plains[3].buf128, block);

  hashcat_sha1_64 (digests->buf128, block);
}

void sha256_transform (plain_t *plains, digest_sha256_sse2_t *digests)
{
  __m128i block[16];

  transpose_to_di4_sse2 (plains[0].buf128, plains[1].buf128, plains[2].buf128, plains[3].buf128, block);

  hashcat_sha256_64 (digests->buf128, block);
}

void sha512_transform (plain_t *plains, digest_sha512_sse2_t *digests)
{
  uint64_t block[16][2] __attribute__ ((aligned (16)));
  uint64_t digest[8][2] __attribute__ ((aligned (16)));

  int i;

  for (i = 0; i < 16; i++)
  {
    block[i][0] = plains[0].buf64[i];
    block[i][1] = plains[1].buf64[i];
  }

  for (i = 0; i < 8; i++)
  {
    digest[i][0] = digests->buf64[(i * 4) + 0];
    digest[i][1] = digests->buf64[(i * 4) + 1];
  }

  hashcat_sha512_64 ((__m128i *) digest, (__m128i *) block);

  for (i = 0; i < 8; i++)
  {
    digests->buf64[(i * 4) + 0] = digest[i][0];
    digests->buf64[(i * 4) + 1] = digest[i][1];
  }

  for (i = 0; i < 16; i++)
  {
    block[i][0] = plains[2].buf64[i];
    block[i][1] = plains[3].buf64[i];
  }

  for (i = 0; i < 8; i++)
  {
    digest[i][0] = digests->buf64[(i * 4) + 2];
    digest[i][1] = digests->buf64[(i * 4) + 3];
  }

  hashcat_sha512_64 ((__m128i *) digest, (__m128i *) block);

  for (i = 0; i < 8; i++)
  {
    digests->buf64[(i * 4) + 2] = digest[i][0];
    digests->buf64[(i * 4) + 3] = digest[i][1];
  }
}
