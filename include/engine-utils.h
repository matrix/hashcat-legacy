#ifndef _ENGINE_UTILS_H_
#define _ENGINE_UTILS_H_

char base64a_int2char (int i);
int base64a_char2int (char c);
char base64b_int2char (int i);
int base64b_char2int (char c);

char int_to_itoa64 (const char c);
char int_to_base64 (const char c);
char itoa64_to_int (const char c);
char base64_to_int (const char c);
char int_to_bf64 (const char c);
char bf64_to_int (const char c);

char hex_convert (char c);
uint is_valid_hex_char (const char c);
char hex_convert (const char c);
char hex_to_char (char hex[2]);
uint32_t hex_to_uint (char hex[ 8]);
uint64_t hex_to_uint64 (char hex[16]);
void uint_to_hex_lower (uint32_t uint, char hex[8]);
void uint_to_hex_upper (uint32_t uint, char hex[8]);

int base64_decode (char (*f) (const char), char *in_buf, int in_len, char *out_buf);
int base64_encode (char (*f) (const char), char *in_buf, int in_len, char *out_buf);

void descrypt_decode (unsigned char digest[DIGEST_SIZE_DESCRYPT], unsigned char buf[HASH_SIZE_DESCRYPT]);
void descrypt_encode (unsigned char digest[DIGEST_SIZE_DESCRYPT], unsigned char buf[HASH_SIZE_DESCRYPT]);

void phpass_decode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_PHPASS]);
void phpass_encode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_PHPASS]);

void md5unix_decode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_MD5UNIX]);
void md5unix_encode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_MD5UNIX]);

void md5sun_decode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_MD5SUN]);
void md5sun_encode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_MD5SUN]);

void md5apr_decode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_MD5APR]);
void md5apr_encode (unsigned char digest[DIGEST_SIZE_MD5], unsigned char buf[HASH_SIZE_MD5APR]);

void sha512unix_decode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char buf[HASH_SIZE_SHA512UNIX]);
void sha512unix_encode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char buf[HASH_SIZE_SHA512UNIX]);

void sha1b64_decode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char buf[HASH_SIZE_SHA1B64]);
void sha1b64_encode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char buf[HASH_SIZE_SHA1B64]);

void sha1b64s_decode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char salt[BLOCK_SIZE], uint32_t in_len, uint32_t *out_len, char *buf);
void sha1b64s_encode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char salt[BLOCK_SIZE], uint32_t salt_len, char *buf);

void sha256b64_decode (unsigned char digest[DIGEST_SIZE_SHA256], unsigned char buf[HASH_SIZE_SHA256B64]);
void sha256b64_encode (unsigned char digest[DIGEST_SIZE_SHA256], unsigned char buf[HASH_SIZE_SHA256B64]);

void sha1aix_decode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char buf[HASH_SIZE_SHA1AIX]);
void sha1aix_encode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char buf[HASH_SIZE_SHA1AIX]);

void sha256aix_decode (unsigned char digest[DIGEST_SIZE_SHA256], unsigned char buf[HASH_SIZE_SHA256AIX]);
void sha256aix_encode (unsigned char digest[DIGEST_SIZE_SHA256], unsigned char buf[HASH_SIZE_SHA256AIX]);

void sha512aix_decode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char buf[HASH_SIZE_SHA512AIX]);
void sha512aix_encode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char buf[HASH_SIZE_SHA512AIX]);

void sha1fortigate_decode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char salt[BLOCK_SIZE], char *buf);
void sha1fortigate_encode (unsigned char digest[DIGEST_SIZE_SHA1], unsigned char salt[BLOCK_SIZE], char *buf);

void md5cisco_decode (char in_buf[HASH_SIZE_MD5CISCO], uint32_t out_buf[4]);
void md5cisco_encode (uint32_t in_buf[4], unsigned char *out_buf);

void bcrypt_encode (char digest[DIGEST_SIZE_BCRYPT], char salt[16], char *bcrypt_str);
void bcrypt_decode (char digest[DIGEST_SIZE_BCRYPT], char salt[16], char *hash_buf, char *salt_buf);

void sha256unix_decode (unsigned char digest[DIGEST_SIZE_SHA256], unsigned char buf[HASH_SIZE_SHA256UNIX]);
void sha256unix_encode (unsigned char digest[DIGEST_SIZE_SHA256], unsigned char buf[HASH_SIZE_SHA256UNIX]);

void sha512b64s_decode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char salt[BLOCK_SIZE], uint32_t in_len, uint32_t *out_len, char *buf);
void sha512b64s_encode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char salt[BLOCK_SIZE], uint32_t salt_len, char *buf);

void drupal7_decode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char buf[HASH_SIZE_DRUPAL7]);
void drupal7_encode (unsigned char digest[DIGEST_SIZE_SHA512], unsigned char buf[HASH_SIZE_DRUPAL7]);

void make_unicode (uint8_t *out, uint8_t *in, int size);
void make_unicode_upper (uint8_t *out, uint8_t *in, int size);

void plain_unicode (plain_t *in, plain_t *out);
void plain_unicode_and_upper (plain_t *in, plain_t *out);

void md4_init_sse2 (digest_md4_sse2_t *digests);
void md5_init_sse2 (digest_md5_sse2_t *digests);
void sha1_init_sse2 (digest_sha1_sse2_t *digests);
void sha256_init_sse2 (digest_sha256_sse2_t *digests);
void sha512_init_sse2 (digest_sha512_sse2_t *digests);

void md4_update_sse2 (plain_t *plains_dst, digest_md4_sse2_t *digests, plain_t *plains_src);
void md5_update_sse2 (plain_t *plains_dst, digest_md5_sse2_t *digests, plain_t *plains_src);
void sha1_update_sse2 (plain_t *plains_dst, digest_sha1_sse2_t *digests, plain_t *plains_src);
void sha256_update_sse2 (plain_t *plains_dst, digest_sha256_sse2_t *digests, plain_t *plains_src);
void sha512_update_sse2 (plain_t *plains_dst, digest_sha512_sse2_t *digests, plain_t *plains_src);

void md4_final_sse2 (plain_t *plains, digest_md4_sse2_t *digests);
void md5_final_sse2 (plain_t *plains, digest_md5_sse2_t *digests);
void sha1_final_sse2 (plain_t *plains, digest_sha1_sse2_t *digests);
void sha256_final_sse2 (plain_t *plains, digest_sha256_sse2_t *digests);
void sha512_final_sse2 (plain_t *plains, digest_sha512_sse2_t *digests);

void sha256_init (hc_sha256_ctx *ctx);
void sha256_update (hc_sha256_ctx *ctx, const char *buf, int len);
void sha256_final (hc_sha256_ctx *ctx);

void sha512_init (hc_sha512_ctx *ctx);
void sha512_update (hc_sha512_ctx *ctx, const char *buf, int len);
void sha512_final (hc_sha512_ctx *ctx);

void md4_update_sse2_max55 (plain_t *plains_dst, plain_t *plains_src);
void md5_update_sse2_max55 (plain_t *plains_dst, plain_t *plains_src);
void sha1_update_sse2_max55 (plain_t *plains_dst, plain_t *plains_src);
void sha256_update_sse2_max55 (plain_t *plains_dst, plain_t *plains_src);

void md4_final_sse2_max55 (plain_t *plains, digest_md4_sse2_t *digests);
void md5_final_sse2_max55 (plain_t *plains, digest_md5_sse2_t *digests);
void sha1_final_sse2_max55 (plain_t *plains, digest_sha1_sse2_t *digests);
void sha256_final_sse2_max55 (plain_t *plains, digest_sha256_sse2_t *digests);

void sha512 (plain_t *plains, digest_t *digests);
void keccak (plain_t *plains, digest_t *digests);
void gost_64 (plain_t *plains, digest_t *digests);
void bcrypt_64 (plain_t *plains, plain_t *salt, uint32_t iterations, digest_bcrypt_sse2_t *digests);
void descrypt_64 (plain_t *plains, digest_t *digests);

void transpose_to_di4_sse2 (const __m128i *s0, const __m128i *s1, const __m128i *s2, const __m128i *s3, __m128i *p2);

void plain_init (plain_t *in);
void plain_init_64 (plain_t *in);

void md4_transform (plain_t *plains, digest_md4_sse2_t *digests);
void md5_transform (plain_t *plains, digest_md5_sse2_t *digests);
void sha1_transform (plain_t *plains, digest_sha1_sse2_t *digests);
void sha256_transform (plain_t *plains, digest_sha256_sse2_t *digests);
void sha512_transform (plain_t *plains, digest_sha512_sse2_t *digests);

#endif
