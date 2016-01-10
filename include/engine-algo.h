#ifndef _ENGINE_ALGO_H_
#define _ENGINE_ALGO_H_

void hashcat_md4_64       (__m128i digests[4], __m128i W[16]);
void hashcat_md5_64       (__m128i digests[4], __m128i W[16]);
void hashcat_sha1_64      (__m128i digests[5], __m128i W[16]);
void hashcat_sha256       (uint32_t digest[8], uint32_t W[16]);
void hashcat_sha256_64    (__m128i digests[8], __m128i W[16]);
void hashcat_sha512       (uint64_t digest[8], uint64_t W[16]);
void hashcat_sha512_128   (uint32_t digests[16][4], uint32_t blocks[160][4]);
void hashcat_sha512_64    (__m128i digests[8], __m128i W[16]);
void hashcat_keccak_64    (__m128i digests[25]);
void hashcat_bcrypt_64    (uint32_t digests[24], plain_t *plain, plain_t *salt, uint32_t iterations);
void hashcat_gost_64_sse2 (__m128i digests[8], __m128i blocks[16]);

#endif
