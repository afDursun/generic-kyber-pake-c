#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "params.h"
#include "kyber-pake.h"
#include "randombytes.h"
#include "kem.h"
#include "symmetric.h"

#include <openssl/aes.h>
#include <openssl/rand.h>

#define BLOCK_SIZE 16


static void encryptData(const uint8_t *key, uint8_t *data, size_t dataSize)
{
    AES_KEY enc_key;
    AES_set_encrypt_key(key, 128, &enc_key);

    uint8_t enc_out[BLOCK_SIZE];
    for (size_t i = 0; i < dataSize; i += BLOCK_SIZE)
    {
        AES_encrypt(data + i, enc_out, &enc_key);
        memcpy(data + i, enc_out, BLOCK_SIZE);
    }
}

static void decryptData(const uint8_t *key, uint8_t *data, size_t dataSize)
{
    AES_KEY dec_key;
    AES_set_decrypt_key(key, 128, &dec_key);

    uint8_t dec_out[BLOCK_SIZE];
    for (size_t i = 0; i < dataSize; i += BLOCK_SIZE)
    {
        AES_decrypt(data + i, dec_out, &dec_key);
        memcpy(data + i, dec_out, BLOCK_SIZE);
    }
}

void printData(const uint8_t *data, size_t dataSize)
{
    for (size_t i = 0; i < dataSize; i++)
    {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void construct_aes_key(unsigned char* key, const unsigned char* ssid, const unsigned char* pw) {
    int i;

    for(i = 0; i < ID_BYTES*3; i++ ){
        key[i] = ssid[i];
    } 
    
    for(i = 0; i < PW_BYTES; i++ ){
        key[i + (ID_BYTES*3)] = pw[i];
    }
}

static int concatenate_a0(unsigned char *components, const unsigned char *ssid, const unsigned char *pw, unsigned char *pk)
{
    int i;
    for (i = 0; i < ID_BYTES; i++)
    {
        components[i] = ssid[i];
    }
    for (i = 0; i < PW_BYTES; i++)
    {
        components[i + ID_BYTES] = pw[i];
    }

    for (i = 0; i < CRYPTO_PUBLICKEYBYTES; i++)
    {
        components[i + ID_BYTES + PW_BYTES] = pk[i];
    }
    return 1;
}

static int concatenate_b0(unsigned char *auth_b, const unsigned char *ssid, const unsigned char *a_id, const unsigned char *b_id, const unsigned char *pw, unsigned char *epk, unsigned char *ct, unsigned char *k)
{
    int i, offset = 0;

    for (i = 0; i < ID_BYTES; i++)
    {
        auth_b[offset + i] = ssid[i];
    }
    offset += ID_BYTES;

    for (i = 0; i < ID_BYTES; i++)
    {
        auth_b[offset + i] = a_id[i];
    }
    offset += ID_BYTES;

    for (i = 0; i < ID_BYTES; i++)
    {
        auth_b[offset + i] = b_id[i];
    }
    offset += ID_BYTES;

    for (i = 0; i < PW_BYTES; i++)
    {
        auth_b[offset + i] = pw[i];
    }
    offset += PW_BYTES;

    for (i = 0; i < PAKE_A0_SEND; i++)
    {
        auth_b[offset + i] = epk[i];
    }
    offset += PAKE_A0_SEND;

    for (i = 0; i < CRYPTO_CIPHERTEXTBYTES; i++)
    {
        auth_b[offset + i] = ct[i];
    }
    offset += CRYPTO_CIPHERTEXTBYTES;

    for (i = 0; i < CRYPTO_BYTES; i++)
    {
        auth_b[offset + i] = k[i];
    }
    return 1;
}

static int concatenate_a1(unsigned char *auth, const unsigned char *ssid, const unsigned char *a_id, const unsigned char *b_id, const unsigned char *pw, unsigned char *epk, unsigned char *ct, unsigned char *k_prime)
{
    int i, offset = 0;

    for (i = 0; i < ID_BYTES; i++)
    {
        auth[offset + i] = ssid[i];
    }
    offset += ID_BYTES;

    for (i = 0; i < ID_BYTES; i++)
    {
        auth[offset + i] = a_id[i];
    }
    offset += ID_BYTES;

    for (i = 0; i < ID_BYTES; i++)
    {
        auth[offset + i] = b_id[i];
    }
    offset += ID_BYTES;

    for (i = 0; i < PW_BYTES; i++)
    {
        auth[offset + i] = pw[i];
    }
    offset += PW_BYTES;

    for (i = 0; i < PAKE_A0_SEND; i++)
    {
        auth[offset + i] = epk[i];
    }
    offset += PAKE_A0_SEND;

    for (i = 0; i < CRYPTO_CIPHERTEXTBYTES; i++)
    {
        auth[offset + i] = ct[i];
    }
    offset += CRYPTO_CIPHERTEXTBYTES;

    for (i = 0; i < CRYPTO_BYTES; i++)
    {
        auth[offset + i] = k_prime[i];
    }
    return 1;
}

static int concatenate_hash(unsigned char *hash_array, const unsigned char *ssid, const unsigned char *a_id, const unsigned char *b_id, unsigned char *epk, unsigned char *ct, unsigned char *auth, unsigned char *k_prime)
{
    int i, offset = 0;

    for (i = 0; i < ID_BYTES; i++)
    {
        hash_array[offset + i] = ssid[i];
    }
    offset += ID_BYTES;

    for (i = 0; i < ID_BYTES; i++)
    {
        hash_array[offset + i] = a_id[i];
    }
    offset += ID_BYTES;

    for (i = 0; i < ID_BYTES; i++)
    {
        hash_array[offset + i] = b_id[i];
    }
    offset += ID_BYTES;

    for (i = 0; i < PAKE_A0_SEND; i++)
    {
        hash_array[offset + i] = epk[i];
    }
    offset += PAKE_A0_SEND;

    for (i = 0; i < CRYPTO_CIPHERTEXTBYTES; i++)
    {
        hash_array[offset + i] = ct[i];
    }
    offset += CRYPTO_CIPHERTEXTBYTES;

    for (i = 0; i < SHA3_256_HashSize; i++)
    {
        hash_array[offset + i] = auth[i];
    }
    offset += SHA3_256_HashSize;

    for (i = 0; i < CRYPTO_BYTES; i++)
    {
        hash_array[offset + i] = k_prime[i];
    }
    return 1;
}

static int concatenate_b1(unsigned char *hash_array, const unsigned char *ssid, const unsigned char *a_id, const unsigned char *b_id, unsigned char *epk, unsigned char *ct, unsigned char *auth_b, unsigned char *k)
{
    int i, offset = 0;

    for (i = 0; i < ID_BYTES; i++)
    {
        hash_array[offset + i] = ssid[i];
    }
    offset += ID_BYTES;

    for (i = 0; i < ID_BYTES; i++)
    {
        hash_array[offset + i] = a_id[i];
    }
    offset += ID_BYTES;

    for (i = 0; i < ID_BYTES; i++)
    {
        hash_array[offset + i] = b_id[i];
    }
    offset += ID_BYTES;

    for (i = 0; i < PAKE_A0_SEND; i++)
    {
        hash_array[offset + i] = epk[i];
    }
    offset += PAKE_A0_SEND;

    for (i = 0; i < CRYPTO_CIPHERTEXTBYTES; i++)
    {
        hash_array[offset + i] = ct[i];
    }
    offset += CRYPTO_CIPHERTEXTBYTES;

    for (i = 0; i < SHA3_256_HashSize; i++)
    {
        hash_array[offset + i] = auth_b[i];
    }
    offset += SHA3_256_HashSize;

    for (i = 0; i < CRYPTO_BYTES; i++)
    {
        hash_array[offset + i] = k[i];
    }
    return 1;
}

void pake_a0(const unsigned char *pw, const uint8_t *ssid, uint8_t *epk, uint8_t *pk, uint8_t *sk)
{
    
    uint8_t components[PAKE_A0_SEND];

    crypto_kem_keypair(pk, sk);

    uint8_t key[128];
    construct_aes_key(key, ssid, pw); // key = (ssid || pw)
    int i;
    for (i = 0; i < CRYPTO_PUBLICKEYBYTES; i++)
    {
        components[i] = pk[i];
    }

    encryptData(key, components, PAKE_A0_SEND);
    memcpy(epk, components, PAKE_A0_SEND);
}

void pake_b0(const unsigned char *pw, const uint8_t *ssid, const unsigned char *a_id, const unsigned char *b_id,
             uint8_t *epk, uint8_t *send_b0, uint8_t *ct, uint8_t *k, uint8_t *auth_b)
{

    int i;
    uint8_t pk[CRYPTO_PUBLICKEYBYTES] = {0};
    uint8_t components[PAKE_A0_SEND];

    uint8_t key[128];
    construct_aes_key(key, ssid, pw); // key = (ssid || pw)
    memcpy(components, epk, PAKE_A0_SEND);
    decryptData(key, components, PAKE_A0_SEND);

    for (i = 0; i < CRYPTO_PUBLICKEYBYTES; i++)
    {
        pk[i] = components[i];
    }

    crypto_kem_enc(ct, k, pk);

    concatenate_b0(auth_b, ssid, a_id, b_id, pw, epk, ct, k);

    hash_h(send_b0, auth_b, AUTH_SIZE);
}

void pake_a1(const unsigned char *pw, uint8_t *sk, uint8_t *epk, uint8_t *send_b0, const uint8_t *ssid, const unsigned char *a_id, const unsigned char *b_id, uint8_t *ct, uint8_t *key_a)
{

    uint8_t k_prime[CRYPTO_BYTES];
    uint8_t auth[AUTH_SIZE];
    uint8_t control_auth[SHA3_256_HashSize];
    uint8_t hash_array[HASH_SIZE];

    crypto_kem_dec(k_prime, ct, sk);

    concatenate_a1(auth, ssid, a_id, b_id, pw, epk, ct, k_prime);

    hash_h(control_auth, auth, AUTH_SIZE);

    if (memcmp(control_auth, send_b0, SHA3_256_HashSize) == 0)
    {
        concatenate_hash(hash_array, ssid, a_id, b_id, epk, ct, control_auth, k_prime);
        hash_h(key_a, hash_array, HASH_SIZE);
    }
    else
    {
        printf("Auth Failed....\n");
    }
}

void pake_b1(const uint8_t *ssid, const unsigned char *a_id, const unsigned char *b_id, uint8_t *epk, uint8_t *ct, uint8_t *auth_b, uint8_t *k, uint8_t *key_b)
{
    uint8_t hash_array[HASH_SIZE];
    uint8_t control_auth[SHA3_256_HashSize];
    hash_h(control_auth, auth_b, AUTH_SIZE);

    concatenate_b1(hash_array, ssid, a_id, b_id, epk, ct, control_auth, k);

    hash_h(key_b, hash_array, HASH_SIZE);
}