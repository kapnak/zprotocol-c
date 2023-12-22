#include <string.h>

#include "zprotocol.h"


void z_helpers_read_kp(const char *filename, unsigned char pk[ED25519_PK_LENGTH], unsigned char sk[ED25519_SK_LENGTH]) {
    FILE *file = fopen(filename, "rb");
    if (file == NULL) {
        z_helpers_generate_kp(pk, sk);
        z_helpers_write_kp(filename, sk);
    } else {
        fread(sk, ED25519_SK_LENGTH, 1, file);
        z_helpers_sk_to_pk(pk, sk);
        fclose(file);
    }
}


void z_helpers_write_kp(const char *filename, const unsigned char sk[ED25519_SK_LENGTH]) {
    FILE *file = fopen(filename, "wb");
    fwrite(sk, ED25519_SK_LENGTH, 1, file);
    fclose(file);
}


void z_helpers_generate_kp(unsigned char pk[ED25519_PK_LENGTH], unsigned char sk[ED25519_SK_LENGTH]) {
    crypto_sign_keypair(pk, sk);
}


void z_helpers_sk_to_pk(unsigned char pk[ED25519_PK_LENGTH], const unsigned char sk[ED25519_SK_LENGTH]) {
    crypto_sign_ed25519_sk_to_pk(pk, sk);
}


void z_helpers_pk_bin_to_bs64(const unsigned char pk[ED25519_PK_LENGTH], char pk_bs64[PK_BS64_LENGTH]) {
    size_t pk_bs64_len = PK_BS64_LENGTH;
    sodium_bin2base64(pk_bs64, pk_bs64_len, pk, ED25519_PK_LENGTH, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
}


void z_helpers_sk_bin_to_bs64(const unsigned char sk[ED25519_SK_LENGTH], char sk_bs64[SK_BS64_LENGTH]) {
    size_t sk_bs64_len = SK_BS64_LENGTH;
    sodium_bin2base64(sk_bs64, sk_bs64_len, sk, ED25519_SK_LENGTH, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
}


void z_helpers_pk_bs64_to_bin(const char pk_bs64[PK_BS64_LENGTH], unsigned char pk[ED25519_PK_LENGTH]) {
    sodium_base642bin(pk, crypto_sign_PUBLICKEYBYTES, pk_bs64, strlen(pk_bs64), NULL, NULL, NULL, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
}


void z_helpers_sk_bs64_to_bin(const char sk_bs64[SK_BS64_LENGTH], unsigned char sk[ED25519_SK_LENGTH]) {
    sodium_base642bin(sk, crypto_sign_PUBLICKEYBYTES, sk_bs64, strlen(sk_bs64), NULL, NULL, NULL, sodium_base64_VARIANT_URLSAFE_NO_PADDING);
}
