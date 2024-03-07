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


int z_helpers_bin_to_bs32(const unsigned char *bin, int bin_length, char *bs32, int bs32_length) {
    if (bin_length < 0 || bin_length > (1 << 28)) {
        return -1;
    }
    int count = 0;
    if (bin_length > 0) {
        unsigned int buffer = bin[0];
        int next = 1;
        int bitsLeft = 8;
        while (count < bs32_length && (bitsLeft > 0 || next < bin_length)) {
            if (bitsLeft < 5) {
                if (next < bin_length) {
                    buffer <<= 8;
                    buffer |= bin[next++] & 0xFF;
                    bitsLeft += 8;
                } else {
                    int pad = 5 - bitsLeft;
                    buffer <<= pad;
                    bitsLeft += pad;
                }
            }
            int index = 0x1F & (buffer >> (bitsLeft - 5));
            bitsLeft -= 5;
            bs32[count++] = "abcdefghijklmnopqrstuvwxyz234567"[index];
        }
    }
    if (count < bs32_length) {
        bs32[count] = '\000';
    }
    return count;
}


int z_helpers_bs32_to_bin(const char *bs32, unsigned char *bin, int bin_length) {
    unsigned int buffer = 0;
    int bitsLeft = 0;
    int count = 0;
    for (const char *ptr = bs32; count < bin_length && *ptr; ++ptr) {
        uint8_t ch = *ptr;
        buffer <<= 5;

        // Look up one base32 digit
        if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) {
            ch = (ch & 0x1F) - 1;
        } else if (ch >= '2' && ch <= '7') {
            ch -= '2' - 26;
        } else {
            return -1;
        }

        buffer |= ch;
        bitsLeft += 5;
        if (bitsLeft >= 8) {
            bin[count++] = buffer >> (bitsLeft - 8);
            bitsLeft -= 8;
        }
    }
    if (count < bin_length) {
        bin[count] = '\000';
    }
    return count;
}
