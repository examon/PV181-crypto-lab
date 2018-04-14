/*
 * Tomas Meszaros - 422336
 *
 * https://tools.ietf.org/html/rfc6070
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

const unsigned char test_vector_1[] = {
    0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5, 0x24,
    0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6
};

const unsigned char test_vector_2[] = {
    0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9, 0x2a,
    0xce, 0x1d, 0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57
};

const unsigned char test_vector_3[] = {
    0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a, 0xbe, 0xad, 0x49, 0xd9,
    0x26, 0xf7, 0x21, 0xd0, 0x65, 0xa4, 0x29, 0xc1
};

const unsigned char test_vector_4[] = {
    0xee, 0xfe, 0x3d, 0x61, 0xcd, 0x4d, 0xa4, 0xe4, 0xe9, 0x94, 0x5b, 0x3d,
    0x6b, 0xa2, 0x15, 0x8c, 0x26, 0x34, 0xe9, 0x84
};

const unsigned char test_vector_5[] = {
    0x3d, 0x2e, 0xec, 0x4f, 0xe4, 0x1c, 0x84, 0x9b, 0x80, 0xc8, 0xd8, 0x36,
    0x62, 0xc0, 0xe4, 0x4a, 0x8b, 0x29, 0x1a, 0x96, 0x4c, 0xf2, 0xf0, 0x70,
    0x38
};

const unsigned char test_vector_6[] = {
    0x56, 0xfa, 0x6a, 0xa7, 0x55, 0x48, 0x09, 0x9d, 0xcc, 0x37, 0xd7, 0xf0,
    0x34, 0x25, 0xe0, 0xc3
};


static void hexprint(const char *d, int n, const char *sep)
{
    int i;

    for (i = 0; i < n; i++)
        printf("%02hhx%s", (const char)d[i], sep);
    printf("\n");
}


int compare_keys(unsigned char key[], const unsigned char expected[],
                 const unsigned int k_len, const unsigned int exp_len) {
    if (k_len != exp_len)
        return -1;
    for (int i = 0; i < k_len; i++) {
        if (key[i] != expected[i])
            return -2;
    }
    return 0;
}


int verify(const char *password, const unsigned long password_len,
           const char *salt, const unsigned long salt_len,
           const unsigned long iterations, bool sha256,
           const unsigned char expected[], const unsigned int expected_len)
{

    unsigned char key[expected_len];

    if (sha256) {
        if (!PKCS5_PBKDF2_HMAC(password, password_len,
                               (unsigned char *)salt, salt_len,
                               iterations, EVP_sha256(), sizeof(key), key)) {
            return -1;
        }

        hexprint((const char*)key, sizeof(key), " ");

    } else {
        if (!PKCS5_PBKDF2_HMAC(password, password_len,
                               (unsigned char *)salt, salt_len,
                               iterations, EVP_sha1(), sizeof(key), key)) {
            return -1;
        }

        hexprint((const char*)key, sizeof(key), " ");
        hexprint((const char*)expected, expected_len, " ");

        if (compare_keys(key, expected, expected_len, expected_len) == 0) {
            printf("keys are the same, test vector verified\n");
        } else {
            printf("FAIL: different keys!\n");
            return -2;
        }
    }

    return 0;
}


int main(int argc, char *argv[])
{
    OpenSSL_add_all_algorithms();
    printf("OpenSSL (%s):\n", SSLeay_version(SSLEAY_VERSION));

    printf("\nSHA1\n");
    {
        printf("\n1st test vector\n");
        verify("password", 8, "salt", 4 , 1, false, test_vector_1, 20);

        printf("\n2nd test vector\n");
        verify("password", 8, "salt", 4, 2, false, test_vector_2, 20);

        printf("\n3th test vector\n");
        verify("password", 8, "salt", 4, 4096, false, test_vector_3, 20);

        printf("\n4th test vector\n");
        verify("password", 8, "salt", 4, 16777216, false, test_vector_4, 20);

        printf("\n5th test vector\n");
        verify("passwordPASSWORDpassword", 24,
               "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
               4096, false, test_vector_5, 25);

        printf("\n6th test vector\n");
        verify("pass\0word", 9, "sa\0lt", 5, 4096, false, test_vector_6, 16);
    }

    printf("\nSHA256\n");
    {
        printf("\n1st test vector\n");
        verify("password", 8, "salt", 4 , 1, true, test_vector_1, 20);

        printf("\n2nd test vector\n");
        verify("password", 8, "salt", 4, 2, true, test_vector_2, 20);

        printf("\n3th test vector\n");
        verify("password", 8, "salt", 4, 4096, true, test_vector_3, 20);

        printf("\n4th test vector\n");
        verify("password", 8, "salt", 4, 16777216, true, test_vector_4, 20);

        printf("\n5th test vector\n");
        verify("passwordPASSWORDpassword", 24,
               "saltSALTsaltSALTsaltSALTsaltSALTsalt", 36,
               4096, true, test_vector_5, 25);

        printf("\n6th test vector\n");
        verify("pass\0word", 9, "sa\0lt", 5, 4096, true, test_vector_6, 16);
    }

    return 0;
}

// vim: set ts=4 sts=4 sw=4 :
