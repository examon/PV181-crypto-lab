/* Tomas Meszaros - 422336
 * ---
 * verify generated file with:
 * openssl rsa -inform PEM -text -noout <private.pem
 */
#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

int main(int argc, char *argv[])
{
    int ret = 0;
    RSA *r = NULL;
    BIGNUM *bne = NULL;
    BIO *bp_public = NULL;
    BIO *bp_private = NULL;
    int bits = 4096;
    unsigned long e = 17;

    /* user for newer openssl version
    BIGNUM *p = NULL;
    BIGNUM *q = NULL;
    */

    bne = BN_new();
    ret = BN_set_word(bne, e);
    if(ret != 1){
        return -1;
    }

    r = RSA_new();
    ret = RSA_generate_key_ex(r, bits, bne, NULL);
    if(ret != 1){
        return -2;
    }

    printf("generated p: %lu\ngenerated q: %lu\n", BN_get_word(r->p), BN_get_word(r->q));

    /* for newer openssl version
    RSA_get0_factors(r, &p, &q);
    printf("generated p: %lu\ngenerated q: %lu\n", BN_get_word(p), BN_get_word(q));
    */

    bp_public = BIO_new_file("public.pem", "w+");
    ret = PEM_write_bio_RSAPublicKey(bp_public, r);
    if(ret != 1){
        return -2;
    }

    bp_private = BIO_new_file("private.pem", "w+");
    ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);
    BIO_free(bp_private);

    BIO *pbuf = BIO_new_file("private.pem", "r");
    RSA *rsa = PEM_read_bio_RSAPrivateKey(pbuf, NULL, NULL, NULL);
    printf("from file p: %lu\nfrom file q: %lu\n", BN_get_word(rsa->p), BN_get_word(rsa->q));

    /* for newer openssl version
    RSA_get0_factors(rsa, &p, &q);
    printf("from file p: %lu\nfrom file q: %lu\n", BN_get_word(p), BN_get_word(q));
    */

    return 0;
}
