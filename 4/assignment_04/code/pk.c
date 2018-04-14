#include "RSAPrivateKey.h"

int main(int argc, char **argv)
{
    if (argc != 2) {
        printf("Need key as an input!\n");
        exit(1);
    }

    RSAPrivateKey_t *k;
    k = (RSAPrivateKey_t*)calloc(1, sizeof *k);
    if(!k)
        exit(1);

    FILE *f=fopen(argv[1],"rb");
    if(!f)
        exit(1);

    unsigned char buffer[10000];
    int bufflen;

    bufflen=fread(buffer,1,10000,f);
    fclose(f);
    asn_dec_rval_t rval = ber_decode(0,&asn_DEF_RSAPrivateKey ,(void**)&k,buffer,bufflen);

    if(rval.code != RC_OK)
        exit(1);

    for (int i=0; i < k->publicExponent.size; i++) {
        if (i == k->publicExponent.size - 1) {
            printf("%02X\n", k->publicExponent.buf[i]);
        } else {
            printf("%02X:", k->publicExponent.buf[i]);
        }
    }
    return 0;
}
