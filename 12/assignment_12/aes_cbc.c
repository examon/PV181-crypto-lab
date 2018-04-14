/* Tomas Meszaros - 422336
 *
 * Encrypt and print data using AES 128 CBC
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <gnutls/crypto.h>

const char *data = "The quick brown The quick brown fox jumps over the lazy dog";
const unsigned char *KEY = (const unsigned char*)"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";
const unsigned char *IV  = (const unsigned char*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08";


int main() {
	gnutls_cipher_hd_t handle;
	gnutls_datum_t k;
	k.data = (unsigned char *) KEY;
	k.size = 16;
	gnutls_datum_t iv;
	iv.data = (unsigned char *) IV;
	iv.size = 16;
	int data_len = strlen(data) + 1;

	char *buf = malloc(sizeof(char) * data_len);
	int i;
	for (i = 0; i < data_len; i++) {
		buf[i] = data[i];
	}
	buf[i] = '\0';

	for (int j = 0; j < data_len; j++) {
		printf("%c", buf[j]);
	}
	printf("\n\n");

	if (gnutls_cipher_init(&handle, GNUTLS_CIPHER_AES_128_CBC, &k, &iv) != 0)
		return 100;
	if (gnutls_cipher_encrypt(handle, buf, (size_t) data_len) != 0)
		return 200;

	for (int j = 0; j < data_len; j++) {
		printf("%02hhx ", buf[j]);
		if ((j + 1) % 16 == 0)
			printf("\n");
	}
	printf("\n");

	return 0;
}
