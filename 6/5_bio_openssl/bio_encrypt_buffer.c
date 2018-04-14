/* Encrypt text buffer using BIO interface. */
#include <openssl/evp.h>
#include <string.h>

/* Never ever hardcode secure keys in code ;-) */
const unsigned char *KEY = (const unsigned char*)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

/* And also IV (Initialization vector) should be generated randomly... */
const unsigned char *IV  = (const unsigned char*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";

static int encrypt(const unsigned char *plaintext, int plaintext_len,
		   const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext)
{
	BIO *out = BIO_new(BIO_s_mem());
	BIO *encipher = BIO_new(BIO_f_cipher());
	int ciphertext_len;
	char *ptr;

	BIO *out_encrypted = BIO_push(encipher, out);
	BIO_set_cipher(out_encrypted, EVP_aes_256_cbc(), KEY, IV, 1);

	BIO_write(out_encrypted, plaintext, plaintext_len);

	BIO_flush(out_encrypted);

	ciphertext_len = BIO_get_mem_data(out_encrypted, &ptr);
	memcpy(ciphertext, ptr, ciphertext_len);

	BIO_free_all(out_encrypted);

	return ciphertext_len;
}

static int decrypt(const unsigned char *ciphertext, int ciphertext_len,
		   const unsigned char *key, const unsigned char *iv, unsigned char *plaintext)
{
	BIO *out = BIO_new(BIO_s_mem());
	BIO *decipher = BIO_new(BIO_f_cipher());
	int plaintext_len;
	BUF_MEM *ptr;

	BIO *out_decrypted = BIO_push(decipher, out);
	BIO_set_cipher(out_decrypted, EVP_aes_256_cbc(), KEY, IV, 0);

	BIO_write(out_decrypted, ciphertext, ciphertext_len);

	BIO_flush(out_decrypted);

	plaintext_len = BIO_get_mem_data(out_decrypted, &ptr);
	memcpy(plaintext, ptr, plaintext_len);

	BIO_free_all(out_decrypted);

	return plaintext_len;
}

int main(int argc, char *argv[])
{
	const unsigned char *plaintext;
	unsigned char ciphertext[128], decrypted_plaintext[128];
	int decryptedtext_len, ciphertext_len;

	/* We intentionally repeat the first block twice - see what happens if ECB is used! */
	/* Also see what happens in CBC mode when you use different IV for decryption. */
	plaintext = (const unsigned char *)"The quick brown The quick brown fox jumps over the lazy dog";

	/* Initialise the library */
	OpenSSL_add_all_algorithms();

	/* Encrypt the plaintext */
	ciphertext_len = encrypt(plaintext, strlen ((const char *)plaintext), KEY, IV, ciphertext);

	printf("Ciphertext is:\n");
	BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);

	/* Decrypt the ciphertext */
	decryptedtext_len = decrypt(ciphertext, ciphertext_len, KEY, IV, decrypted_plaintext);

	printf("Decrypted text is:\n");
	decrypted_plaintext[decryptedtext_len] = '\0';
	printf("%s\n", decrypted_plaintext);

	EVP_cleanup();

	return 0;
}
