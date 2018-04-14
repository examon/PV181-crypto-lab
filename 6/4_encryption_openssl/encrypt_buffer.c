/* Encrypt text buffer using EVP, example based on OpenSSL manual */
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

/* Never ever hardcode secure keys in code ;-) */
const unsigned char *KEY = (const unsigned char*)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

/* And also IV (Initialization vector) should be generated randomly... */
const unsigned char *IV  = (const unsigned char*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";

static void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

static int encrypt(const unsigned char *plaintext, int plaintext_len,
		   const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int ciphertext_len;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

	/* Initialise the encryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits */
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
		handleErrors();

	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
		handleErrors();

	ciphertext_len = len;

	/* Finalise the encryption. Further ciphertext bytes may be written at this stage. */
	if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
		handleErrors();

	ciphertext_len += len;

	EVP_CIPHER_CTX_free(ctx);

	return ciphertext_len;
}

static int decrypt(const unsigned char *ciphertext, int ciphertext_len,
		   const unsigned char *key, const unsigned char *iv, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int plaintext_len;

	if (!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
		handleErrors();

	if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1)
		handleErrors();

	plaintext_len = len;

	if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
		handleErrors();

	plaintext_len += len;

	EVP_CIPHER_CTX_free(ctx);

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
	ERR_load_crypto_strings();
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
	ERR_free_strings();

	return 0;
}
