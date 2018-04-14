#include <stdio.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>

/* Never ever hardcode secure keys in code ;-) */
const unsigned char *KEY = (const unsigned char*)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f";

/* And also IV (Initialization vector) should be generated randomly... */
const unsigned char *IV  = (const unsigned char*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";

/* Subdirectory with certificates */
#define CERT_DIR "./root"

/* Pasword to generated PKCS12 file */
#define PKCS12_PASSWORD "mypassword"
#define PKCS12_PASSWORD_LEN 10
#define PKCS12_FILE_NAME CERT_DIR"/sub-ca.p12"

/* Encrypted and signed file */
#define DATA_FILE_NAME "signed_and_encrypted_file.txt"

int main(int argc, char *argv[])
{

	X509 *signer = NULL;
	EVP_PKEY *key = NULL;
	BIO *data_out;

	/* Some data to sign and encrypt */
	struct data {
		char name[100];
		char surname[100];
	} record1 = { "Jon", "Doe" };
	struct data *record_out = NULL;

	/* library initialization */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	ERR_load_OBJ_strings();

	/* reads a certificate and a private key from PKCS#12 file */
	{
		BIO *pkcs12file = BIO_new_file(PKCS12_FILE_NAME, "rb");
		PKCS12 *p12 = d2i_PKCS12_bio(pkcs12file, NULL);

		if (!p12 || !PKCS12_verify_mac(p12, PKCS12_PASSWORD, PKCS12_PASSWORD_LEN))
			printf("Cannot verify PKCS12 file.\n");

		PKCS12_parse(p12, PKCS12_PASSWORD, &key, &signer, NULL);
		PKCS12_free(p12);
		BIO_free(pkcs12file);
	}

	/* Sign and encrypt file containing record structure with BIO interface */
	{
		BIO *in_record = BIO_new_mem_buf(&record1, sizeof(struct data));
		BIO *out_signed = BIO_new_file(DATA_FILE_NAME, "wb");

		PKCS7 *p7 = PKCS7_sign(signer, key, NULL, in_record, PKCS7_BINARY);

		BIO *encipher = BIO_new(BIO_f_cipher());
		BIO *out_encrypted = BIO_push(encipher, out_signed);

		BIO_set_cipher(out_encrypted, EVP_aes_128_cbc(), KEY, IV, 1);

		i2d_PKCS7_bio(out_encrypted, p7);

		BIO_flush(out_encrypted);

		BIO_free(in_record);
		BIO_free_all(out_encrypted);
	}

	/* Decrypt file and verify signature, including cert chain. CRL is not used. */
	{
		BIO *p7_in, *decipher;
		PKCS7 *read_p7;

		X509_STORE *store = X509_STORE_new();
		STACK_OF(X509) *othercerts = sk_X509_new_null();
		X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir());

		X509_LOOKUP_add_dir(lookup, CERT_DIR, X509_FILETYPE_PEM);
		sk_X509_push(othercerts, signer);

		p7_in = BIO_new_file(DATA_FILE_NAME, "rb");
		decipher = BIO_new(BIO_f_cipher());

		BIO_set_cipher(decipher, EVP_aes_128_cbc(), KEY, IV, 0);
		p7_in = BIO_push(decipher,p7_in);
		data_out = BIO_new(BIO_s_mem());

		read_p7 = d2i_PKCS7_bio(p7_in, NULL);

		if (PKCS7_verify(read_p7, othercerts, store, NULL, data_out, PKCS7_NOCRL|PKCS7_BINARY))
			printf("Signature verified\n");
		else
			printf("Signature verification failed\n");

		BIO_free_all(p7_in);
	}

	/* Check the length of decrypted data */
	if (BIO_get_mem_data(data_out, &record_out) != sizeof(struct data))
		printf("Size of data does not match\n");
	else
		printf("The data is '%s %s'\n",record_out->name, record_out->surname);

	BIO_free(data_out);

	return 0;
}
