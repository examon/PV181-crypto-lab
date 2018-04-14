/*
 * Example: HASH and HMAC in OpenSSL 1.1.0 (and older)
 */
#include <stdio.h>
#include <string.h>

/* OpenSSL includes */
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

/* Print buffer in HEX with optional separator */
static void hexprint(const char *d, int n, const char *sep)
{
	int i;

	for (i = 0; i < n; i++)
		printf("%02hhx%s", (const char)d[i], sep);
	printf("\n");
}

static void print_out(const char *hash, const char *text,
		      const void *expected_out, const void *out,
		      unsigned int out_len)
{
	printf("Input (hash %s): %s\n", hash, text);
	printf("Expected output: ");
	hexprint((const char*)expected_out, out_len, " ");
	printf("Hashed output:   ");
	hexprint((const char*)out, out_len, " ");
}

/*
 * Compatible wrappers for OpenSSL < 1.1.0
 * All older version have to use malloc() for context.
 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
static EVP_MD_CTX *EVP_MD_CTX_new(void)
{
	EVP_MD_CTX *md = malloc(sizeof(*md));

	if (md)
		EVP_MD_CTX_init(md);

	return md;
}

static void EVP_MD_CTX_free(EVP_MD_CTX *md)
{
	EVP_MD_CTX_cleanup(md);
	free(md);
}

static HMAC_CTX *HMAC_CTX_new(void)
{
	HMAC_CTX *md = malloc(sizeof(*md));

	if (md)
		HMAC_CTX_init(md);

	return md;
}

static void HMAC_CTX_free(HMAC_CTX *md)
{
	HMAC_CTX_cleanup(md);
	free(md);
}
#endif

int main(int argc, char *argv[])
{
	const char *hash_name, *text, *expected_out, *key;
	int key_len;
	unsigned char out[32];
	unsigned int out_len;

	/* Library initialization */
	OpenSSL_add_all_algorithms();
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	printf("OpenSSL (%s):\n", SSLeay_version(SSLEAY_VERSION));
#else
	printf("OpenSSL (%s):\n", OpenSSL_version(OPENSSL_VERSION));
#endif
	/*
	 * HASH
	 */
	hash_name = "sha256";
	text = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	expected_out =
		"\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39"
		"\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1";

	/* OpenSSL HASH using EVP */
	printf("HASH using EVP interface:\n");
	{
		const EVP_MD *hash_id;
		EVP_MD_CTX *md;
		/*
		* Check hash algorithm is available and
		* that buffer is large enough
		*/
		hash_id = EVP_get_digestbyname(hash_name);
		if (!hash_id)
			return 1;

		if (EVP_MD_size(hash_id) > (int)sizeof(out))
			return 1;

		/* Create context */
		md = EVP_MD_CTX_new();
		if (!md)
			return 1;

		/* Calculate hash */
		if (EVP_DigestInit(md, hash_id) != 1)
			return 1;

		if (EVP_DigestUpdate(md, text, strlen(text)) != 1)
			return 2;

		if (EVP_DigestFinal(md, out, &out_len) != 1)
			return 2;

		EVP_MD_CTX_free(md);

		print_out(hash_name, text, expected_out, out, out_len);
	}

	/* OpenSSL HASH - non-EVP version */
	printf("HASH using SHA256 directly:\n");
	{
		SHA256_CTX sha256;

		if (SHA256_Init(&sha256) != 1)
			return 1;

		if (SHA256_Update(&sha256, text, strlen(text)) != 1)
			return 2;

		if (SHA256_Final(out, &sha256) != 1)
			return 2;

		print_out(hash_name, text, expected_out, out, out_len);
	}

	/*
	 * HMAC (keyed hash)
	 */
	hash_name = "sha256";
	text = "Hi There";
	key = "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b";
	key_len = 20;
	expected_out =
		"\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b"
		"\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7";

	/* OpenSSL HMAC (keyed hash) */
	printf("HMAC using EVP interface:\n");
	{
		const EVP_MD *hash_id;
		HMAC_CTX *md;

		/*
		* Check hash algorithm is available and
		* that buffer is large enough
		*/
		hash_id = EVP_get_digestbyname(hash_name);
		if (!hash_id)
			return 1;

		if (EVP_MD_size(hash_id) > (int)sizeof(out))
			return 1;

		/* Create context */
		md = HMAC_CTX_new();
		if (!md)
			return 1;

		/* Calculate HMAC */
		/* Note that for OpenSSL < 1.0.0 the functions are void (no return values) ! */
		/* if (HMAC_Init(md, key, key_len, hash_id) != 1) */
		if (HMAC_Init_ex(md, key, key_len, hash_id, NULL) != 1)
			return 1;

		if (HMAC_Update(md, (const unsigned char *)text, strlen(text)) != 1)
			return 2;

		if (HMAC_Final(md, out, &out_len) != 1)
			return 2;

		HMAC_CTX_free(md);

		print_out(hash_name, text, expected_out, out, out_len);
	}

	/* For short messages simplified interface can be used */
	printf("HMAC using simplified interface:\n");
	{
		if (!HMAC(EVP_sha256(), key, key_len, (const unsigned char *)text, strlen(text), out, &out_len))
			return 2;

		print_out(hash_name, text, expected_out, out, out_len);
	}

	return 0;
}
