/*
 * Example: HASH and HMAC in libsodium
 */
#include <stdio.h>
#include <string.h>
#include <sodium/version.h>
#include <sodium/crypto_auth.h>
#include <sodium/crypto_hash_sha256.h>
#include <sodium/crypto_auth_hmacsha256.h>

/* Print buffer in HEX with optional separator */
static void hexprint(const unsigned char *d, int n, const char *sep)
{
	int i;

	for (i = 0; i < n; i++)
		printf("%02hhx%s", (const char)d[i], sep);
	printf("\n");
}

static void print_out(const char *hash, const unsigned char *text,
		      const unsigned char *expected_out, const unsigned char *out,
		      unsigned int out_len)
{
	printf("Input (hash %s): %s\n", hash, text);
	printf("Expected output: ");
	hexprint(expected_out, out_len, " ");
	printf("Hashed output:   ");
	hexprint(out, out_len, " ");
}

int main(int argc, char *argv[])
{
	const unsigned char *expected_out, *text;
	unsigned char key[crypto_auth_KEYBYTES];
	unsigned char out[crypto_auth_BYTES];
	int key_len;
	unsigned long long text_len;

	/* Library initialization */
	printf("Sodium (%s) RNG:\n", sodium_version_string());

	/*
	 * HASH
	 */
	text = (const unsigned char *)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	text_len = strlen((const char*)text);
	expected_out = (const unsigned char *)
		"\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39"
		"\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1";

	/* libsodium HASH */
	printf("HASH using libsodium:\n");
	{
		crypto_hash_sha256_state state;

		if (crypto_hash_sha256_init(&state))
			return 1;
		if (crypto_hash_sha256_update(&state, text, text_len))
			return 2;
		if (crypto_hash_sha256_final(&state, out))
			return 2;

		print_out("sha256", text, expected_out, out, crypto_hash_sha256_BYTES);
	}

	/* libsodium HASH simple interface */
	printf("HASH using libsodium (one call):\n");
	{
		if (crypto_hash_sha256(out, text, text_len))
			return 1;

		print_out("sha256", text, expected_out, out, crypto_hash_sha256_BYTES);
	}

	/*
	 * HMAC (keyed hash)
	 */
	text = (const unsigned char *)"Hi There";
	text_len = strlen((const char*)text);
	key_len = 20;
	memcpy(key, "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", key_len);
	expected_out = (const unsigned char *)
		"\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b"
		"\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7";

	/* libsodium HMAC (keyed hash) */
	printf("HMAC using libsodium:\n");
	{
		crypto_auth_hmacsha256_state state;

		if (crypto_auth_hmacsha256_init(&state, key, key_len))
			return 1;
		if (crypto_auth_hmacsha256_update(&state, text, text_len))
			return 2;
		if (crypto_auth_hmacsha256_final(&state, out))
			return 2;

		print_out("sha256", text, expected_out, out, crypto_auth_hmacsha256_BYTES);
	}

	/* NaCl intended way - simple auth interface */
	expected_out =	(const unsigned char *)
		"\xcf\x76\x8c\x6f\xd3\xf0\x8f\x64\x0f\x77\x9d\xdb\xd9\xbc\x38\x42"
		"\xfe\x78\xa2\x61\xf1\x97\xda\x9c\x4a\x95\x85\x10\xac\x82\x26\xdb";
	/* This should be random :-) */
	memset(key, '\x0b', crypto_auth_KEYBYTES);

	printf("HMAC using libsodium (default algorithm is %s)\n", crypto_auth_primitive());
	{
		/* Calculate HMAC */
		if (crypto_auth(out, text, text_len, key))
			return 1;

		print_out(crypto_auth_primitive(), text, expected_out, out, crypto_auth_hmacsha256_BYTES);

		/* Calculate and verify */
		if (crypto_auth_verify(expected_out, text, text_len, key))
			printf("Verify failed.\n");
		else
			printf("Verify OK.\n");
	}

	return 0;
}
