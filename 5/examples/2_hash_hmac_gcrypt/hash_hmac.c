/*
 * Example: HASH and HMAC in libgcrypt
 */
#include <stdio.h>
#include <string.h>
#include <gcrypt.h>

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

int main(int argc, char *argv[])
{
	const char *hash_name, *text, *expected_out, *key;
	int key_len;
	unsigned char out[32];
	unsigned int out_len;

	/* Library initialization */
	if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P))
		gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
	printf("gcrypt (%s)\n", gcry_check_version(NULL));

	/*
	 * HASH
	 */
	hash_name = "sha256";
	text = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	expected_out =
		"\x24\x8d\x6a\x61\xd2\x06\x38\xb8\xe5\xc0\x26\x93\x0c\x3e\x60\x39"
		"\xa3\x3c\xe4\x59\x64\xff\x21\x67\xf6\xec\xed\xd4\x19\xdb\x06\xc1";

	printf("HASH using gcrypt:\n");
	{
		int hash_id;
		unsigned char *out_hd;
		gcry_md_hd_t hd;

		/*
		* Check hash algorithm is available and
		* that buffer is large enough
		*/
		hash_id = gcry_md_map_name(hash_name);
		if (!hash_id)
			return 1;

		out_len = gcry_md_get_algo_dlen(hash_id);
		if (out_len > sizeof(out))
			return 1;

		/* Calculate hash */
		if (gcry_md_open(&hd, hash_id, 0))
			return 1;

		gcry_md_write(hd, text, strlen(text));

		out_hd = gcry_md_read(hd, hash_id);
		if (!out_hd)
			return 2;

		print_out(hash_name, text, expected_out, out_hd, out_len);

		gcry_md_close(hd);
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

	printf("HMAC using gcrypt interface:\n");
	{
		int hash_id;
		unsigned char *out_hd;
		gcry_md_hd_t hd;
		/*
		* Check hash algorithm is available and
		* that buffer is large enough
		*/
		hash_id = gcry_md_map_name(hash_name);
		if (!hash_id)
			return 1;

		out_len = gcry_md_get_algo_dlen(hash_id);
		if (out_len > sizeof(out))
			return 1;

		/* Calculate hash */
		if (gcry_md_open(&hd, hash_id, GCRY_MD_FLAG_HMAC))
			return 1;

		if (gcry_md_setkey(hd, key, key_len))
			return 2;

		gcry_md_write(hd, text, strlen(text));

		out_hd = gcry_md_read(hd, hash_id);
		if (!out_hd)
			return 2;

		print_out(hash_name, text, expected_out, out_hd, out_len);

		gcry_md_close(hd);
	}

	return 0;
}
