/*
 * Example: PBKDF2-SHA256 in libgcrypt
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

static void print_out(const char *hash, const void *out, unsigned int out_len)
{
	printf("Derived key using %s\n", hash);
	hexprint((const char*)out, out_len, " ");
}

int main(int argc, char *argv[])
{
	const char *password;
	unsigned char salt[32], key[64];
	unsigned long iterations;

	/* Library initialization, use /dev/urandom */
	if (!gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P)) {
		gcry_control(GCRYCTL_SET_PREFERRED_RNG_TYPE, GCRY_RNG_TYPE_SYSTEM);
		gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);
	}
	printf("gcrypt (%s)\n", gcry_check_version(NULL));

	password = "my passphrase";
	iterations = 1000;

	printf("PBKDF2 using gcrypt:\n");
	{
		//gcry_randomize(salt, sizeof(salt), GCRY_STRONG_RANDOM);
		memset(salt, 0xab, sizeof(salt));

		if (gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2, GCRY_MD_SHA256,
			salt, sizeof(salt), iterations, sizeof(key), key))
			return 1;

		print_out("PBKDF2-SHA256", key, sizeof(key));
	}

	return 0;
}
