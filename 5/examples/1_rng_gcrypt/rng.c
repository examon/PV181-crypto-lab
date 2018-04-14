/*
 * Example: RNG in gcrypt
 */
#include <stdio.h>
#include <stdbool.h>

/* libgcrypt include */
#include <gcrypt.h>

/* Print buffer in HEX with optional separator */
static void hexprint(const char *d, int n, const char *sep)
{
	int i;

	for (i = 0; i < n; i++)
		printf("%02hhx%s", (const char)d[i], sep);
	printf("\n");
}

int main(int argc, char *argv[])
{
	char buf[32];

	//gcry_control(GCRYCTL_SET_PREFERRED_RNG_TYPE, GCRY_RNG_TYPE_SYSTEM);
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
	printf("gcrypt (%s) RNG:\n", gcry_check_version(NULL));
	gcry_randomize(buf, sizeof(buf), GCRY_STRONG_RANDOM);
	hexprint(buf, sizeof(buf), " ");

	return 0;
}
