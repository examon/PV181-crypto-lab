/*
 * Example: RNG in libsodium
 */
#include <stdio.h>
#include <stdbool.h>
#include <sodium/randombytes.h>
#include <sodium/version.h>

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

	printf("Sodium (%s) RNG:\n", sodium_version_string());
	/*
	 * Internally it is just wrapper to /dev/urandom!
	 */
	randombytes((unsigned char*)buf, sizeof(buf));
	hexprint(buf, sizeof(buf), " ");

	return 0;
}
