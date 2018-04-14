/*
 * Example: RNG in OpenSSL
 */
#include <stdio.h>
#include <stdbool.h>

/* OpenSSL includes */
#include <openssl/crypto.h>
#include <openssl/rand.h>

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

	printf("OpenSSL (%s) RNG (RAND_status() = %d):\n", SSLeay_version(SSLEAY_VERSION), RAND_status());
	/* See man RAND_seed():
	 * On systems that provide "/dev/urandom", the randomness device
	 * is used to seed the PRNG transparently.
	 */
	if (RAND_bytes((unsigned char*)buf, sizeof(buf)) != 1) {
		printf("RNG error.\n");
		return 1;
	}

	hexprint(buf, sizeof(buf), " ");

	return 0;
}
