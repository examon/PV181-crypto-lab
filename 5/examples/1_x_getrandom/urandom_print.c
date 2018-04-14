/*
 * Example: Read few bytes from /dev/urandom through new syscall
 * and print them in hexa format.
 * NOTE: This will not even compile on old systems!
 */
#include <stdio.h>
#include <stdbool.h>
#include <sys/random.h>

/* Print buffer in HEX with optional separator */
static void hexprint(const char *d, int n, const char *sep)
{
	int i;

	for (i = 0; i < n; i++)
		printf("%02hhx%s", (const char)d[i], sep);
	printf("\n");
}

static bool urandom_get(void *buf, size_t buf_size)
{
	int r;

	/*
	 *This call is available only on recent Linux kernels > 3.19
	 * If not in glibc, you can use direct syscall interface
	 * #include <unistd.h>
	 * #include <sys/syscall.h>
	 * r = syscall(SYS_getrandom, buf, buf_size, 0);
	 */
	r = getrandom(buf, buf_size, 0);

	if (r < 0 || r != buf_size)
		return false;

	return true;
}

int main(int argc, char *argv[])
{
	char buf[32];

	if (!urandom_get(buf, sizeof(buf))) {
		fprintf(stderr, "Error reading RNG.\n");
		return 1;
	}

	hexprint(buf, sizeof(buf), " ");

	return 0;
}
