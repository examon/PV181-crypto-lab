/*
 * Example: Read few bytes from /dev/urandom and print them in hexa format.
 * The code tries to be extremely defensive.
 * Note it is only example of few possible approaches.
 */
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>

/* Print buffer in HEX with optional separator */
static void hexprint(const char *d, int n, const char *sep)
{
	int i;

	for (i = 0; i < n; i++)
		printf("%02hhx%s", (const char)d[i], sep);
	printf("\n");
}

/*
 * Returns false if the whole buffer is not read.
 */
__attribute__ ((warn_unused_result))
static bool urandom_get(char *buf, size_t length)
{
	int fd;
	ssize_t read_bytes;
	/* Old content of input parameters for additional defensive checks */
	struct stat stat;
	size_t old_len = length;
	char *old_buf = buf;

	fd = open("/dev/urandom", O_RDONLY);
	if (fd == -1)
		return false;

	/* Read it only if it is char device */
	if (fstat(fd, &stat) || !S_ISCHR(stat.st_mode)) {
		errno = EINVAL;
		close(fd);
		return false;
	}

	while (length) {
		read_bytes = read(fd, buf, length);

		/* If call is interrupted, repeat the call otherwise fail. */
		if (read_bytes == -1 && errno != EINTR) {
			close(fd);
			return false;
		}

		/* read() can return lower amount of bytes than expected */
		if (read_bytes > 0) {
			length -= read_bytes;
			buf    += read_bytes;
		}
	}

	/* Additional checks (could catch unintended error) */
	assert(length == 0);
	assert((size_t)(buf - old_buf) == old_len);

	close(fd);
	return true;
}

int main(int argc, char *argv[])
{
	char buf[32];

	if (!urandom_get(buf, sizeof(buf))) {
		fprintf(stderr, "Error reading RNG: %s\n", strerror(errno));
		return 1;
	}

	hexprint(buf, sizeof(buf), " ");

	return 0;
}
