#include <stdio.h>
#include <time.h>
#include <stdlib.h>

int main() {
    fopen("K.bin", "w"); // clear file if it exists
    FILE *f = fopen("K.bin", "ab");
    srand(time(NULL)); // seed prng by time since unix epoch

    // write 128 random bytes to K.bin
    for (int i = 0; i < 128; i++) {
        char x = rand();
        fwrite(&x, sizeof x, 1, f);
    }
    return 0;
}
