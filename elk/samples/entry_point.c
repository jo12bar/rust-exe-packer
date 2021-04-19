#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/mman.h>
#include <errno.h>

const char *instructions = "\x48\x31\xFF\xB8\x3C\x00\x00\x00\x0F\x05";
const size_t instructions_len = 10;

int main() {
    printf("        main @ %p\n", &main);
    printf("instructions @ %p\n", instructions);

    size_t region = (size_t) instructions;
    region = region & (~0xFFF);
    printf("        page @ %p\n", region);

    printf("Making page executable...\n");
    int ret = mprotect(
        (void*) region,
        0x1000,
        PROT_READ | PROT_EXEC
    );
    if (ret != 0) {
        printf("mprotect failed: error %d\n", errno);
        return 1;
    }

    void (*f)(void) = (void*) instructions;
    printf("Jumping...\n");
    f();
    printf("After jump!\b\n");

    return 0;
}
