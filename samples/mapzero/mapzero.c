#include <stdio.h>
#include <sys/mman.h>

int main() {
    unsigned long long *ptr = mmap(
        0x0, 0x1000,
        PROT_READ | PROT_WRITE,
        MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
        0, 0
    );

    printf("Writing to 0x0...\n");
    *ptr = 0xfeedface;
    printf("Reading to 0x0...\n");
    printf("*ptr = 0x%llx\n", *ptr);
    return 0;
}
