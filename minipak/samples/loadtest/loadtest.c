#include <dlfcn.h>
#include <stdio.h>
#include <stdint.h>

typedef void (*premain_t)(uint64_t);

int main() {
    void *lib = dlopen("target/debug/libstage1.so", RTLD_NOW);
    if (!lib) {
        fprintf(stderr, "Could not load library libstage1.so\n");
        fprintf(
            stderr,
            "Make sure you run `cargo build` to build the stage1 crate in debug mode!\n"
            );
        return 1;
    }

    void *sym = dlsym(lib, "premain");
    if (!sym) {
        fprintf(stderr, "Could not find symbol `premain`\n");
        return 1;
    }

    premain_t premain = (premain_t) sym;

    fprintf(stderr, "Calling premain...\n");
    premain(0x1234);
}
