#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define TIMEOUT_MS 3000

__attribute__((noinline)) int parse_args(int argc, char **argv, int *verbose) {
    *verbose = 0;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--verbose") == 0) *verbose = 1;
        else if (strcmp(argv[i], "--legacy-mode") == 0) *verbose = 2;
    }
    return 0;
}

__attribute__((noinline)) int sync_data(int verbose) {
    int timeout = TIMEOUT_MS;
    if (verbose) printf("syncing with timeout %d\n", timeout);
    return timeout > 1000 ? 0 : 1;
}

int main(int argc, char **argv) {
    int verbose;
    parse_args(argc, argv, &verbose);
    return sync_data(verbose);
}
