/* Eval fixture: license check with an XOR-obfuscated secret. */
#include <stdio.h>
#include <string.h>

static const unsigned char kEnc[] = {0x18, 0x0f, 0x0b, 0x75, 0x13, 0x19, 0x0e, 0x6b}; /* "REA?YSD!" ^ 0x4a */

__attribute__((noinline)) static void decode(char *out) {
    for (int i = 0; i < 8; i++) out[i] = (char)(kEnc[i] ^ 0x4a);
    out[8] = 0;
}

__attribute__((noinline)) int validate_key(const char *key) {
    char secret[9];
    if (strlen(key) != 12) return 0;
    if (key[4] != '-') return 0;
    decode(secret);
    if (strncmp(key, secret, 4) != 0) return 0;
    int sum = 0;
    for (int i = 5; i < 12; i++) sum += key[i];
    return sum % 7 == 3;
}

int main(int argc, char **argv) {
    if (argc < 2) { puts("usage: crackme <key>"); return 2; }
    if (validate_key(argv[1])) { puts("ok"); return 0; }
    puts("invalid key");
    return 1;
}
