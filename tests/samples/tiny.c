#include <stdio.h>

static int add(int a, int b) { return a + b; }
static int secret_check(const char *s) {
    int h = 0;
    for (int i = 0; s[i]; i++) h = (h * 31 + s[i]) & 0xffff;
    return h == 0x1f2e;
}

int main(int argc, char **argv) {
    printf("sum=%d\n", add(argc, 41));
    if (argc > 1 && secret_check(argv[1])) puts("match");
    return 0;
}
