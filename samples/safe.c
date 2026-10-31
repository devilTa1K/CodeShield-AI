#include <stdio.h>
#include <string.h>

int greet(void) {
    char name[16];
    char msg[32];
    printf("Name: ");
    if (fgets(name, sizeof name, stdin) == NULL) {
        return -1;
    }
    name[strcspn(name, "\n")] = '\0';
    int n = snprintf(msg, sizeof msg, "Hello, %s", name);
    if (n < 0 || (size_t)n >= sizeof msg) {
        return -1;
    }
    printf("%s\n", msg);
    return 0;
}

int main(void) {
    return greet() == 0 ? 0 : 1;
}
