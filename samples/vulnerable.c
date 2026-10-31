#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void greet(void) {
    char name[16];
    printf("Name: ");
    gets(name);
    char msg[32];
    strcpy(msg, "Hello, ");
    strcat(msg, name);
    printf(msg);
}

void run(const char *file) {
    char cmd[64];
    sprintf(cmd, "cat %s", file);
    system(cmd);
}

int main(void) {
    greet();
    run("notes.txt");
    return 0;
}
