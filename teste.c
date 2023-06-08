#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    // char str[] = "a$_$c$d$";
    // char* aux = NULL;
    // aux = strtok(str, "$");
    // printf("%s\n", aux);
    // aux = strtok(NULL, "$");
    // printf("%s\n", aux);
    // aux = strtok(NULL, "$");
    // printf("%s\n", aux);
    // aux = strtok(NULL, "$");
    // printf("%s\n", aux);
    // aux = strtok(NULL, "$");
    // if(aux == NULL) printf("NULL\n");

    char a[20] = "a";
    char aux[20];
    sprintf(aux, "%d,", 1);
    strcat(a, aux);
    printf("%s", a);
    return 0;
}