#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#define BUFSZ 2048
#define MAX_CLIENTS 3

void usageExit(int argc, char **argv) {
    printf("Client usage: %s <server IP> <server port>\n", argv[0]);
    printf("Ex: %s 127.0.0.1 51511\n", argv[0]); // IPv4 loopback
    printf("Ex: %s ::1 51511\n", argv[0]); // IPv6 loopback
    exit(EXIT_FAILURE);
}

void msgExit(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int addrparse(const char *addrstr, const char *portstr, struct sockaddr_storage *storage) {
    // AF_INET = IPv4, AF_INET6 = IPv6
    if(addrstr == NULL || portstr == NULL) return -1;

    uint16_t port = (uint16_t)atoi(portstr); // unsigned short, 16 bits
    if(port == 0) return -1;

    port = htons(port); // converte para network byte order, host to network short

    struct in_addr inaddr4; // IPv4, 32 bits
    // inet presentation to network
    if(inet_pton(AF_INET, addrstr, &inaddr4)) {
        // converte para sockaddr_in (IPv4) e armazena em storage
        struct sockaddr_in *addr4 = (struct sockaddr_in *)storage;
        addr4->sin_family = AF_INET;
        addr4->sin_port = port;
        addr4->sin_addr = inaddr4;
        return 0;
    }

    struct in6_addr inaddr6; // IPv6, 128 bits
    if(inet_pton(AF_INET6, addrstr, &inaddr6)) {
        // converte para sockaddr_in6 (IPv6) e armazena em storage
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)storage;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = port;
        // addr6->sin6_addr = inaddr6; não funciona, pois inaddr6 é um array de 16 bytes
        // memcpy(destino, origem, tamanho)
        memcpy(&(addr6->sin6_addr), &inaddr6, sizeof(inaddr6));
        return 0;
    }

    return -1;
}

void addrtostr(const struct sockaddr *addr, char *str, size_t strsize) {
    int version;
    char addrstr[INET6_ADDRSTRLEN + 1] = ""; // pode ser IPv4 ou IPv6
    uint16_t port;

    if(addr->sa_family == AF_INET) {
        version = 4;
        struct sockaddr_in *addr4 = (struct sockaddr_in *)addr;
        // inet network to presentation
        if(!inet_ntop(AF_INET, &(addr4->sin_addr), addrstr, INET6_ADDRSTRLEN + 1))
            msgExit("ntop ipv4 failed");
        // network to host short
        port = ntohs(addr4->sin_port);
    } else if(addr->sa_family == AF_INET6) {
        version = 6;
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)addr;
        // inet network to presentation
        // AF_INET6 or AF_INET?
        if(!inet_ntop(AF_INET6, &(addr6->sin6_addr), addrstr, INET6_ADDRSTRLEN + 1))
            msgExit("ntop ipv6 failed");
        // network to host short
        port = ntohs(addr6->sin6_port);
    } else msgExit("addrtostr() failed, unknown protocol");

    if(str) snprintf(str, strsize, "IPv%d %s %hu", version, addrstr, port);
}

int clientIndexes[MAX_CLIENTS];
int thisClientIndex = -2;

void* processStdin(void *sockNum) {
    int count = 0;
    char buffer[BUFSZ];
    long sock = (long)sockNum;

    while(1) {
        memset(buffer, 0, BUFSZ);
        pthread_testcancel();
        fgets(buffer, BUFSZ-1, stdin);

        if(strncmp(buffer, "close connection", 16) == 0) {
            memset(buffer, 0, BUFSZ);
            sprintf(buffer, "02$%d$_$_$", thisClientIndex);
            count = send(sock, buffer, strlen(buffer)+1, 0);
            if(count != strlen(buffer)+1) msgExit("send() failed, msg size mismatch");
        }

        if(strncmp(buffer, "list users", 10) == 0) {
            int foundOne = 0;
            for(int i = 0; i < MAX_CLIENTS; i++) {
                if(clientIndexes[i] != 0) {
                    if(foundOne) printf(" %02d", i+1);
                    else printf("%02d", i+1);
                    foundOne = 1;
                }
            }
            if(foundOne) printf("\n");
        }

        if(strncmp(buffer, "send to ", 8) == 0) {
            char *token = strtok(buffer, " "); // send
            token = strtok(NULL, " ");         // to
            token = strtok(NULL, " ");         // dest
            if(token == NULL) continue;
            int idUserDest = atoi(token) - 1;
            token = strtok(NULL, "");          // msg
            if(token == NULL) continue;
            char msg[BUFSZ - 8 - 17]; // -8 dos separadores e outros conteúdos da MSG e -17 da marca "P" e da marca de tempo.
            strcpy(msg, token);

            memset(buffer, 0, BUFSZ);
            sprintf(buffer, "06$%d$%d$%s$", thisClientIndex, idUserDest, msg);
            // printf("buffer: %s\n", buffer);
            count = send(sock, buffer, strlen(buffer)+1, 0);
            if(count != strlen(buffer)+1) msgExit("send() failed, msg size mismatch");
        }

        // envia mensagem para o servidor, +1 para contar o '\0', count conta os bytes enviados
        // count = send(sock, buffer, strlen(buffer)+1, 0);
        // if(count != strlen(buffer)+1) msgExit("send() failed, msg size mismatch");
    }

    pthread_exit(NULL);
}


int main(int argc, char **argv) {
    if(argc < 3 || argc > 3) usageExit(argc, argv);


    // estrutura que armazena endereço ipv4 ou ipv6
    struct sockaddr_storage storage;
    if (addrparse(argv[1], argv[2], &storage) != 0) usageExit(argc, argv);

    int sock;
    //IPv4 ou IPv6, TCP, IP
    sock = socket(storage.ss_family, SOCK_STREAM, 0);
    if(sock < 0) msgExit("socket() failed");

    struct sockaddr *addr = (struct sockaddr *)(&storage);
    if(connect(sock, addr, sizeof(storage)) != 0) msgExit("connect() failed");

    char addrstr[BUFSZ];
    addrtostr(addr, addrstr, BUFSZ);
    printf("Connected to %s\n", addrstr);

    // char bufferRes[BUFSZ];
    char bufferRes[BUFSZ];
    // memset(bufferRes, 0, BUFSZ);

    for(int i = 0; i < MAX_CLIENTS; i++) clientIndexes[i] = 0;

    pthread_t t_stdin;
    long sockNum = (long)sock;
    if(pthread_create(&t_stdin, NULL, processStdin, (void *)sockNum) !=0) msgExit("pthread_create() failed");

    while(1) {
        // recebe mensagem do servidor e coloca em buffer em ordem
        // variavel total é necessaria pois não recebemos tudo de uma vez
        memset(bufferRes, 0, BUFSZ);
        // unsigned total = 0;
        // while(1) {
        //     count = recv(sock, bufferRes + total, BUFSZ - total, 0);
        //     if (count == 0) break;
        //     total += count;
        // }
        int count = recv(sock, bufferRes, BUFSZ+1, 0);

        char *idMsg = strtok(bufferRes, "$");
        char *idSender = strtok(NULL, "$");
        char *idReceiver = strtok(NULL, "$");
        char *message = strtok(NULL, "$");

        if(strcmp(idMsg, "02") == 0) {
            int senderIndex = atoi(idSender);
            clientIndexes[senderIndex] = 0;
            printf("User %02d left the group!\n", senderIndex+1);
        }
        if(strcmp(idMsg, "04") == 0) {
            char *aux = strtok(message, ",");
            while(aux != NULL) {
                clientIndexes[atoi(aux)] = 1;
                aux = strtok(NULL, ",");
            }
        }
        if(strcmp(idMsg, "06") == 0) {
            if(strcmp(idReceiver, "_") == 0) {
                clientIndexes[atoi(idSender)] = 1;
                if(thisClientIndex == -2) thisClientIndex = atoi(idSender); // -2 significa que ainda não foi definido
            }
            printf("%s", message);
        }
        if(strcmp(idMsg, "07") == 0) {
            if(strcmp(message, "01") == 0) {
                printf("User limit exceeded\n");
                break;
            }
            if(strcmp(message, "02") == 0) {
                printf("User not found\n");
            }
            if(strcmp(message, "03") == 0) {
                printf("Receiver not found\n");
            }
        }
        if(strcmp(idMsg, "08") == 0) {
            printf("Removed Successfully\n");
            break;
        }
        printf("Client indexes: \n");
        for(int i = 0; i < MAX_CLIENTS; i++) printf("%d\n", clientIndexes[i]);
        printf("This client index: %d\n", thisClientIndex);
    }
    printf("ended\n");
    // kill the thread
    pthread_cancel(t_stdin);
    pthread_join(t_stdin, NULL);
    close(sock);
    exit(EXIT_SUCCESS);
}