#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#define BUFSZ 2048
#define MAX_CLIENTS 3

void usageExit(int argc, char **argv) {
    printf("Server usage: %s <v4|v6> <server port>\n", argv[0]);
    printf("Ex: %s v4 51511\n", argv[0]);
    printf("Ex: %s v6 51511\n", argv[0]);
    exit(EXIT_FAILURE);
}

void msgExit(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

int serverAddrInit(const char *proto, const char *portstr, struct sockaddr_storage *storage) {
    // AF_INET = IPv4, AF_INET6 = IPv6
    if(proto == NULL || portstr == NULL) return -1;

    uint16_t port = (uint16_t)atoi(portstr); // unsigned short, 16 bits
    if(port == 0) return -1;
    port = htons(port);

    memset(storage, 0, sizeof(*storage));
    if(strcmp(proto, "v4") == 0) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)storage;
        addr4->sin_family = AF_INET;
        addr4->sin_addr.s_addr = INADDR_ANY; // qualquer endereço na interface de rede
        addr4->sin_port = port;
        return 0;
    } else if(strcmp(proto, "v6") == 0) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)storage;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_addr = in6addr_any;
        addr6->sin6_port = port;
        return 0;
    }
    else return -1;
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
        if(!inet_ntop(AF_INET6, &(addr6->sin6_addr), addrstr, INET6_ADDRSTRLEN + 1))
            msgExit("ntop ipv6 failed");
        // network to host short
        port = ntohs(addr6->sin6_port);
    } else msgExit("addrtostr() failed, unknown protocol");

    if(str) snprintf(str, strsize, "IPv%d %s %hu", version, addrstr, port);
}

typedef struct command{
    int idMsg;
    int idSender;
    int idReceiver; 
    char message[BUFSZ]; 
} command;

typedef struct clientSockets {
    // -2 = vazio, >= 0 = socket válido
    int list[MAX_CLIENTS];
    int clientCount;
} clientSockets;

clientSockets clients;

struct clientData {
    int clientSocket;
    int clientIndex;
    struct sockaddr_storage clientStorage;
};

void* clientThread(void *data) {
    struct clientData *cdata = (struct clientData *)data;
    struct sockaddr *clientSockaddr = (struct sockaddr *)(&cdata->clientStorage);

    char clientAddrStr[BUFSZ];
    addrtostr(clientSockaddr, clientAddrStr, BUFSZ);
    printf("[log] connected from %s\n", clientAddrStr);

    while(1) {
        command *req = (command *)malloc(sizeof(command));
        size_t bytesReceived = recv(cdata->clientSocket, req, BUFSZ, 0);
        printf("[log] %s, %d bytes: %s\n", clientAddrStr, (int)bytesReceived, req->message);

        if(idMsg == 2) {
            int senderIndex = atoi(idSender);
            printf("senderIndex: %d, thisId: %d\n", senderIndex, cdata->clientIndex);
            printf("socketList: %d, thisSocket: %d\n", clients.list[senderIndex], clients.list[cdata->clientIndex]);
            if(clients.list[senderIndex] == -2) {
                sprintf(buffer, "07$_$%d$02$", senderIndex);
                bytesReceived = send(cdata->clientSocket, buffer, strlen(buffer)+1, 0);
                if(bytesReceived != strlen(buffer)+1) msgExit("send() failed");
                if(bytesReceived == 0) break;

                continue;
            }
            else {
                clients.list[senderIndex] = -2;

                sprintf(buffer, "08$_$%d$01$", senderIndex);
                bytesReceived = send(cdata->clientSocket, buffer, strlen(buffer)+1, 0);
                if(bytesReceived != strlen(buffer)+1) msgExit("send() failed");
                if(bytesReceived == 0) break;

                printf("User %02d removed\n", senderIndex+1);

                sprintf(buffer, "02$%d$_$_$", senderIndex);
                for(int i = 0; i < MAX_CLIENTS; i++) {
                    if(clients.list[i] != -2) {
                        bytesReceived = send(clients.list[i], buffer, strlen(buffer)+1, 0);
                        if(bytesReceived != strlen(buffer)+1) msgExit("send() failed");
                        if(bytesReceived == 0) break;
                    }
                }
                // finaliza o processo de saída de um user
                break;
            }
        }

        if(strcmp(idMsg, "06") == 0) {
            int receiverIndex = atoi(idReceiver);
            if((receiverIndex < 0 || receiverIndex >= MAX_CLIENTS) || clients.list[receiverIndex] == -2) {
                printf("User %02d not found\n", receiverIndex+1);

                sprintf(buffer, "07$_$%d$03$", receiverIndex);
                bytesReceived = send(cdata->clientSocket, buffer, strlen(buffer)+1, 0);
                if(bytesReceived != strlen(buffer)+1) msgExit("send() failed");
                if(bytesReceived == 0) break;
            }
            else {
                // hora atual no formato HH:MM
                time_t rawtime;
                struct tm *timeinfo;
                time(&rawtime);
                timeinfo = localtime(&rawtime);
                char timeStr[6];
                strftime(timeStr, 6, "%H:%M", timeinfo);

                int senderIndex = atoi(idSender);
                char aux[strlen(message)];
                strcpy(aux, message);
                char finalMessage[BUFSZ - 8];

                sprintf(finalMessage, "P [%s] -> %02d: %s", timeStr, receiverIndex+1, aux);

                sprintf(buffer, "06$%d$%d$%s$", senderIndex, receiverIndex, finalMessage);
                bytesReceived = send(cdata->clientSocket, buffer, strlen(buffer)+1, 0);
                if(bytesReceived != strlen(buffer)+1) msgExit("send() failed");
                if(bytesReceived == 0) break;

                sprintf(finalMessage, "P [%s] %02d: %s", timeStr, senderIndex+1, aux);

                sprintf(buffer, "06$%d$%d$%s$", senderIndex, receiverIndex, finalMessage);
                bytesReceived = send(clients.list[receiverIndex], buffer, strlen(buffer)+1, 0);
                if(bytesReceived != strlen(buffer)+1) msgExit("send() failed");
                if(bytesReceived == 0) break;
            }
        }

        // sprintf(buffer, "_$_$_$_$");
        // bytesReceived = send(cdata->clientSocket, buffer, strlen(buffer)+1, 0);
        // if(bytesReceived != strlen(buffer)+1) msgExit("send() failed");
        // if(bytesReceived == 0) break;
    }

    close(cdata->clientSocket);
    clients.clientCount--;
    clients.list[cdata->clientIndex] = -2;
    free(cdata);
    pthread_exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
    if(argc < 3 || argc > 3) usageExit(argc, argv);

    struct sockaddr_storage storage;
    if (serverAddrInit(argv[1], argv[2], &storage) != 0) usageExit(argc, argv);

    int sock;
    //IPv4 ou IPv6, TCP, IP
    sock = socket(storage.ss_family, SOCK_STREAM, IPPROTO_TCP);
    if(sock < 0) msgExit("socket() failed");

    int enable = 1;
    // Reusar porta sem atraso
    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) != 0)
        msgExit("setsockopt() failed");

    struct sockaddr *addr = (struct sockaddr *)(&storage);
    // bind
    if(bind(sock, addr, sizeof(storage)) != 0) msgExit("bind() failed");

    // listen, 15 = número máximo de conexões pendentes para tratamento
    if(listen(sock, 15) != 0) msgExit("listen() failed");

    char addrstr[BUFSZ];
    addrtostr(addr, addrstr, BUFSZ);
    printf("[log] Bound to %s, waiting connections\n", addrstr);

    int count = 0;
    for(int i = 0; i < MAX_CLIENTS; i++) clients.list[i] = -2;
    clients.clientCount = 0;

    while(1) {
        struct sockaddr_storage clientStorage;
        struct sockaddr *clientSockaddr = (struct sockaddr *)(&clientStorage);
        socklen_t clientAddrLen = sizeof(clientStorage);

        // accept, Socket que conversa com cliente
        printf("[log] Waiting for connections...\n");
        int clientSocket = accept(sock, clientSockaddr, &clientAddrLen);
        if(clientSocket == -1) {
            close(sock);
            msgExit("accept() failed");
        }
        printf("[log] Connection accepted\n");

        command *msg = (command *)malloc(sizeof(command));
        if(clients.clientCount == MAX_CLIENTS) {
            msg->id = 7;
            msg->idSender = -1;
            msg->idReceiver = -1;
            sprintf(msg->message, "01");

            count = send(clientSocket, msg, sizeof(command), 0);
            if(count != sizeof(command)) msgExit("send() failed");
            close(clientSocket);
            free(msg);
            continue;
        }

        struct clientData *cdata = (struct clientData *)malloc(sizeof(struct clientData));
        if(!cdata) msgExit("malloc() failed");
        cdata->clientSocket = clientSocket;
        memcpy(&(cdata->clientStorage), &clientStorage, sizeof(clientStorage));

        int index = 0;
        for(index = 0; index < MAX_CLIENTS; index++) {
            if(clients.list[index] == -2) {
                clients.list[index] = clientSocket;
                clients.clientCount++;
                break;
            }
        }
        cdata->clientIndex = index;
        printf("User %02d added\n", index+1);

        msg->idMsg = 6;
        msg->idSender = index;
        msg->idReceiver = -1;
        sprintf(msg->message, "User %02d joined the group!\n", index+1);

        // broadcast message indicating new user to all active users
        for(int j = 0; j < MAX_CLIENTS; j++) {
            if(clients.list[j] != -2) {
                printf("Sending broadcast to socket %d\n", clients.list[j]);
                count = send(clients.list[j], msg, sizeof(command), 0);
                if(count != sizeof(command)) msgExit("send() failed");
            }
        }

        // send the updated list of clients to the new user
        msg->idMsg = 4;
        msg->idSender = -1;
        msg->idReceiver = -1;

        int first = 1;
        for(int j = 0; j < MAX_CLIENTS; j++) {
            if(clients.list[j] != -2) {
                if(first) sprintf(msg->message, "%d,", j);
                else {
                    char temp[3];
                    sprintf(temp, "%d,", j);
                    strcat(msg->message, temp);
                }
                first = 0;
            }
        }

        printf("Sending list %s to user %d\n", msg->message, clients.list[index]);
        count = send(clients.list[index], msg, sizeof(command), 0);
        if(count != sizeof(command)) msgExit("send() failed");

        pthread_t tid;
        if(pthread_create(&tid, NULL, clientThread, cdata) != 0){
            clients.list[index] = -2;
            clients.clientCount--;
            free(msg);
            free(cdata);
            close(clientSocket);
            msgExit("pthread_create() failed");
        }

        free(msg);
    }
    close(sock);
    exit(EXIT_SUCCESS);
}