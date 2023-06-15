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
    char message[BUFSZ - 3 * sizeof(int)]; 
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
    // printf("[log] connected from %s\n", clientAddrStr);

    // command *req = (command *)malloc(sizeof(command));
    // command *res = (command *)malloc(sizeof(command));

    while(1) {
        command *req = (command *)malloc(sizeof(command));
        // command *res = (command *)malloc(sizeof(command));
        size_t bytesReceived = recv(cdata->clientSocket, req, sizeof(command), 0);
        if(bytesReceived != sizeof(command)) msgExit("recv() failed");
        // printf("size of req: %ld", sizeof(req));
        // printf("[log] %s, %d bytes: %s\n", clientAddrStr, (int)bytesReceived, req->message);

        if(req->idMsg == 2) {
            // printf("senderIndex: %d, thisId: %d\n", senderIndex, cdata->clientIndex);
            // printf("socketList: %d, thisSocket: %d\n", clients.list[senderIndex], clients.list[cdata->clientIndex]);
            if(clients.list[req->idSender] == -2) {
                req->idMsg = 7;
                req->idReceiver = req->idSender; // os dois apontam para o mesmo lugar!!!
                req->idSender = -1;
                sprintf(req->message, "02");

                bytesReceived = send(cdata->clientSocket, req, sizeof(command), 0);
                if(bytesReceived != sizeof(command)) msgExit("send() failed");
                if(bytesReceived == 0) break;

                free(req);
                // free(req);
                continue;
            }
            else {
                // printf("index to be removed: %d\n", req->idSender);
                clients.list[req->idSender] = -2;

                req->idMsg = 8;
                char auxIdSender[3];
                char auxIdReceiver[3];
                sprintf(auxIdSender, "%d", req->idSender);
                sprintf(auxIdReceiver, "%d", req->idReceiver);
                req->idSender = atoi(auxIdReceiver);
                req->idReceiver = atoi(auxIdSender);
                // req->idReceiver = req->idSender; // os dois apontam para o mesmo lugar!!!
                // req->idSender = -1; // os dois são -1 agora!!
                sprintf(req->message, "01");
                // printf("id sender: %d\n", req->idSender);
                // printf("id receiver: %d\n", req->idReceiver);

                bytesReceived = send(cdata->clientSocket, req, sizeof(command), 0);
                if(bytesReceived != sizeof(command)) msgExit("send() failed");
                if(bytesReceived == 0) break;
                // printf("index to be removed: %d\n", req->idSender);

                printf("User %02d removed\n", req->idReceiver+1);

                req->idMsg = 2;
                req->idSender = atoi(auxIdSender);
                req->idReceiver = -1;
                memset(req->message, 0, BUFSZ - 3 * sizeof(int));

                for(int i = 0; i < MAX_CLIENTS; i++) {
                    if(clients.list[i] != -2) {
                        bytesReceived = send(clients.list[i], req, sizeof(command), 0);
                        if(bytesReceived != sizeof(command)) msgExit("send() failed");
                        if(bytesReceived == 0) break;
                    }
                }
                // finaliza o processo de saída de um user
                free(req);
                // free(res);
                break;
            }
        }

        if(req->idMsg == 6) {
            if(req->idReceiver == -1) {
                int count = 0;
                // req = req;
                time_t rawtime;
                struct tm *timeinfo;
                time(&rawtime);
                timeinfo = localtime(&rawtime);
                char timeStr[6];
                strftime(timeStr, 6, "%H:%M", timeinfo);
                printf("[%s] %02d: %s", timeStr, req->idSender+1, req->message);
                
                for(int i = 0; i < MAX_CLIENTS; i++) {
                    if(clients.list[i] != -2) {
                        // printf("Sending public to socket %d\n", clients.list[i]);
                        count = send(clients.list[i], req, sizeof(command), 0);
                        if(count != sizeof(command)) msgExit("send() failed");
                    }
                }
            }
            else if((req->idReceiver < 0 || req->idReceiver >= MAX_CLIENTS) || clients.list[req->idReceiver] == -2) {
                printf("User %02d not found\n", req->idReceiver+1);

                req->idMsg = 7;
                req->idSender = -1;
                // req->idReceiver = req->idReceiver;
                sprintf(req->message, "03");
                
                bytesReceived = send(cdata->clientSocket, req, sizeof(command), 0);
                if(bytesReceived != sizeof(command)) msgExit("send() failed");
                if(bytesReceived == 0) break;
            }
            else {
                req->idMsg = 6;
                // req->idSender = req->idSender;
                // req->idReceiver = req->idReceiver;
                // sprintf(res->message, "%s", req->message);

                // echo para o cliente que enviou a mensagem
                bytesReceived = send(cdata->clientSocket, req, sizeof(command), 0);
                if(bytesReceived != sizeof(command)) msgExit("send() failed");
                if(bytesReceived == 0) break;

                // então envia de fato a mensagem para o remetente
                bytesReceived = send(clients.list[req->idReceiver], req, sizeof(command), 0);
                if(bytesReceived != sizeof(command)) msgExit("send() failed");
                if(bytesReceived == 0) break;
            }
        }

        free(req);
        // free(res);
    }

    // free(req);
    // free(res);
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
    // printf("[log] Bound to %s, waiting connections\n", addrstr);

    int count = 0;
    for(int i = 0; i < MAX_CLIENTS; i++) clients.list[i] = -2;
    clients.clientCount = 0;

    while(1) {
        struct sockaddr_storage clientStorage;
        struct sockaddr *clientSockaddr = (struct sockaddr *)(&clientStorage);
        socklen_t clientAddrLen = sizeof(clientStorage);

        // accept, Socket que conversa com cliente
        // printf("[log] Waiting for connections...\n");
        int clientSocket = accept(sock, clientSockaddr, &clientAddrLen);
        if(clientSocket == -1) {
            close(sock);
            msgExit("accept() failed");
        }
        // printf("[log] Connection accepted\n");

        command *reqAdd = (command *)malloc(sizeof(command));
        count = recv(clientSocket, reqAdd, sizeof(command), 0);
        if(count != sizeof(command)) msgExit("recv() failed");
        if(reqAdd->idMsg != 1) {
            reqAdd->idMsg = 8;
            reqAdd->idSender = -1;
            reqAdd->idReceiver = -1;
            memset(reqAdd->message, 0, BUFSZ - 3 * sizeof(int));

            count = send(clientSocket, reqAdd, sizeof(command), 0);
            if(count != sizeof(command)) msgExit("send() failed");

            close(clientSocket);
            free(reqAdd);
            continue; // código incorreto para REQ_ADD
        }
        free(reqAdd);

        command *msg = (command *)malloc(sizeof(command));
        if(clients.clientCount == MAX_CLIENTS) {
            msg->idMsg = 7;
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
                // printf("Sending broadcast to socket %d\n", clients.list[j]);
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

        // printf("Sending list %s to user %d\n", msg->message, clients.list[index]);
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