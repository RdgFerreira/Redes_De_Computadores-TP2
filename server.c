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

// Constante representante do tamanho máximo de uma mensagem
#define BUFSZ 2048
// Constante representante do número máximo de clientes simultâneos
#define MAX_CLIENTS 15
// Constante representante de um campo inteiro nulo na estrutura command
#define NULL_INT_FIELD -6969

// Função que imprime na tela exemplos de argumentos corretos para a execução de um servidor
void usageExit(int argc, char **argv) {
    printf("Server usage: %s <v4|v6> <server port>\n", argv[0]);
    printf("Ex: %s v4 51511\n", argv[0]);
    printf("Ex: %s v6 51511\n", argv[0]);
    exit(EXIT_FAILURE);
}

// Impressão de mensagem de erro caso alguma função do framework de sockets ou threads retorne erro
void msgExit(const char *msg) {
    perror(msg);
    exit(EXIT_FAILURE);
}

// Inicialização do endereçamento do servidor, IPv4 e IPv6
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

// Recuperação do endereço do servidor em formato de string
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

// Estrutura de dados que encapsula os conteúdos essenciais de um comando:
// idMsg: identificador da mensagem;
// idSender: identificador do remetente (0 -> 14, ou NULL_INT_FIELD quando este campo == NULL);
// idReceiver: identificador do destinatário (0 -> 14, ou NULL_INT_FIELD quando este campo == NULL),
// message: O conteúdo textual da mensagem em si.
// Note que o tamanho máximo do campo mensagem do comando é o tamanho máximo definido acima (2048)
// descontado de 12 bytes dos 3 inteiros usados para identificar a mensagem, o remetente e o destinatário.
typedef struct command{
    int idMsg;
    int idSender;
    int idReceiver; 
    char message[BUFSZ - 3 * sizeof(int)]; 
} command;

// Enumeração que representa os identificadores dos tipos de comandos possíveis:
enum commandTypes {
    REQ_ADD = 1,
    REQ_REM = 2,
    RES_LIST = 4,
    MSG = 6,
    ERROR = 7,
    OK = 8
};

// Estrutura de dados que controla quantos e quais clientes estão conectados:
// list: lista de inteiros que contêm -2 ou números de sockets de clientes válidos, 
// indexados diretamente pelos identificadores de clientes recuperados pelos comandos recebidos
// clientCount: contador de clientes ativos atualmente 
typedef struct clientSockets {
    // -2 = vazio, >= 0 = socket válido
    int list[MAX_CLIENTS];
    int clientCount;
} clientSockets;

// Inicialização global da estrutura acima 
clientSockets clients;

// Estrutura de dados auxiliar que contém informações úteis para um cliente específico:
// clientSocket: número do socket deste cliente
// clientIndex: identificador deste cliente
// clientStorage: estrutura do framework de sockets que abstrai o endereço deste cliente
struct clientData {
    int clientSocket;
    int clientIndex;
    struct sockaddr_storage clientStorage;
};

// Função principal das threads que gerenciam os múltiplos clientes 
void* clientThread(void *data) {
    struct clientData *cdata = (struct clientData *)data;
    struct sockaddr *clientSockaddr = (struct sockaddr *)(&cdata->clientStorage);

    char clientAddrStr[BUFSZ];
    addrtostr(clientSockaddr, clientAddrStr, BUFSZ);
    int count = 0;
    size_t bytesSent = 0;
    unsigned total = 0;

    // loop principal de recepção de comandos do cliente e resposta do servidor
    // Cada iteração criamos uma nova estrutura auxiliar de comando para recepção e resposta
    // lendo, processando e escrevendo os campos adequadamente.
    while(1) {
        command *req = (command *)malloc(sizeof(command));
        total = 0;
        while(1) {
            count = recv(cdata->clientSocket, req + total, sizeof(command) - total, 0);
            if (count == 0 || count == sizeof(command)) break;
            total += count;
        }

        if(req->idMsg == REQ_REM) { // Recepção do comando REQ_REM(idUser_i, NULL_INT_FIELD, "");
            if(clients.list[req->idSender] == -2) { // Usuário solicitante da remoção não está presente na base de clientes do servidor
                // Montagem do comando de resposta ERROR(NULL_INT_FIELD, idUser_i, "02");
                req->idMsg = ERROR;
                char auxIdSender[3];
                sprintf(auxIdSender, "%d", req->idSender);
                req->idReceiver = atoi(auxIdSender);
                // Note que apenas o código de erro é enviado, o cliente conhece as mensagens associadas aos códigos e os imprime adequadamente
                // Este comportamento segue ao longo do código do servidor
                sprintf(req->message, "02");

                // Envio da Resposta
                bytesSent = send(cdata->clientSocket, req, sizeof(command), 0);
                if(bytesSent != sizeof(command)) msgExit("send() failed");
                if(bytesSent == 0) break;
            }
            else { // Usuário está na base e, então, inicia-se o processo de remoção.
                // Marca o socket na lista como vazio na posição indexada pelo identificador do cliente solicitante
                clients.list[req->idSender] = -2;

                // Montagem e envio do comando de resposta OK(NULL_INT_FIELD, idUser_i, "01")
                req->idMsg = OK;
                char auxIdSender[3];
                char auxIdReceiver[3];
                sprintf(auxIdSender, "%d", req->idSender);
                sprintf(auxIdReceiver, "%d", req->idReceiver);
                req->idSender = atoi(auxIdReceiver);
                req->idReceiver = atoi(auxIdSender);
                sprintf(req->message, "01");

                bytesSent = send(cdata->clientSocket, req, sizeof(command), 0);
                if(bytesSent != sizeof(command)) msgExit("send() failed");
                if(bytesSent == 0) break;

                // Mensagem padrão de remoção de um cliente no terminal do servidor
                printf("User %02d removed\n", req->idReceiver+1);

                // Montagem e envio broadcast do comando REQ_REM(id_User_i, NULL_INT_FIELD, "")
                req->idMsg = REQ_REM;
                req->idSender = atoi(auxIdSender);
                req->idReceiver = NULL_INT_FIELD;
                memset(req->message, 0, BUFSZ - 3 * sizeof(int));

                // Percorre a estrutura de lista de clientes e envia a mensagem para todos os clientes ativos
                for(int i = 0; i < MAX_CLIENTS; i++) {
                    if(clients.list[i] != -2) {
                        bytesSent = send(clients.list[i], req, sizeof(command), 0);
                        if(bytesSent != sizeof(command)) msgExit("send() failed");
                        if(bytesSent == 0) break;
                    }
                }
                // finaliza o processo de saída de um cliente
                free(req);
                break;
            }
        }

        if(req->idMsg == MSG) { // Recepção do comando MSG(idUser_i, idUser_j, "mensagem")
            if(req->idReceiver == NULL_INT_FIELD) { // Se o campo de remetente for NULL (NULL_INT_FIELD), trata-se de uma mensagem pública
                time_t rawtime;
                struct tm *timeinfo;
                time(&rawtime);
                timeinfo = localtime(&rawtime);
                char timeStr[6];
                strftime(timeStr, 6, "%H:%M", timeinfo);
                // Impressão da mensagem pública com o timestamp do sistema
                printf("[%s] %02d: %s", timeStr, req->idSender+1, req->message);
                
                // Envio da mensagem recebida via broadcast para os clientes ativos
                for(int i = 0; i < MAX_CLIENTS; i++) {
                    if(clients.list[i] != -2) {
                        bytesSent = send(clients.list[i], req, sizeof(command), 0);
                        if(bytesSent != sizeof(command)) msgExit("send() failed");
                    }
                }
            }
            else if((req->idReceiver < 0 || req->idReceiver >= MAX_CLIENTS) || clients.list[req->idReceiver] == -2) {
                // Se o idUser_j (Destinatário) for um identificador inválido, ou seja, menor que -1,
                // maior que o maior identificador possível (14) ou o valor indexado por ele na lista de
                // clientes contém um socket vazio, então este usuário não foi encontrado.
                printf("User %02d not found\n", req->idReceiver+1);

                // Montagem e resposta para o cliente remetente do comando ERROR(03)
                req->idMsg = ERROR;
                req->idSender = NULL_INT_FIELD;
                req->idReceiver = NULL_INT_FIELD;
                sprintf(req->message, "03");
                
                bytesSent = send(cdata->clientSocket, req, sizeof(command), 0);
                if(bytesSent != sizeof(command)) msgExit("send() failed");
                if(bytesSent == 0) break;
            }
            else {
                // Envia a mensagem para o destinatário
                bytesSent = send(clients.list[req->idReceiver], req, sizeof(command), 0);
                if(bytesSent != sizeof(command)) msgExit("send() failed");
                if(bytesSent == 0) break;
            }
        }

        // libera a memória alocada para o comando recebido e enviado
        free(req);
    }

    // Fecha o socket do cliente, marca o id deste cliente como vazio e decrementa o contador de clientes ativos
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

    int count = 0;
    unsigned total = 0;
    // Inicialização do vetor de clientes ativos, de modo que todos os índices sejam vazios (-2)
    for(int i = 0; i < MAX_CLIENTS; i++) clients.list[i] = -2;
    // contador de clientes inicia em 0
    clients.clientCount = 0;

    while(1) {
        struct sockaddr_storage clientStorage;
        struct sockaddr *clientSockaddr = (struct sockaddr *)(&clientStorage);
        socklen_t clientAddrLen = sizeof(clientStorage);

        // accept, Socket que conversa com cliente
        int clientSocket = accept(sock, clientSockaddr, &clientAddrLen);
        if(clientSocket == -1) {
            close(sock);
            msgExit("accept() failed");
        }

        // Após a conclusão do bem sucedida do accept, o servidor deve receber um comando REQ_ADD e 
        // responder com um OK(NULL_INT_FIELD, NULL_INT_FIELD, "")
        command *reqAdd = (command *)malloc(sizeof(command));
        while(1) {
            count = recv(clientSocket, reqAdd + total, sizeof(command) - total, 0);
            if (count == 0 || count == sizeof(command)) break;
            total += count;
        }
        if(reqAdd->idMsg != REQ_ADD) {
            reqAdd->idMsg = OK;
            reqAdd->idSender = NULL_INT_FIELD;
            reqAdd->idReceiver = NULL_INT_FIELD;
            memset(reqAdd->message, 0, BUFSZ - 3 * sizeof(int));

            count = send(clientSocket, reqAdd, sizeof(command), 0);
            if(count != sizeof(command)) msgExit("send() failed");

            close(clientSocket);
            free(reqAdd);
            continue; // código incorreto para REQ_ADD
        }
        free(reqAdd);

        // Alocação dinâmica de memória para o comando de resposta
        command *msg = (command *)malloc(sizeof(command));
        // Se a lista de clientes ativos está cheia, o cliente será desconectado e sua execução encerrada, 
        // enviando um comando ERROR(NULL_INT_FIELD, NULL_INT_FIELD, "01")
        if(clients.clientCount == MAX_CLIENTS) {
            msg->idMsg = ERROR;
            msg->idSender = NULL_INT_FIELD;
            msg->idReceiver = NULL_INT_FIELD;
            sprintf(msg->message, "01");

            count = send(clientSocket, msg, sizeof(command), 0);
            if(count != sizeof(command)) msgExit("send() failed");
            close(clientSocket);
            free(msg);
            continue;
        }

        // Definição da estrutura de dados do cliente e de seu número de socket
        struct clientData *cdata = (struct clientData *)malloc(sizeof(struct clientData));
        if(!cdata) msgExit("malloc() failed");
        cdata->clientSocket = clientSocket;
        memcpy(&(cdata->clientStorage), &clientStorage, sizeof(clientStorage));

        // O primeiro índice que indica uma posição vazia no vetor de clientes ativos é preenchido com o número do socket do cliente
        // e o contador de clientes ativos é incrementado
        int index = 0;
        for(index = 0; index < MAX_CLIENTS; index++) {
            if(clients.list[index] == -2) {
                clients.list[index] = clientSocket;
                clients.clientCount++;
                break;
            }
        }
        // O índice de espaço vazio encontrado é o índice do cliente na lista de clientes ativos
        cdata->clientIndex = index;
        printf("User %02d added\n", index+1);

        msg->idMsg = MSG;
        msg->idSender = index;
        msg->idReceiver = NULL_INT_FIELD;
        sprintf(msg->message, "User %02d joined the group!\n", index+1);

        // broadcast de uma MSG(idUser_i, NULL_INT_FIELD, "User i joined the group!") para os usuários ativos da rede
        for(int j = 0; j < MAX_CLIENTS; j++) {
            if(clients.list[j] != -2) {
                count = send(clients.list[j], msg, sizeof(command), 0);
                if(count != sizeof(command)) msgExit("send() failed");
            }
        }

        // envio de uma RES_LIST(NULL_INT_FIELD, NULL_INT_FIELD, "i,j,k,...") para o usuário i, contendo a lista de usuários i,j,k,... ativos da rede
        msg->idMsg = RES_LIST;
        msg->idSender = NULL_INT_FIELD;
        msg->idReceiver = NULL_INT_FIELD;

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

        count = send(clients.list[index], msg, sizeof(command), 0);
        if(count != sizeof(command)) msgExit("send() failed");

        // Criação da thread que trata as requisições e respostas de cada cliente
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