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
#define MAX_CLIENTS 15

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

// Estrutura de dados que define o corpo genérico da mensagem.
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

// Array de clientes conectados ao servidor registrados neste cliente. 
// clientIndexes[i] = 0 se o cliente i não está conectado.
// clientIndexes[i] = 1 se o cliente i está conectado.
int clientIndexes[MAX_CLIENTS];
int thisClientIndex = -2;

// Função principal da thread deste cliente que é responsável por filtrar os comandos do terminal
void* processStdin(void *sockNum) {
    int count = 0;
    unsigned total = 0;
    // definição do buffer de entrada com o tamanho máximo de uma mensagem somado de um overhead de 15 bytes para
    // comportar as palavras chave do comando de terminal
    char buffer[BUFSZ + 15];
    // socket do servidor
    long sock = (long)sockNum;

    while(1) {
        // leitura do comando da entrada padrão
        memset(buffer, 0, BUFSZ + 15);
        pthread_testcancel();
        fgets(buffer, BUFSZ + 15, stdin);

        // A cada iteração do loop de leitura, uma estrutura de dados é alocada para criar e enviar a mensagem de acordo,
        // caso o comando da entrada padrão segue o padrão esperado dos exemplos.
        command *req = (command *)malloc(sizeof(command));

        // Filtragem do comando "close connection"
        if(strncmp(buffer, "close connection", 16) == 0) {
            // buffer deve ser exatamente "close connection" ou "close connection\n"
            if(strlen(buffer) > 17) {
                free(req);
                continue;
            }
            else if(strlen(buffer) == 17 && buffer[strlen(buffer) - 1] != '\n') {
                free(req);
                continue;
            }

            // Montagem e envio do comando REQ_REM(idUser_i, -1, "") para o servidor, solicitando sua remoção e saída
            // onde idUser_i é o id deste cliente
            req->idMsg = REQ_REM;
            req->idSender = thisClientIndex;
            req->idReceiver = -1;
            memset(req->message, 0, BUFSZ - 3 * sizeof(int));

            total = 0;
            while(1) {
                count = send(sock, req + total, sizeof(command) - total, 0);
                if (count == 0 || count == sizeof(command)) break;
                total += count;
            }
        }

        // filtragem do comando "list users"
        if(strncmp(buffer, "list users", 10) == 0) {
            if(strlen(buffer) > 11) {
                free(req);
                continue;
            }
            // buffer deve ser exatamente "list users" ou "list users\n"
            else if(strlen(buffer) == 11 && buffer[strlen(buffer) - 1] != '\n') {
                free(req);
                continue;
            }

            // Este cliente realiza uma consulta à sua base local de clientes ativos (clientIndexes) e imprime na tela os IDs
            // dos clientes ativos, exceto este.
            int foundOne = 0;
            for(int i = 0; i < MAX_CLIENTS; i++) {
                if(clientIndexes[i] != 0 && i != thisClientIndex) {
                    if(foundOne) printf(" %02d", i+1);
                    else printf("%02d", i+1);
                    foundOne = 1;
                }
            }
            if(foundOne) printf("\n");
        }

        // filtragem do comando send to <dest> "<message>"
        if(strncmp(buffer, "send to ", 8) == 0) {
            // tratamento de exceções caso exista mais espaços em branco que o necessário entre "to" e <dest> e/ou entre <dest> e <message>
            if(strlen(buffer) >= 9 && buffer[8] == ' ') {
                free(req);
                continue;
            }
            char *token = strtok(buffer, " "); // send
            token = strtok(NULL, " ");         // to
            token = strtok(NULL, " ");         // <dest>
            if(token == NULL || (atoi(token) == 0 && strcmp(token, "00") != 0)) {
                free(req);
                continue;
            }

            // Como os índices passados via linha de comando começam de 1,
            // a recuperação dos índices dos clientes, que indexam diretamente o array de clientes ativos
            // tanto no user.c como no server.c, é feita apenas subtraindo 1 do valor passado via linha de comando. 
            req->idReceiver = atoi(token) - 1;

            token = strtok(NULL, ""); // "<message>"
            // filtragem das aspas duplas que delimitam a mensagem na linha de comando
            if(token == NULL ||
               token[0] != '\"' ||
               !(token[strlen(token) - 1] == '\"' || (token[strlen(token) - 2] == '\"' && token[strlen(token) - 1] == '\n'))) {
                free(req);
                continue;
            }
            // Incremento de um do ponteiro de "<message>" para ignorar a primeira aspas dupla
            token += 1;
            // insere uma quebra de linha no lugar da segunda aspas dupla e finaliza a string para envio
            if(token[strlen(token) - 1] == '\"') token[strlen(token) - 1] = '\n';
            else {
                token[strlen(token) - 2] = '\n';
                token[strlen(token) - 1] = '\0';
            }

            // Montagem e envio do comando MSG(idUser_i, idUser_j, <message>) para o servidor, solicitando o envio da mensagem
            // de idUser_i para idUser_j, onde idUser_i é o id deste cliente
            req->idMsg = MSG;
            req->idSender = thisClientIndex;
            memset(req->message, 0, BUFSZ - 3 * sizeof(int));
            sprintf(req->message, "%s", token);

            total = 0;
            while(1) {
                count = send(sock, req + total, sizeof(command) - total, 0);
                if (count == 0 || count == sizeof(command)) break;
                total += count;
            }
        }

        // filtragem do comando send all "<message>"
        if(strncmp(buffer, "send all ", 9) == 0) {
            // filtragem das aspas duplas que delimitam a mensagem na linha de comando
            if(strlen(buffer) >= 10 && buffer[9] != '\"') {
                free(req);
                continue;
            }
            char *token = strtok(buffer, "\"");
            if(token == NULL) {
                free(req);
                continue;
            }
            // depois de send all , deve vir "<message>" ou "<message>"\n 
            token = strtok(NULL, "");
            if(token == NULL || !(token[strlen(token) - 1] == '\"' || (token[strlen(token) - 2] == '\"' && token[strlen(token) - 1] == '\n'))) {
                free(req);
                continue;
            }
            // insere uma quebra de linha no lugar da segunda aspas dupla e finaliza a string para envio
            if(token[strlen(token) - 1] == '\"') token[strlen(token) - 1] = '\n';
            else {
                token[strlen(token) - 2] = '\n';
                token[strlen(token) - 1] = '\0';
            }

            // Montagem e envio do comando MSG(idUser_i, -6969, <message>) para o servidor, solicitando o envio da mensagem
            // de idUser_i para todos os clientes ativos, onde idUser_i é o id deste cliente
            req->idMsg = MSG;
            req->idSender = thisClientIndex;
            req->idReceiver = -6969;
            memset(req->message, 0, BUFSZ - 3 * sizeof(int));
            sprintf(req->message, "%s", token);

            total = 0;
            while(1) {
                count = send(sock, req + total, sizeof(command) - total, 0);
                if (count == 0 || count == sizeof(command)) break;
                total += count;
            }
        }

        free(req);
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

    // função connect deste cliente conversa com o accept do servidor para concluir uma conexão TCP
    struct sockaddr *addr = (struct sockaddr *)(&storage);
    if(connect(sock, addr, sizeof(storage)) != 0) msgExit("connect() failed");

    char addrstr[BUFSZ];
    addrtostr(addr, addrstr, BUFSZ);
    int count = 0;

    // Logo após o sucesso do connect, este cliente envia um REQ_ADD(-1, -1, "") para o servidor, solicitando
    // a adição deste novo cliente
    command *reqAdd = (command *)malloc(sizeof(command));
    reqAdd->idMsg = REQ_ADD;
    reqAdd->idSender = -1;
    reqAdd->idReceiver = -1;
    memset(reqAdd->message, 0, BUFSZ - 3 * sizeof(int));

    count = send(sock, reqAdd, sizeof(command), 0);
    if(count != sizeof(command)) msgExit("send() failed, msg size mismatch");
    free(reqAdd);

    // Inicialização do vetor de índices dos clientes ativos, com todos inativos por enquanto
    for(int i = 0; i < MAX_CLIENTS; i++) clientIndexes[i] = 0;

    // lançamento de uma thread para processar os comandos digitados pelo usuário no terminal
    pthread_t t_stdin;
    long sockNum = (long)sock;
    if(pthread_create(&t_stdin, NULL, processStdin, (void *)sockNum) !=0) msgExit("pthread_create() failed");

    while(1) {
        // Assim como o loop principal da thread que processa e filtra a entrada padrão,
        // este loop principal do cliente recebe e processa mensagens do servidor
        // por meio da alocação da mesma estrutura command a cada iteração
        command *res = (command*)malloc(sizeof(command)); 
        count = recv(sock, res, sizeof(command), 0);
        if(count != sizeof(command)) msgExit("recv() failed, msg size mismatch");

        // filtragem da resposta REQ_REM(idUser, -1, "") do servidor, que indica que o cliente idUser
        // deve ser retirado da lista de clientes ativos, aliado de uma impressão de mensagem na tela
        // que confirma isso.
        if(res->idMsg == REQ_REM) { 
            clientIndexes[res->idSender] = 0;
            printf("User %02d left the group!\n", res->idSender+1);
        }

        // filtragem da resposta RES_LIST(-1, -1, "i,j,k,...") do servidor, que indica que este cliente
        // deve atualizar sua lista de clientes ativos
        if(res->idMsg == RES_LIST) {
            char *aux = strtok(res->message, ",");
            while(aux != NULL) {
                clientIndexes[atoi(aux)] = 1;
                aux = strtok(NULL, ",");
            }
        }

        // filtragem da resposta MSG() do servidor
        if(res->idMsg == MSG) {
            // Criação de uma string com o horário atual usada para impressão da mensagem
            // de acordo com os formatos especificados, ou seja, strings de timestamps não
            // são trafegadas no socket
            time_t rawtime;
            struct tm *timeinfo;
            time(&rawtime);
            timeinfo = localtime(&rawtime);
            char timeStr[6];
            strftime(timeStr, 6, "%H:%M", timeinfo);
            
            if(clientIndexes[res->idSender] == 0) { // broadcast de nova conexão (remetente da mensagem é desconhecido por este cliente)
                clientIndexes[res->idSender] = 1; // marca como conhecido
                if(thisClientIndex == -2) { // Atribuição de id para este cliente caso ainda não esteja definido (recém conectado)
                    thisClientIndex = res->idSender;
                }
                printf("%s", res->message); // User {idSender} joined the group!
            }
            else if(res->idReceiver == -6969) { // broadcast de mensagem pública (id de destinatário é -6969 (NULL))
                // caso o broadcast tenha sido feito por este cliente, o formato da mensagem inclui um "-> all"
                if(res->idSender == thisClientIndex) printf("[%s] -> all: %s", timeStr, res->message);
                else printf("[%s] %02d: %s", timeStr, res->idSender+1, res->message);
            }
            else if(res->idSender != thisClientIndex) { // Mensagem Privada chegou de outro cliente
                printf("P [%s] %02d: %s", timeStr, res->idSender+1, res->message);
            }
            else { // echo de mensagem privada para este cliente
                printf("P [%s] -> %02d: %s", timeStr, res->idReceiver+1, res->message);
            }
        }

        // filtragem da resposta de ERROR do servidor
        if(res->idMsg == ERROR) {
            // filtragem e impressão dos códigos de erro
            if(strcmp(res->message, "01") == 0) {
                printf("User limit exceeded\n");
                free(res);
                break;
            }
            if(strcmp(res->message, "02") == 0) {
                printf("User not found\n");
            }
            if(strcmp(res->message, "03") == 0) {
                printf("Receiver not found\n");
            }
        }

        // filtragem da resposta OK() do servidor (remoção deste cliente da lista de clientes ativos)
        // e impressão de mensagem na tela que confirma isso
        if(res->idMsg == OK) {
            printf("Removed Successfully\n");
            free(res);
            break;
        }

        // libera a memória alocada para a estrutura command nesta iteração
        free(res);
    }

    // encerramento da thread que processa os comandos digitados pelo usuário no terminal e encerramento do programa
    pthread_cancel(t_stdin);
    pthread_join(t_stdin, NULL);
    close(sock);
    exit(EXIT_SUCCESS);
}