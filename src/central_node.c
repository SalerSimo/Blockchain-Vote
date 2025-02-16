#include <stdio.h>
#include<string.h>
#include<pthread.h>
#include"blockchain.h"

#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include<unistd.h>
    #define SOCKET int
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
#endif

void InitializeSockets() {
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        printf("WSAStartup failed\n");
        exit(1);
    }
#endif
}

void CleanupSockets() {
#ifdef _WIN32
    WSACleanup();
#endif
}

void CloseSocket(SOCKET socket){
#ifdef _WIN32
    closesocket(socket);
#else
    close(socket);
#endif
}

typedef struct{
    char peerIp[MAX_PEERS][16];
    int peerPort[MAX_PEERS];
    char publicKey[MAX_PEERS][MAX_PUBLIC_KEY_LENGTH];
    int peerCount;
}Peers;

int RegisterPeer(Peers *peerList, char *peerIp, int peerPort, char *key){
    int *i = &(peerList->peerCount);
    if(*i < MAX_PEERS){
        strcpy(peerList->peerIp[*i], peerIp);
        strcpy(peerList->publicKey[*i], key);
        peerList->peerPort[*i] = peerPort;
        (*i)++;
    }
    else{
        return 0;
    }
    return 1;
}

void SendPeerList(Peers *peerList, SOCKET peerSocket){
    char ack;

    send(peerSocket, (char *)&peerList->peerCount, sizeof(int), 0);
    recv(peerSocket, &ack, sizeof(ack), 0);

    for(int i=0; i<peerList->peerCount; i++){
        send(peerSocket, peerList->peerIp[i], sizeof(peerList->peerIp[i]), 0);
        recv(peerSocket, &ack, sizeof(ack), 0);

        send(peerSocket, (char *)&peerList->peerPort[i], sizeof(int), 0);
        recv(peerSocket, &ack, sizeof(ack), 0);

        send(peerSocket, peerList->publicKey[i], MAX_PUBLIC_KEY_LENGTH, 0);
        recv(peerSocket, &ack, sizeof(ack), 0);
    }
    closesocket(peerSocket);
}

void UpdatePeers(Peers *peerList){
    int last = peerList->peerCount - 1;
    SOCKET peerSocket;
    struct sockaddr_in peerAddr;
    int addrLength = sizeof(peerAddr);
    char ack;

    for(int i=0; i<last; i++){
        peerSocket = socket(AF_INET, SOCK_STREAM, 0);
        peerAddr.sin_family = AF_INET;
        peerAddr.sin_port = htons(peerList->peerPort[i]);
        peerAddr.sin_addr.s_addr = inet_addr(peerList->peerIp[i]);
        connect(peerSocket, (struct sockaddr *)&peerAddr, sizeof(peerAddr));

        send(peerSocket, "update", 6, 0);
        recv(peerSocket, &ack, sizeof(ack), 0);

        send(peerSocket, peerList->peerIp[last], sizeof(peerList->peerIp[last]), 0);
        recv(peerSocket, &ack, sizeof(ack), 0);

        send(peerSocket, (char *)&peerList->peerPort[last], sizeof(int), 0);
        recv(peerSocket, &ack, sizeof(ack), 0);

        send(peerSocket, peerList->publicKey[last], MAX_PUBLIC_KEY_LENGTH, 0);
        recv(peerSocket, &ack, sizeof(ack), 0);
    }
}


Peers *Peers_init(){
    Peers *peerList = (Peers *)malloc(sizeof(Peers));
    peerList->peerCount = 0;
    return peerList;
}

void printPeers(Peers *peerList){
    for(int i=0; i<peerList->peerCount; i++){
        printf("Peer %d: \t%s:%d\n", i, peerList->peerIp[i], peerList->peerPort[i]);
        printf("Peer %d public key: %s\n", i, peerList->publicKey[i]);
    }
}

int main(){
    //WSADATA wsa;
    SOCKET clientSocket, serverSocket;
    struct sockaddr_in serverAddr, clientAddr;
    int addrLength = sizeof(clientAddr);
    int recvSize, receivedPort;
    char peerIp[16], ack = 'x', key[MAX_PUBLIC_KEY_LENGTH];
    Peers *peerList = Peers_init();
    
    //WSAStartup(MAKEWORD(2,2), &wsa);
    InitializeSockets();
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(5000);

    bind(serverSocket, (struct sockaddr *)&serverAddr, sizeof(serverAddr));

    listen(serverSocket, 5);
    printf("listening\n");

    while((clientSocket = accept(serverSocket, (struct sockaddr *)&clientAddr, &addrLength)) != INVALID_SOCKET){
        strcpy(peerIp, inet_ntoa(clientAddr.sin_addr));
        recvSize = recv(clientSocket, (char *)&receivedPort, sizeof(int), 0);
        printf("Received peer: %s:%d\n", peerIp, receivedPort);

        recvSize = recv(clientSocket, key, MAX_PUBLIC_KEY_LENGTH, 0);

        ack = RegisterPeer(peerList, peerIp, receivedPort, key);

        send(clientSocket, &ack, 1, 0);

        if(ack == 1){
            SendPeerList(peerList, clientSocket);
            UpdatePeers(peerList);
            send(clientSocket, &ack, 1, 0);
        }

        CloseSocket(clientSocket);
    }
    printf("end\n");
    CloseSocket(serverSocket);
    CleanupSockets();
    return 0;
}