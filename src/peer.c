#include <stdio.h>
#include<string.h>
#include<pthread.h>
#include<unistd.h>
#include<pthread.h>
#include<semaphore.h>
#include"blockchain.h"

#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
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
    int thisPeer;
}Peers;

typedef struct{
    Peers *peerList;
    Blockchain *blockchain;
    SOCKET socket;
}data_t;

sem_t blockchainMutex, peerMutex, miningMutex;
char *privateKey, *publicKey;

int MineNewBlock(Vote *voteArray, int numVotes, Blockchain *blockchain, Peers *peerList);
int SendBlockBroadcast(Block *block, Peers *peerList);
int SendBlock(Block block, SOCKET peerSocket, Peers *peerList, char *peerPublicKey);
void ReceiveBlock(SOCKET senderSocket, Blockchain *blockchain, Peers *peerList);

void SendBlockchain(SOCKET socket, Blockchain *blockchain, Peers *peerList);
void ReceiveBlockchain(Peers *peerList, Blockchain *blockchain);

void PrintCommands();

void PrintPeers(Peers *peerList){
    for(int i=0; i<peerList->peerCount; i++){
        printf("Peer %d: \t%s:%d\n", i, peerList->peerIp[i], peerList->peerPort[i]);
    }
}

void UpdatePeers(Peers *peerList, SOCKET centralSocket){
    int last = peerList->peerCount;
    int recvSize;
    char ack = 'x';

    send(centralSocket, &ack, 1, 0);

    recvSize = recv(centralSocket, peerList->peerIp[last], sizeof(peerList->peerIp[last]), 0);
    send(centralSocket, &ack, 1, 0);

    recvSize = recv(centralSocket, (char *)&peerList->peerPort[last], sizeof(peerList->peerPort[last]), 0);
    send(centralSocket, &ack, 1, 0);

    recvSize = recv(centralSocket, peerList->publicKey[last], MAX_PUBLIC_KEY_LENGTH, 0);
    send(centralSocket, &ack, 1, 0);

    peerList->peerCount++;
}

int SendBlockBroadcast(Block *block, Peers *peerList){
    char ack, peerPublicKey[MAX_PUBLIC_KEY_LENGTH];
    SOCKET peerSocket;
    struct sockaddr_in peerAddr;
    int addrLength = sizeof(peerAddr), peerIndex;

    for(int i=0; i<peerList->peerCount; i++){
        if(i == peerList->thisPeer)
            continue;
        peerSocket = socket(AF_INET, SOCK_STREAM, 0);
        peerAddr.sin_family = AF_INET;
        peerAddr.sin_port = htons(peerList->peerPort[i]);
        peerAddr.sin_addr.s_addr = inet_addr(peerList->peerIp[i]);
        connect(peerSocket, (struct sockaddr *)&peerAddr, sizeof(peerAddr));

        send(peerSocket, "block", 5, 0);
        recv(peerSocket, &ack, sizeof(ack), 0);

        recv(peerSocket, (char *)&peerIndex, sizeof(int), 0);

        if(!SendBlock(*block, peerSocket, peerList, peerList->publicKey[peerIndex])){
            printf("Somethin went wrong\n");
            return 0;
        }

        CloseSocket(peerSocket);
    }
    return 1;
}

int SendBlock(Block block, SOCKET peerSocket, Peers *peerList, char *peerPublicKey){
    char ack;

    for(int i=0; i<block.numVotes; i++){
        memcpy(block.votes[i].voterId, Encrypt(peerPublicKey, block.votes[i].voterId), 256);
        memcpy(block.votes[i].candidateVoted, Encrypt(peerPublicKey, block.votes[i].candidateVoted), 256);
    }

    send(peerSocket, (char *)&block, sizeof(block), 0);
    recv(peerSocket, &ack, 1, 0);

    send(peerSocket, (char *)&peerList->thisPeer, sizeof(peerList->thisPeer), 0);
    recv(peerSocket, &ack, 1, 0);

    return ack - '0';
}

void ReceiveBlock(SOCKET senderSocket, Blockchain *blockchain, Peers *peerList){
    int recvSize, i, signValidity = 1, senderIndex;
    char ack = 'x';
    Block *block = malloc(sizeof(Block));

    send(senderSocket, &ack, 1, 0);

    send(senderSocket, (char *)&peerList->thisPeer, sizeof(peerList->thisPeer), 0);

    recvSize = recv(senderSocket, (char *)block, sizeof(*block), 0);
    send(senderSocket, &ack, 1, 0);

    for(int i=0; i<block->numVotes; i++){
        strcpy(block->votes[i].voterId, Decrypt(privateKey, block->votes[i].voterId));
        strcpy(block->votes[i].candidateVoted, Decrypt(privateKey, block->votes[i].candidateVoted));
    }

    recv(senderSocket, (char *)&senderIndex, sizeof(int), 0);
    send(senderSocket, &ack, 1, 0);

    for(int i=0; i<block->numVotes; i++){
        if(!CheckSign(&block->votes[i], peerList->publicKey[senderIndex])){
            printf("Signature %d NOT valid\n", i);
            signValidity = 0;
        }
    }

    if(CheckBlock(block, blockchain) && signValidity && strcmp(block->prevHash, blockchain->tail->hash) == 0){
        AddBlock(blockchain, block);
        send(senderSocket, "1", 1, 0);
    }else{
        printf("Block not valid\n");
        send(senderSocket, "0", 1, 0);
    }

    CloseSocket(senderSocket);
}

void SendBlockchain(SOCKET socket, Blockchain *blockchain, Peers *peerList){
    Block *block = blockchain->head;
    char ack = 'x';
    int peerIndex;

    send(socket, &ack, 1, 0);
    recv(socket, (char *)&peerIndex, sizeof(int), 0);

    while(block != blockchain->end){
        for(int i=0; i<block->numVotes; i++)
            SignVote(&block->votes[i], privateKey);
        SendBlock(*block, socket, peerList, peerList->publicKey[peerIndex]);
        block = block->next;
    }
    shutdown(socket, SD_SEND);
    CloseSocket(socket);
}

void ReceiveBlockchain(Peers *peerList, Blockchain *blockchain){
    SOCKET peerSocket;
    struct sockaddr_in peerAddr;
    int addrLength = sizeof(peerAddr), recvSize;
    char ack = '1';
    int index = 0, signValidity = 1;
    Block *block;

    if(peerList->thisPeer == 0)
        index = 1;

    peerSocket = socket(AF_INET, SOCK_STREAM, 0);
    peerAddr.sin_family = AF_INET;
    peerAddr.sin_port = htons(peerList->peerPort[index]);
    peerAddr.sin_addr.s_addr = inet_addr(peerList->peerIp[index]);
    connect(peerSocket, (struct sockaddr *)&peerAddr, sizeof(peerAddr));

    send(peerSocket, "blockchain", 10, 0);
    recv(peerSocket, &ack, sizeof(ack), 0);

    send(peerSocket, (char *)&peerList->thisPeer, sizeof(peerList->thisPeer), 0);

    while(1){
        block = malloc(sizeof(Block));

        recvSize = recv(peerSocket, (char *)block, sizeof(*block), 0);
        if(recvSize <= 0){
            free(block);
            break;
        }
        send(peerSocket, &ack, 1, 0);

        for(int i=0; i<block->numVotes; i++){
            strcpy(block->votes[i].voterId, Decrypt(privateKey, block->votes[i].voterId));
            strcpy(block->votes[i].candidateVoted, Decrypt(privateKey, block->votes[i].candidateVoted));
        }
    
        recv(peerSocket, (char *)&index, sizeof(int), 0);
        send(peerSocket, &ack, 1, 0);
    
        for(int i=0; i<block->numVotes; i++){
            if(!CheckSign(&block->votes[i], peerList->publicKey[index])){
                printf("Signature %d NOT valid\n", i);
                signValidity = 0;
            }
        }

        if(block->index == 0){
            blockchain->head = block;
            blockchain->tail = block;
            blockchain->end = CreateEndBlock();
            blockchain->tail->next = blockchain->end;
        }

        AddBlock(blockchain, block);
    }
    CloseSocket(peerSocket);
}

void *ReceiveMessageThread(void *args){
    data_t *data = (data_t *)args;
    SOCKET senderSocket;
    struct sockaddr_in senderAddr;
    char buffer[128], ack = 'x';
    int recvSize, addrLength = sizeof(senderAddr);

    listen(data->socket, MAX_PEERS + 1);

    while((senderSocket = accept(data->socket, (struct sockaddr *)&senderAddr, &addrLength)) != INVALID_SOCKET){
        recvSize = recv(senderSocket, buffer, 128, 0);
        buffer[recvSize] = '\0';
        if(strcmp(buffer, "update") == 0){
            //printf("Received update\n");
            sem_wait(&peerMutex);
            UpdatePeers(data->peerList, senderSocket);
            sem_post(&peerMutex);
        }
        if(strcmp(buffer, "block") == 0){
            //printf("Receiving block\n");
            sem_wait(&blockchainMutex);
            ReceiveBlock(senderSocket, data->blockchain, data->peerList);
            sem_post(&blockchainMutex);
        }
        if(strcmp(buffer, "blockchain") == 0){
            //printf("Received blockchain request\n");
            sem_wait(&blockchainMutex);
            SendBlockchain(senderSocket, data->blockchain, data->peerList);
            sem_post(&blockchainMutex);
        }
        if(strcmp(buffer, "start mining") == 0){
            //printf("Another peer is mining\n");
            sem_wait(&miningMutex);
        }
        if(strcmp(buffer, "end mining") == 0){
            //printf("The other peer has finished mining\n");
            sem_post(&miningMutex);
        }
        CloseSocket(senderSocket);
    }
}

void *CheckBlockchainThread(void *args){
    data_t *data = (data_t *)args;
    while(1){
        sleep(4);
        sem_wait(&blockchainMutex);
        if(!CheckIntegrity(data->blockchain)){
            printf("The blockchain is compromised, sending blockchain request\n");
            Blockchain_free(data->blockchain);
            data->blockchain = malloc(sizeof(Blockchain));
            ReceiveBlockchain(data->peerList, data->blockchain);
        }
        sem_post(&blockchainMutex);
    }
}

void Discover(char *centralIp, int port, Peers *peerList){
    char buffer[1024], ack = 'x';
    int recvSize;
    
    SOCKET centralSocket;
    struct sockaddr_in centralAddr;
    int addrLength = sizeof(centralAddr);

    centralSocket = socket(AF_INET, SOCK_STREAM, 0);
    centralAddr.sin_family = AF_INET;
    centralAddr.sin_port = htons(CENTRAL_PORT);
    centralAddr.sin_addr.s_addr = inet_addr(centralIp);
    connect(centralSocket, (struct sockaddr *)&centralAddr, sizeof(centralAddr));

    send(centralSocket, (char *)&port, 4, 0);
    send(centralSocket, publicKey, MAX_PUBLIC_KEY_LENGTH, 0);

    recv(centralSocket, &ack, 1, 0);
    if(ack == 0){
        printf("Max number of peers already reached\n");
        exit(0);
    }

    recvSize = recv(centralSocket, (char *)&peerList->peerCount, sizeof(peerList->peerCount), 0);
    peerList->thisPeer = peerList->peerCount - 1;
    send(centralSocket, &ack, 1, 0);

    for(int i=0; i<peerList->peerCount; i++){
        recvSize = recv(centralSocket, peerList->peerIp[i], sizeof(peerList->peerIp[i]), 0);
        send(centralSocket, &ack, 1, 0);

        recvSize = recv(centralSocket, (char *)&peerList->peerPort[i], sizeof(peerList->peerPort[i]), 0);
        send(centralSocket, &ack, 1, 0);

        recvSize = recv(centralSocket, peerList->publicKey[i], MAX_PUBLIC_KEY_LENGTH, 0);
        send(centralSocket, &ack, 1, 0);
    }
    recv(centralSocket, &ack, 1, 0);
    printf("The peer has successfully joined the network.\n");
}

int MineNewBlock(Vote *voteArray, int numVotes, Blockchain *blockchain, Peers *peerList){
    SOCKET peerSocket;
    struct sockaddr_in peerAddr;
    Block *newBlock;

    sem_wait(&peerMutex);

    for(int i=0; i<peerList->peerCount; i++){
        if(i == peerList->thisPeer)
            continue;
        peerSocket = socket(AF_INET, SOCK_STREAM, 0);
        peerAddr.sin_family = AF_INET;
        peerAddr.sin_port = htons(peerList->peerPort[i]);
        peerAddr.sin_addr.s_addr = inet_addr(peerList->peerIp[i]);
        connect(peerSocket, (struct sockaddr *)&peerAddr, sizeof(peerAddr));

        send(peerSocket, "start mining", 12, 0);
        CloseSocket(peerSocket);
    }

    sem_wait(&miningMutex);
    sem_wait(&blockchainMutex);
    newBlock = CreateBlock(blockchain, voteArray, numVotes);

    if(!CheckBlock(newBlock, blockchain)){
        printf("Check failed\n");
        return 0;
    }

    for(int i=0; i<numVotes; i++){
        SignVote(&newBlock->votes[i], privateKey);
    }

    if(SendBlockBroadcast(newBlock, peerList)){
        printf("Block accepted from all peers\n");
        AddBlock(blockchain, newBlock);
    }
    sem_post(&blockchainMutex);
    sem_post(&miningMutex);

    for(int i=0; i<peerList->peerCount; i++){
        if(i == peerList->thisPeer)
            continue;
        peerSocket = socket(AF_INET, SOCK_STREAM, 0);
        peerAddr.sin_family = AF_INET;
        peerAddr.sin_port = htons(peerList->peerPort[i]);
        peerAddr.sin_addr.s_addr = inet_addr(peerList->peerIp[i]);
        connect(peerSocket, (struct sockaddr *)&peerAddr, sizeof(peerAddr));

        send(peerSocket, "end mining", 10, 0);
        CloseSocket(peerSocket);
    }
    sem_post(&peerMutex);
    return 1;
}

float GetPercentage(Blockchain *blockchain, char *candidate){
    Block *block = blockchain->head->next;
    int totalVotes = 0, candidateVotes = 0;
    float percentage = 0;

    while(block != blockchain->end){
        totalVotes += block->numVotes;
        for(int i=0; i<block->numVotes; i++){
            if(strcmp(block->votes[i].candidateVoted, candidate) == 0){
                candidateVotes += 1;
            }
        }
        block = block->next;
    }
    if(totalVotes)
        percentage = (float)candidateVotes / totalVotes;
    return percentage;
}

void Interaction(data_t *data){
    char choice[25];
    Vote newVotes[MAX_VOTES];
    int numVotes = 0, duplicateFound = 0;
    char candidate[MAX_MSG_LENGTH];

    while(1){
        printf("Insert choice\n");
        scanf("%s", choice);
        if(strcmp(choice, "add") == 0){
            getchar();
            printf("Insert voterId:\n");
            scanf("%[^\n]", newVotes[numVotes].voterId);
            getchar();
            for(int i=0; i<numVotes; i++){
                if(strcmp(newVotes[i].voterId, newVotes[numVotes].voterId) == 0){
                    printf("There cannot be two votes with the same voter ID\n");
                    duplicateFound = 1;
                    break;
                }
            }
            if(duplicateFound){
                duplicateFound = 0;
                continue;
            }
            printf("Insert candidate voted\n");
            scanf("%[^\n]", newVotes[numVotes].candidateVoted);
            getchar();
            numVotes++;
            if(numVotes == MAX_VOTES){
                MineNewBlock(newVotes, numVotes, data->blockchain, data->peerList);
                numVotes = 0;
            }
        }else if(strcmp(choice, "send") == 0){
            if(numVotes == 0){
                printf("You cannot send a block with 0 votes\n");
                continue;
            }
            MineNewBlock(newVotes, numVotes, data->blockchain, data->peerList);
            numVotes = 0;
        }else if(strcmp(choice, "print") == 0){
            PrintBlockchain(data->blockchain);
        }else if(strcmp(choice, "get") == 0){
            getchar();
            printf("Insert candidate\n");
            scanf("%[^\n]", candidate);
            getchar();
            printf("The candidate %s has received the %.2f%% of votes\n", candidate, GetPercentage(data->blockchain, candidate) * 100);
        }else if(strcmp(choice, "peers") == 0){
            printf("\nLIST OF PEERS\n");
            PrintPeers(data->peerList);
            printf("\n");
        }else if(strcmp(choice, "command") == 0){
            PrintCommands();
        }
    }
}

void PrintCommands(){
    printf("\n- add: \t\tAdds a vote to the new vote list, you will be required to insert the voter ID and the candidate voted for.\n");
    printf("- send: \tCreates a new block containing the new vote list, sends it to the other peers, and adds it to the blockchain if all peers accept it.\n");
    printf("- print: \tDisplays the blockchain.\n");
    printf("- get: \t\tDisplays the percentage of votes received by the candidate you specify.\n");
    printf("- peers: \tDisplays the peer list with their local IP addresses and listening ports.\n");
    printf("- command: \tDisplays the list of commands.\n\n");
}

int main(int argc, char **argv){
    //WSADATA wsa;
    SOCKET peerSocket, centralSocket;
    struct sockaddr_in peerAddr, centralAddr;
    int addrLength = sizeof(peerAddr), port;
    Peers *peerList = malloc(sizeof(Peers));
    data_t data;
    pthread_t tid[2];

    sem_init(&blockchainMutex, 0, 0);
    sem_init(&peerMutex, 0, 1);
    sem_init(&miningMutex, 0, 1);

    data.peerList = peerList;

    //WSAStartup(MAKEWORD(2,2), &wsa);
    InitializeSockets();

    peerSocket = socket(AF_INET, SOCK_STREAM, 0);
    peerAddr.sin_family = AF_INET;
    peerAddr.sin_port = htons(0);
    peerAddr.sin_addr.s_addr = INADDR_ANY;
    bind(peerSocket, (struct sockaddr *)&peerAddr, sizeof(peerAddr));
    data.socket = peerSocket;
    getsockname(peerSocket, (struct sockaddr *)&peerAddr, &addrLength);
    port = ntohs(peerAddr.sin_port);

    GenerateRsaKeys(&privateKey, &publicKey);

    if(argc == 1)
        Discover(DEFAULT_CENTRAL_IP, port, peerList);
    else
        Discover(argv[1], port, peerList);

    pthread_create(tid, NULL, ReceiveMessageThread, &data);
    pthread_create(tid + 1, NULL, CheckBlockchainThread, &data);

    if(peerList->thisPeer == 0){
        printf("Creating blockchain\n");
        data.blockchain = CreateBlockchain();
        printf("Blockchain created\n");
        sem_post(&blockchainMutex);
    }
    else{
        data.blockchain = malloc(sizeof(Blockchain));
        printf("Receiving blockchain\n");
        ReceiveBlockchain(peerList, data.blockchain);
        printf("Blockchain received\n");
    }
    sem_post(&blockchainMutex);

    printf("\nType \"command\" to display the list of available commands.\n\n");

    Interaction(&data);
    
    pthread_join(tid[0], NULL);
    pthread_join(tid[1], NULL);

    CloseSocket(peerSocket);
    CleanupSockets();
    return 0;
}