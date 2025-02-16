#include<time.h>

#define DATA_SIZE 1024
#define SIGNATURE_LEN 64
#define MAX_MSG_LENGTH 256
#define MAX_VOTES 10

#define MAX_PEERS 10
#define MAX_PUBLIC_KEY_LENGTH 600
#define CENTRAL_PORT 5000
#define DEFAULT_CENTRAL_IP "192.168.178.21"

typedef struct{
    char voterId[MAX_MSG_LENGTH];
    char candidateVoted[MAX_MSG_LENGTH];
    char signature[MAX_MSG_LENGTH];
}Vote;

typedef struct Block{
    int index;
    time_t timestamp;
    Vote votes[MAX_VOTES];
    int numVotes;
    //char data[DATA_SIZE];
    char prevHash[65];
    char hash[65];
    long int nonce;
    struct Block *next;
}Block;

typedef struct{
    Block *head;
    Block *tail;
    Block *end;
}Blockchain;

int VerifyHash(char *hash);

char *CalculateHash(Block* block);

void MineBlock(Block *block);

Block *CreateGenesisBlock();

Block *CreateEndBlock();

Blockchain *CreateBlockchain();

Block *CreateBlock(Blockchain *blockchain, Vote *voteArray, int numVotes);

void PrintBlock(Block *block);

void AddBlock(Blockchain *blockchain, Block *block);

void PrintBlockchain(Blockchain *blockchain);

int CheckIntegrity(Blockchain *blockchain);
int CheckBlock(Block *block, Blockchain *blockchain);

void SaveBlockchain(Blockchain *blockchain, char *filePath);

Blockchain *LoadBlockchain(char *filePath);

void Blockchain_free(Blockchain *blockchain);

void GenerateRsaKeys(char **privateKey, char **publicKey);

void SignVote(Vote *vote, char *privateKey);
int CheckSign(Vote *vote, char *publicKey);

char *Encrypt(char *publicKey, char *message);
char *Decrypt(char *privateKey, char *encryptedMessage);