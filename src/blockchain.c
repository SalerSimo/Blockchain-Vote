#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<time.h>
#include<openssl/sha.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include<openssl/err.h>
#include"blockchain.h"

#define DIFFICULTY 4
#define NONE "none"
#define KEY_LENGTH 2048

int VerifyHash(char *hash){
    for(int i=0; i<DIFFICULTY; i++){
        if(hash[i] != '0'){
            return 0;
        }
    }
    return 1;
}

char *CalculateHash(Block* block){
    int inputSize;
    char input[sizeof(Block)], *hash_output = malloc(65);
    unsigned char hash[SHA256_DIGEST_LENGTH];

    inputSize = sprintf(input, "%d%ld", block->index, block->timestamp);

    for(int i=0; i<block->numVotes; i++){
        inputSize += sprintf(input + inputSize, "%s%s", block->votes[i].voterId, block->votes[i].candidateVoted);
    }
    sprintf(input + inputSize, "%s%d\0", block->prevHash, block->nonce);

    SHA256((unsigned char*)input, strlen(input), hash);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        sprintf(hash_output + (i * 2), "%02x", hash[i]);

    hash_output[64] = '\0';
    return hash_output;
}

void MineBlock(Block *block){
    char *hash;
    while(1){
        hash = CalculateHash(block);
        if(VerifyHash(hash)){
            strcpy(block->hash, hash);
            free(hash);
            break;
        }
        free(hash);
        block->nonce++;
    }
}

Block *CreateGenesisBlock(){
    Block *genesis = malloc(sizeof(Block));
    genesis->index = 0;
    genesis->timestamp = time(NULL);
    strcpy(genesis->votes[0].candidateVoted, "Genesis block");
    strcpy(genesis->votes[0].voterId, NONE);
    genesis->numVotes = 1;
    //strcpy(genesis->data, "Genesis block");
    strcpy(genesis->prevHash, NONE);
    genesis->nonce = 0;
    MineBlock(genesis);
    return genesis;
}

Block *CreateEndBlock(){
    Block *end = malloc(sizeof(Block));
    return end;
}

Blockchain *CreateBlockchain(){
    Blockchain *blockchain = (Blockchain *)malloc(sizeof(Blockchain));
    blockchain->head = CreateGenesisBlock();
    blockchain->tail = blockchain->head;
    blockchain->end = CreateEndBlock();
    blockchain->tail->next = blockchain->end;
    strcpy(blockchain->end->prevHash, blockchain->tail->hash);
    return blockchain;
}

void AddBlock(Blockchain *blockchain, Block *block){
    blockchain->tail->next = block;
    blockchain->tail = block;
    block->next = blockchain->end;
    strcpy(blockchain->end->prevHash, block->hash);
}

Block *CreateBlock(Blockchain *blockchain, Vote *voteArray, int numVotes){
    Block *newBlock = malloc(sizeof(Block));
    newBlock->index = blockchain->tail->index + 1;
    newBlock->timestamp = time(NULL);
    newBlock->numVotes = numVotes;
    for(int i=0; i<numVotes; i++){
        strcpy(newBlock->votes[i].voterId, voteArray[i].voterId);
        strcpy(newBlock->votes[i].candidateVoted, voteArray[i].candidateVoted);
    }
    strcpy(newBlock->prevHash, blockchain->tail->hash);
    newBlock->nonce = 0;
    MineBlock(newBlock);
    //AddBlock(blockchain, newBlock);
    return newBlock;
}

void CreateAndAddBlock(Blockchain *blockchain, Vote *voteArray, int numVotes){
    Block *newBlock = CreateBlock(blockchain, voteArray, numVotes);
    AddBlock(blockchain, newBlock);
}

void PrintBlock(Block *block){
    printf("Index: \t\t %d\n", block->index);
    printf("Timestamp: \t %ld\n\n", block->timestamp);
    /*printf("\nVote 0\n");
    printf("Voter ID: \t %s\n", block->votes[0].voterId);
    if(strcmp(block->votes[0].voterId, "Genesis block") != 0)
        printf("Candidate voted: %s\n",block->votes[0].candidateVoted);*/
    for(int i=0; i<block->numVotes; i++){
        printf("Vote %d:\t\t %s\n", i, block->votes[i].candidateVoted);
        /*printf("Voter ID: \t %s\n", block->votes[i].voterId);
        printf("Candidate voted: %s\n",block->votes[i].candidateVoted);*/
    }
    printf("\nHash: \t\t %s\n", block->hash);
    printf("Previous hash: \t %s\n", block->prevHash);
    printf("Nonce: \t\t %d\n", block->nonce);
}

void PrintBlockchain(Blockchain *blockchain){
    Block *block = blockchain->head;

    printf("PRINTING BLOCKCHAIN\n");

    while(block != blockchain->end){
        printf("\n");
        PrintBlock(block);
        printf("\n");
        if(block->next != blockchain->end){
            printf(" |\n");
            printf(" |\n");
            printf(" V\n");
        }
        block = block->next;
    }
}

int CheckIntegrity(Blockchain *blockchain){
    Block *block = blockchain->head;
    char *hash;
    while(block != blockchain->end){
        hash = CalculateHash(block);
        if(strcmp(hash, block->next->prevHash) != 0 && !CheckBlock(block, blockchain)){
            return 0;
        }
        block = block->next;
    }
    return 1;
}

int CheckBlock(Block *block, Blockchain *blockchain){
    Block *blockchainBlock = blockchain->head;
    if(strcmp(block->hash, CalculateHash(block)) != 0)
        return 0;
    for(int i=0; i<block->numVotes; i++){
        //printf("checking vote %d\n", i);
        while(blockchainBlock != blockchain->end){
            for(int j=0; j<blockchainBlock->numVotes; j++){
                if(strcmp(block->votes[i].voterId, blockchainBlock->votes[j].voterId) == 0){
                    printf("There cannot be two vote with the same voter ID\n");
                    return 0;
                }
            }
            blockchainBlock = blockchainBlock->next;
        }
    }
    return 1;
}

void SaveBlockchain(Blockchain *blockchain, char *filePath){
    Block *block = blockchain->head;
    FILE *fp = fopen(filePath, "wb");

    while(block != blockchain->end){
        fwrite(block, 1, sizeof(*block), fp);
        block = block->next;
    }
    fclose(fp);
}

Blockchain *LoadBlockchain(char *filePath){
    Blockchain *blockchain = malloc(sizeof(Blockchain));
    Block *block = malloc(sizeof(Block));
    FILE *fp = fopen(filePath, "rb");

    blockchain->end = CreateEndBlock();

    fread(block, 1, sizeof(*block), fp);

    blockchain->head = block;
    blockchain->tail = block;
    blockchain->tail->next = blockchain->end;

    block = malloc(sizeof(Block));

    while(fread(block, 1, sizeof(*block), fp) != 0){
        AddBlock(blockchain, block);
        block = malloc(sizeof(Block));
    }
    free(block);
    fclose(fp);
    return blockchain;
}

void printVote(Vote *vote){
    printf("Voter ID: \t%s\n", vote->voterId);
    printf("Candidate voted: %s\n", vote->candidateVoted);
}

char *HashVote(Vote *vote){
    char voteData[512], hash[SHA256_DIGEST_LENGTH];
    char *hashString = malloc(65);

    sprintf(voteData, "%s%s", vote->voterId, vote->candidateVoted);

    SHA256((unsigned char *)voteData, strlen(voteData), hash);

    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++){
        sprintf(&hashString[i * 2], "%02x", hash[i]);
    }
    
    hashString[64] = '\0';
    return hashString;
}

char *Sign(char *privateKey, char *message){
    EVP_PKEY *pkey = NULL;
    BIO *bio = BIO_new_mem_buf(privateKey, -1);
    EVP_PKEY_CTX *ctx;
    char *signedMessage;
    size_t signedLength;

    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_sign_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);

    EVP_PKEY_sign(ctx, NULL, &signedLength, message, strlen(message));
    signedMessage = malloc(KEY_LENGTH / 8);
    EVP_PKEY_sign(ctx, signedMessage, &signedLength, message, strlen(message));

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return signedMessage;
}

int VerifySign(char *publicKey, char *signedMessage, char *originalMessage){
    EVP_PKEY *pkey = NULL;
    BIO *bio = BIO_new_mem_buf(publicKey, -1);
    EVP_PKEY_CTX *ctx;
    int verifyStatus;

    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_verify_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);

    verifyStatus = EVP_PKEY_verify(ctx, signedMessage, KEY_LENGTH / 8, originalMessage, strlen(originalMessage));

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return verifyStatus;
}

char *Encrypt(char *publicKey, char *message){
    EVP_PKEY *pkey = NULL;
    BIO *bio = BIO_new_mem_buf(publicKey, -1);
    EVP_PKEY_CTX *ctx;
    char *encryptedMessage;
    size_t encryptedLength;

    pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

    EVP_PKEY_encrypt(ctx, NULL, &encryptedLength, message, strlen(message));
    encryptedMessage = malloc(KEY_LENGTH / 8);
    EVP_PKEY_encrypt(ctx, encryptedMessage, &encryptedLength, message, strlen(message));

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return encryptedMessage;
}

char *Decrypt(char *privateKey, char *encryptedMessage){
    EVP_PKEY *pkey = NULL;
    BIO *bio = BIO_new_mem_buf(privateKey, -1);
    EVP_PKEY_CTX *ctx;
    char *message;
    size_t messageLength;

    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_decrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

    EVP_PKEY_decrypt(ctx, NULL, &messageLength, encryptedMessage, KEY_LENGTH / 8);
    message = malloc(messageLength);
    EVP_PKEY_decrypt(ctx, message, &messageLength, encryptedMessage, KEY_LENGTH / 8);

    message[messageLength] = '\0';


    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return message;
}

void Blockchain_free(Blockchain *blockchain){
    Block *block = blockchain->head;
    Block *prevBlock;
    while(block != blockchain->end){
        prevBlock = block;
        block = block->next;
        free(prevBlock);
    }
    free(block);
    free(blockchain);
}

void GenerateRsaKeys(char **privateKey, char **publicKey){
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    BIO *privateBio, *publicBio;
    int keyLength;

    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, KEY_LENGTH);
    EVP_PKEY_keygen(ctx, &pkey);

    EVP_PKEY_CTX_free(ctx);

    privateBio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(privateBio, pkey, NULL, NULL, 0, NULL, NULL);
    keyLength = BIO_pending(privateBio) + 1;
    *privateKey = malloc(keyLength);
    BIO_read(privateBio, *privateKey, keyLength);
    (*privateKey)[keyLength] = '\0';
    BIO_free(privateBio);

    publicBio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(publicBio, pkey);
    keyLength = BIO_pending(publicBio) + 1;
    *publicKey = malloc(keyLength);
    BIO_read(publicBio, *publicKey, keyLength);
    (*publicKey)[keyLength] = '\0';
    BIO_free(publicBio);

    EVP_PKEY_free(pkey);
}

void SignVote(Vote *vote, char *privateKey){
    char *voteHash = HashVote(vote);
    char *hashSign = Sign(privateKey, voteHash);
    memcpy(vote->signature, hashSign, 256);
    free(hashSign);
}

int CheckSign(Vote *vote, char *publicKey){
    char *voteHash = HashVote(vote);
    return VerifySign(publicKey, vote->signature, voteHash);
}

int mainz(){
    char *privateKey, *publicKey;
    char *original = "tranquillo mbare";
    char *encrypted, *decrypted, *sign;
    int encryptedLength;
    
    Blockchain *blockchain = CreateBlockchain();
    PrintBlockchain(blockchain);

    Vote vote;

    strcpy(vote.candidateVoted, "01");
    strcpy(vote.voterId, "simo");

    CreateAndAddBlock(blockchain, &vote, 1);

    PrintBlockchain(blockchain);

    SaveBlockchain(blockchain, "blockchain.txt");

    Blockchain *blockchain2 = LoadBlockchain("blockchain.txt");
    PrintBlockchain(blockchain2);
    return 0;
}