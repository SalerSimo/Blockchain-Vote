# Blockchain-Vote
A decentralized, secure, and transparent digital voting system built from scratch using the blockchain technology, implemented in C.  
The system creates a peer-to-peer (P2P) network, enabling direct communication between peers within the same local network. A central node is used to coordinate peers, ensuring  synchronization and network stability.


## Features
- **Secure Voting**: Each vote is recorded as a blockchain transaction, ensuring data integrity.
- **Immutability**: Votes cannot be altered or deleted, preventing tampering.
- **Transparency**: All votes are visible on the blockchain, ensuring openness in the election process.
- **Decentralization**: The voting system runs on a distributed blockchain network, eliminating the need for intermediaries.

## Requirements
- C compiler (e.g., GCC)
- Windows, Linux or macOS

## Installation
1. Clone the repository:
    ```bash
    git clone https://github.com/SalerSimo/Blockchain-Vote.git
    cd Blockchain-Vote
## Usage
1. Compile `central_node.c` and `peer.c`:

    ```bash
    gcc src/central_node.c -o central -lws2_32

    gcc src/peer.c src/blockchain.c -o peer -Iinclude -Llib -llibssl -llibcrypto -lws2_32
2. Start the central node:  
Run `central` on the device that will act as the central node
3. Start the peers:  
Run `peer` on other devices, providing the local IP address of the central node as an argument
