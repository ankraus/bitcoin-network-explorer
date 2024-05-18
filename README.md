# BitcoinNetworkMonitor

This is a small command-line application built in Rust that connects to the Bitcoin network and parses new block data as it comes in.
For each block the program displays:

- Timestamp
- The calculated hash of the block
- The expected hash of the block
- Whether or not the two hashes match
- The block version
- The hash of the previous block
- The difficulty
- The nonce
- The total number of transactions in the block
- The total value of all transactions in the block
- Which transaction was the most valuable
- All transactions that are worth more than 1 BTC

**Note:**
Depending on the Bitcoin network, it can take up to an hour for a block to arrive. No output from the program does not mean it crashed. If there is an error or the connection gets lost, the program will explicitly tell the user.

## Prerequesits

- Rust > 1.76
- Cargo > 1.76

## Running

1. Clone the repository `git clone https://github.com/ankraus/bitcoin-network-explorer.git`
2. `cd bitcoin-network-explorer`
3. Check the configuration file (`config.toml`)
4. Run the program using `cargo run`
5. The program will start and wait for Block data to arrive
6. To exit the program, press `ctrl + c`
