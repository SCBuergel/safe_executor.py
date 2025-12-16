# Safe Transaction Executor

A minimal Python script to execute pending [Safe](https://safe.global/) multisig transactions on-chain.

## What it does

This script fetches pending Safe transactions from the Safe Transaction Service API and submits them to the blockchain. It's useful when you have a fully-signed Safe transaction that needs to be executed (i.e., the required number of owners have already signed).

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python execute_safe_tx.py \
  --network <network> \
  --rpc <rpc_url> \
  --safe <safe_address> \
  --nonce <nonce_or_range> \
  --private-key <private_key> \
  [--gas-limit <gas_limit>] \
  [--gas-price <gas_price>]
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `--network` | Yes | Network name: `ethereum`, `gnosis`, `arbitrum`, or `sepolia` |
| `--rpc` | Yes | RPC endpoint URL |
| `--safe` | Yes | Safe multisig address |
| `--nonce` | Yes | Safe tx nonce (single: `5`) or range (`5-10`) |
| `--private-key` | Yes | Private key of the executor account |
| `--gas-limit` | No | Gas limit (default: 800000) |
| `--gas-price` | No | Gas price in wei (default: fetched from network) |

### Example

```bash
python execute_safe_tx.py \
  --network ethereum \
  --rpc https://eth.llamarpc.com \
  --safe 0x1234...abcd \
  --nonce 42 \
  --private-key 0xabc123...
```

Execute a range of nonces:

```bash
python execute_safe_tx.py \
  --network sepolia \
  --rpc https://rpc.sepolia.org \
  --safe 0x1234...abcd \
  --nonce 5-10 \
  --private-key 0xabc123...
```

## ⚠️ Security Warning

**Never expose your private key in shell history, environment variables, or logs.**

- Use a **dedicated executor wallet** with only enough ETH to cover gas costs
- Do **not** use a key that controls significant funds
- Consider using a hardware wallet or secure key management solution for production use
- Clear your shell history after running commands containing private keys

The executor account does not need to be a Safe owner—it only needs ETH to pay for gas.

