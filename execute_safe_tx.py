#!/usr/bin/env python3
"""
Minimal Safe tx executor with verbose logging.

Requirements:
  pip install web3 requests
"""

import argparse
import json
import sys
import time
import requests
from web3 import Web3
from eth_account import Account
from datetime import datetime

def log(msg):
    ts = datetime.utcnow().isoformat(timespec="seconds")
    print(f"[{ts}] {msg}", flush=True)

SAFE_API_BASE = "https://api.safe.global/tx-service"

NETWORKS = {
    "ethereum": ("eth", 1),
    "gnosis": ("gno", 100),
    "arbitrum": ("arb1", 42161),
    "sepolia": ("sep", 11155111),
}

SAFE_ABI = json.loads("""
[
  {
    "inputs": [
      {"internalType":"address","name":"to","type":"address"},
      {"internalType":"uint256","name":"value","type":"uint256"},
      {"internalType":"bytes","name":"data","type":"bytes"},
      {"internalType":"uint8","name":"operation","type":"uint8"},
      {"internalType":"uint256","name":"safeTxGas","type":"uint256"},
      {"internalType":"uint256","name":"baseGas","type":"uint256"},
      {"internalType":"uint256","name":"gasPrice","type":"uint256"},
      {"internalType":"address","name":"gasToken","type":"address"},
      {"internalType":"address","name":"refundReceiver","type":"address"},
      {"internalType":"bytes","name":"signatures","type":"bytes"}
    ],
    "name":"execTransaction",
    "outputs":[{"internalType":"bool","name":"success","type":"bool"}],
    "stateMutability":"payable",
    "type":"function"
  }
]
""")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--network", required=True)
    ap.add_argument("--rpc", required=True)
    ap.add_argument("--safe", required=True)
    ap.add_argument("--nonce", required=True, help="single nonce or range (e.g. 5 or 5-10)")
    ap.add_argument("--private-key", required=True)
    ap.add_argument("--gas-limit", type=int, default=800000)
    ap.add_argument("--gas-price", type=int)
    args = ap.parse_args()

    log("starting Safe tx executor")

    # parse nonce or nonce range
    if "-" in args.nonce:
        start, end = args.nonce.split("-", 1)
        nonces = list(range(int(start), int(end) + 1))
    else:
        nonces = [int(args.nonce)]
    log(f"nonces to execute: {nonces}")

    if args.network not in NETWORKS:
        log(f"unsupported network: {args.network}")
        sys.exit(1)

    net_slug, chain_id = NETWORKS[args.network]
    log(f"selected network={args.network} chain_id={chain_id}")

    api = f"{SAFE_API_BASE}/{net_slug}"
    log(f"Safe API endpoint={api}")

    log("connecting to RPC")
    w3 = Web3(Web3.HTTPProvider(args.rpc))
    if not w3.is_connected():
        log("RPC connection failed")
        sys.exit(1)
    log("RPC connected")

    acct = Account.from_key(args.private_key)
    log(f"loaded signer address={acct.address}")

    safe_addr = Web3.to_checksum_address(args.safe)
    safe = w3.eth.contract(address=safe_addr, abi=SAFE_ABI)
    log("Safe contract instantiated")

    for nonce in nonces:
        log(f"--- processing nonce={nonce} ---")

        log(f"fetching Safe tx for safe={args.safe} nonce={nonce}")
        r = requests.get(
            f"{api}/api/v2/safes/{args.safe}/multisig-transactions/",
            params={"nonce": nonce},
            timeout=10,
        )
        log(f"Safe API response status={r.status_code}")
        r.raise_for_status()

        data = r.json()
        log(f"transactions returned={data.get('count', 0)}")

        if data.get("count", 0) == 0:
            log("no transaction found for nonce, skipping")
            continue

        tx = data["results"][0]
        log("using first transaction entry")
        log(f"safeTxHash={tx.get('safeTxHash')}")
        log(f"to={tx.get('to')} value={tx.get('value')} operation={tx.get('operation')}")

        log("assembling Safe execution payload from Safe service data")

        # --- log full Safe tx fields ---
        log(f"safeTxHash={tx['safeTxHash']}")
        log(f"to={tx['to']}")
        log(f"value={tx['value']}")
        log(f"data={tx['data']}")
        log(f"operation={tx['operation']}")
        log(f"safeTxGas={tx['safeTxGas']}")
        log(f"baseGas={tx['baseGas']}")
        log(f"gasPrice={tx['gasPrice']}")
        log(f"gasToken={tx['gasToken']}")
        log(f"refundReceiver={tx['refundReceiver']}")

        # --- signatures ---
        log("collecting signatures from Safe service")

        confirmations = tx.get("confirmations", [])
        log(f"confirmations found={len(confirmations)}")

        if len(confirmations) == 0:
            log("Safe transaction has no confirmations, skipping")
            continue

        sig_bytes = []

        # Safe requires signatures sorted by signer address (ascending)
        for c in sorted(confirmations, key=lambda x: x["owner"].lower()):
            owner = c["owner"]
            sig_hex = c["signature"]

            if sig_hex is None:
                log(f"missing signature for owner {owner}, skipping nonce")
                continue

            sig = Web3.to_bytes(hexstr=sig_hex)

            log(
                f"confirmation owner={owner} "
                f"len={len(sig)} "
                f"sig={sig_hex}"
            )

            sig_bytes.append(sig)

        signatures = b"".join(sig_bytes)
        log(f"total concatenated signatures length={len(signatures)} bytes")

        # --- build execTransaction call ---
        log("building execTransaction call (executor pays gas)")

        exec_tx = safe.functions.execTransaction(
            Web3.to_checksum_address(tx["to"]),
            int(tx["value"]),
            Web3.to_bytes(hexstr=tx["data"]),
            int(tx["operation"]),
            int(tx["safeTxGas"]),
            int(tx["baseGas"]),
            int(tx["gasPrice"]),
            Web3.to_checksum_address(tx["gasToken"]),
            Web3.to_checksum_address(tx["refundReceiver"]),
            signatures,
        )


        gas_price = args.gas_price or w3.eth.gas_price
        log(f"using gas_price={gas_price} gas_limit={args.gas_limit}")

        log("sending transaction")
        log("building transaction dict")

        tx_dict = exec_tx.build_transaction({
            "from": acct.address,
            "gas": args.gas_limit,
            "gasPrice": gas_price,
            "nonce": w3.eth.get_transaction_count(acct.address, "pending"),
            "chainId": chain_id,
        })

        log("signing raw transaction")
        signed_tx = acct.sign_transaction(tx_dict)

        log("sending raw transaction via eth_sendRawTransaction")
        tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)

        log(f"transaction submitted hash={tx_hash.hex()}")

        log("waiting 2 seconds before next transaction")
        time.sleep(2)

    log("done")

if __name__ == "__main__":
    main()

