import json
import os
import hashlib
from binascii import hexlify, unhexlify
import struct
import time

DIFFICULTY_TARGET = "0000ffff00000000000000000000000000000000000000000000000000000000"
MEMPOOL_DIR = "mempool"
BLOCK_HEIGHT = 620000
PREV_BLOCK_HASH = "0000000000000000000000000000000000000000000000000000000000000000"  # Replace with the actual previous block hash

def sha256(data):
    return hashlib.sha256(data).digest()

def double_sha256(data):
    return sha256(sha256(data))

def read_transactions(mempool_dir):
    transactions = []
    for filename in os.listdir(mempool_dir):
        if filename.endswith(".json"):
            with open(os.path.join(mempool_dir, filename), 'r') as file:
                transaction = json.load(file)
                transactions.append(transaction)
    return transactions

def validate_transaction(tx):
    try:
        assert isinstance(tx['version'], int), "Invalid version"
        assert isinstance(tx['locktime'], int), "Invalid locktime"
        assert tx['locktime'] <= BLOCK_HEIGHT, "Transaction locktime is not yet valid"
        
        for vin in tx['vin']:
            assert isinstance(vin['txid'], str) and len(vin['txid']) == 64, "Invalid input txid"
            assert isinstance(vin['vout'], int), "Invalid input vout"
            assert 'scriptsig' in vin or 'witness' in vin, "Missing scriptsig or witness"
        
        for vout in tx['vout']:
            assert isinstance(vout['value'], int) and vout['value'] > 0, "Invalid output value"
            assert isinstance(vout['scriptpubkey'], str), "Invalid scriptpubkey"
        
        return True
    except AssertionError:
        return False

def serialize_transaction(tx):
    serialized_tx = b""
    serialized_tx += struct.pack("<i", tx['version'])
    
    serialized_tx += struct.pack("<I", len(tx['vin']))
    for vin in tx['vin']:
        serialized_tx += unhexlify(vin['txid'])[::-1]
        serialized_tx += struct.pack("<I", vin['vout'])
        scriptsig = bytes.fromhex(vin['scriptsig']) if vin['scriptsig'] else b""
        serialized_tx += struct.pack("<I", len(scriptsig))
        serialized_tx += scriptsig
        serialized_tx += struct.pack("<I", vin['sequence'])
    
    serialized_tx += struct.pack("<I", len(tx['vout']))
    for vout in tx['vout']:
        serialized_tx += struct.pack("<q", vout['value'])
        scriptpubkey = bytes.fromhex(vout['scriptpubkey'])
        serialized_tx += struct.pack("<I", len(scriptpubkey))
        serialized_tx += scriptpubkey
    
    serialized_tx += struct.pack("<i", tx['locktime'])
    return serialized_tx

def calculate_merkle_root(transactions):
    if not transactions:
        return "0000000000000000000000000000000000000000000000000000000000000000"

    hashes = [double_sha256(serialize_transaction(tx)) for tx in transactions]

    while len(hashes) > 1:
        if len(hashes) % 2 != 0:
            hashes.append(hashes[-1])

        new_hashes = []
        for i in range(0, len(hashes), 2):
            new_hashes.append(double_sha256(hashes[i] + hashes[i + 1]))

        hashes = new_hashes

    return hexlify(hashes[0][::-1]).decode()

def mine_block(transactions):
    valid_transactions = [tx for tx in transactions if validate_transaction(tx)]
    coinbase_tx = valid_transactions[0]
    txids = [hashlib.sha256(serialize_transaction(tx)).hexdigest() for tx in valid_transactions]

    nonce = 0
    version = 1
    prev_block_hash = PREV_BLOCK_HASH
    merkle_root = calculate_merkle_root(valid_transactions)
    timestamp = int(time.time())
    bits = unhexlify(DIFFICULTY_TARGET)

    while True:
        block_header = struct.pack("<I", version) + \
                       unhexlify(prev_block_hash)[::-1] + \
                       unhexlify(merkle_root)[::-1] + \
                       struct.pack("<I", timestamp) + \
                       bits + \
                       struct.pack("<I", nonce)
        
        block_hash = hexlify(double_sha256(block_header)).decode()
        
        if block_hash < DIFFICULTY_TARGET:
            print("Block mined successfully with hash:", block_hash)
            break
        nonce += 1
    
    serialized_coinbase = serialize_transaction(coinbase_tx)
    
    return [hexlify(block_header).decode(), hexlify(serialized_coinbase).decode()] + txids

def write_output(block_data):
    with open("output.txt", "w") as f:
        for line in block_data:
            f.write(line + "\n")

def main():
    transactions = read_transactions(MEMPOOL_DIR)
    mined_block = mine_block(transactions)
    write_output(mined_block)
    print("Finished writing mined block to output.txt")

if __name__ == "__main__":
    main()