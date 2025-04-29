import requests
import time
import hashlib
import struct
import binascii
from multiprocessing import Pool, cpu_count, Manager, Process
from datetime import datetime
import json
import os

# ==== RPC настройки ====
RPC_USER = "testuser"
RPC_PASSWORD = "Hw8pKv3zYq"
RPC_URL = "http://127.0.0.1:18332"  # testnet RPC порт

# ==== Получение bits с fallback ====
def get_bits():
    try:
        response = requests.get('https://mempool.space/testnet/api/blocks/tip', timeout=10)
        response.raise_for_status()
        block_data = response.json()
        if isinstance(block_data, list) and block_data:
            block_data = block_data[0]
        bits_value = block_data.get('bits')
        if isinstance(bits_value, str):
            return int(bits_value, 16)
        elif isinstance(bits_value, int):
            return bits_value
    except Exception as e:
        print(f"Ошибка получения bits: {e}")
    return 0x1efffff0  # слабая сложность (fallback)

# ==== Получение текущего блока (testnet) ====
def get_latest_block_data():
    try:
        response = requests.get('https://blockstream.info/testnet/api/blocks', timeout=10)
        response.raise_for_status()
        block_data = response.json()[0]
        prev_hash = block_data['id']
        block_height = block_data['height'] + 1
        timestamp = int(time.time())
        bits = get_bits()
        return prev_hash, bits, block_height, timestamp
    except Exception as e:
        raise Exception(f"Ошибка получения блока: {e}")

# ==== Получение транзакций ====
def get_mempool_transactions():
    return []  # пустой список — coinbase-only блок

# ==== SHA-256 двойной ====
def double_sha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

# ==== Merkle root (только coinbase) ====
def compute_merkle_root(transactions):
    if not transactions:
        return double_sha256(b'').hex()
    tx_hashes = [double_sha256(binascii.unhexlify(tx)).hex() for tx in transactions]
    while len(tx_hashes) > 1:
        if len(tx_hashes) % 2 != 0:
            tx_hashes.append(tx_hashes[-1])
        new_hashes = []
        for i in range(0, len(tx_hashes), 2):
            combined = binascii.unhexlify(tx_hashes[i] + tx_hashes[i+1])
            new_hashes.append(double_sha256(combined).hex())
        tx_hashes = new_hashes
    return tx_hashes[0]

# ==== Создание coinbase-транзакции ====
def create_coinbase_transaction(block_height: int) -> str:
    subsidy = 5000000000  # 50 BTC → для regtest/testnet
    height_script = block_height.to_bytes((block_height.bit_length() + 7) // 8, 'little').hex()

    script_sig = f"{len(height_script)//2:02x}{height_script}03ffff001d"
    output_script = "0014d0e6b0f8f7c8e9d8f8c7e6d5f4c3b2a1f0e9d8c7"  # P2WPKH dummy
    tx = (
        "01000000" +
        "01" +
        "00"*32 + "ffffffff" +
        f"{len(script_sig)//2:02x}" + script_sig +
        "ffffffff" +
        "01" +
        struct.pack("<Q", subsidy).hex() +
        f"{len(output_script)//2:02x}" + output_script +
        "00000000"
    )
    return tx

# ==== bits → target ====
def bits_to_target(bits: int) -> int:
    exponent = bits >> 24
    mantissa = bits & 0xffffff
    return mantissa * (1 << (8 * (exponent - 3)))

# ==== block header ====
def create_block_header(prev_hash: str, merkle_root: str, timestamp: int, bits: int, nonce: int) -> bytes:
    version = 0x20000000
    return struct.pack(
        "<L32s32sLLL",
        version,
        bytes.fromhex(prev_hash)[::-1],
        bytes.fromhex(merkle_root)[::-1],
        timestamp,
        bits,
        nonce
    )

# ==== block hash ====
def get_block_hash(header: bytes) -> str:
    return double_sha256(header)[::-1].hex()

# ==== Проверка хеша ====
def is_valid_hash(block_hash: str, target: int) -> bool:
    return int(block_hash, 16) < target

# ==== Вспомогательное: varint ====
def encode_varint(n):
    if n < 0xfd:
        return struct.pack("<B", n).hex()
    elif n < 0xffff:
        return "fd" + struct.pack("<H", n).hex()
    elif n < 0xffffffff:
        return "fe" + struct.pack("<L", n).hex()
    else:
        return "ff" + struct.pack("<Q", n).hex()

# ==== Сборка блока ====
def assemble_block(header: bytes, coinbase_tx: str, transactions: list) -> str:
    tx_count = 1 + len(transactions)
    return header.hex() + encode_varint(tx_count) + coinbase_tx + "".join(transactions)

# ==== Отправка блока в Bitcoin Core ====
def submit_block(block_hex: str):
    try:
        payload = {
            "jsonrpc": "1.0",
            "id": "miner",
            "method": "submitblock",
            "params": [block_hex]
        }
        response = requests.post(
            RPC_URL,
            data=json.dumps(payload),
            auth=(RPC_USER, RPC_PASSWORD),
            headers={"Content-Type": "application/json"},
            timeout=10
        )
        result = response.json()
        if result.get("result") is None:
            print("✔ Блок успешно принят нодой!")
            return True
        else:
            print(f"❌ Ошибка: {result.get('error')}")
            return False
    except Exception as e:
        print(f"❌ Ошибка отправки блока: {e}")
        return False

# ==== Майнинг чанка ====
def mine_chunk(args):
    start_nonce, end_nonce, prev_hash, merkle_root, timestamp, bits, target = args
    for nonce in range(start_nonce, end_nonce):
        header = create_block_header(prev_hash, merkle_root, timestamp, bits, nonce)
        block_hash = get_block_hash(header)
        if is_valid_hash(block_hash, target):
            return nonce, block_hash, header
    return None

# ==== Старт майнинга ====
def start_mining():
    print("🚀 Запуск SOLO майнинга (testnet)")
    initial_block_found = False

    while not initial_block_found:
        try:
            prev_hash, bits, height, timestamp = get_latest_block_data()
            target = bits_to_target(bits)
            print(f"⛏ Высота: {height} | Bits: {hex(bits)} | Target: {hex(target)}")

            coinbase_tx = create_coinbase_transaction(height)
            transactions = []
            merkle_root = compute_merkle_root([coinbase_tx])
            print(f"🔗 Merkle root: {merkle_root}")

            num_cores = cpu_count()
            chunk_size = 500_000
            start_nonce = 0
            end_nonce = 0xffffffff

            args_list = []
            for i in range(num_cores):
                chunk_start = start_nonce + i * chunk_size
                chunk_end = min(chunk_start + chunk_size, end_nonce)
                args_list.append((chunk_start, chunk_end, prev_hash, merkle_root, timestamp, bits, target))

            with Pool(processes=num_cores) as pool:
                results = pool.imap_unordered(mine_chunk, args_list)
                for result in results:
                    if result:
                        nonce, block_hash, header = result
                        print(f"\n✅ Найден блок!")
                        print(f"Nonce: {nonce}")
                        print(f"Hash: {block_hash}")

                        block_hex = assemble_block(header, coinbase_tx, transactions)
                        submit_block(block_hex)

                        # Создание файла с найденным блоком
                        os.makedirs("Test", exist_ok=True)
                        with open(f"Test/block_{height}.txt", "w") as f:
                            f.write(f"Block Height: {height}\n")
                            f.write(f"Nonce: {nonce}\n")
                            f.write(f"Hash: {block_hash}\n")

                        initial_block_found = True
                        break

            if not initial_block_found:
                print("❌ Блок не найден, начинаем новый проход...\n")
                time.sleep(1)

        except Exception as e:
            print(f"❗ Ошибка: {e}")
            time.sleep(5)

# ==== Запуск ====
if __name__ == "__main__":
    start_mining()
