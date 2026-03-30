import sys
import json
import socket
import base64
import argparse
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


def load_key(filepath):
    with open(filepath, "rb") as f:
        return RSA.import_key(f.read())


def main():
    parser = argparse.ArgumentParser(description="Secure Message Sender")
    parser.add_argument("receiver_ip", help="Receiver IP address to connect to")
    parser.add_argument("receiver_port", type=int, help="Receiver port to connect to")
    parser.add_argument("-q", "--quiet", action="store_true", help="Minimal output (for assignment)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output (show all intermediate values)")
    # Optional explicit key paths
    parser.add_argument("--sender-priv", help="Path to sender private key (PEM)")
    parser.add_argument("--sender-pub", help="Path to sender public key (PEM)")
    parser.add_argument("--receiver-pub", help="Path to receiver public key (PEM)")
    args = parser.parse_args()

    receiver_ip = args.receiver_ip
    receiver_port = args.receiver_port

    # verbosity: 0 = quiet, 1 = normal, 2 = verbose
    verbosity = 1
    if args.quiet:
        verbosity = 0
    if args.verbose:
        verbosity = 2

    def log(level, *messages):
        # level: 0=quiet-only, 1=normal, 2=debug/verbose
        if verbosity >= level:
            print(*messages)

    # ===== STEP 1: Plaintext =====
    plaintext = (
        "Halo Bat, saya ingin menjalin kerjasama untuk melakukan training "
        "yang maksimal kepada rAI, saya juga akan bantu merahasiakan project "
        "rAI karena sebenarnya AI ini belum siap untuk digunakan oleh publik, "
        "oleh karena itu saya tertarik untuk berkolaborasi dengan anda sebagai "
        "penemu dari rAI, -Bat:)"
    )
    log(1, "=" * 60)
    log(1, "SENDER - Secure Message Sender")
    log(1, "=" * 60)
    log(2, f"\n[1] Plaintext:\n    {plaintext}")

    # ===== STEP 2: Generate AES-256 symmetric key =====
    aes_key = get_random_bytes(32)  # 256-bit
    aes_iv = get_random_bytes(16)   # IV for CBC mode
    log(2, f"\n[2] AES-256 Key (hex): {aes_key.hex()}")
    log(2, f"    AES IV (hex):      {aes_iv.hex()}")

    # ===== STEP 3: Encrypt plaintext with AES-256-CBC =====
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    plaintext_bytes = plaintext.encode("utf-8")
    ciphertext = cipher_aes.encrypt(pad(plaintext_bytes, AES.block_size))
    ciphertext_b64 = base64.b64encode(ciphertext).decode("utf-8")
    log(2, f"\n[3] Ciphertext (base64):\n    {ciphertext_b64}")

    # ===== STEP 4: Encrypt AES key with receiver's RSA public key =====
    if args.receiver_pub:
        receiver_pub_path = args.receiver_pub
    else:
        possible = [
            "keys/receiver_public.pem",
        ]
        receiver_pub_path = next((p for p in possible if os.path.exists(p)), possible[0])
    receiver_public_key = load_key(receiver_pub_path)
    cipher_rsa = PKCS1_OAEP.new(receiver_public_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key).decode("utf-8")
    log(2, f"\n[4] Encrypted AES Key (base64):\n    {encrypted_aes_key_b64}")

    # ===== STEP 5: Hash plaintext with SHA-256 =====
    hash_obj = SHA256.new(plaintext_bytes)
    hash_hex = hash_obj.hexdigest()
    log(2, f"\n[5] SHA-256 Hash:\n    {hash_hex}")

    # ===== STEP 6: Digital Signature with sender's RSA private key =====
    if args.sender_priv:
        sender_priv_path = args.sender_priv
    else:
        possible = [
            "keys/sender_private.pem",
        ]
        sender_priv_path = next((p for p in possible if os.path.exists(p)), possible[0])
    sender_private_key = load_key(sender_priv_path)
    signature = pkcs1_15.new(sender_private_key).sign(hash_obj)
    signature_b64 = base64.b64encode(signature).decode("utf-8")
    log(2, f"\n[6] Digital Signature (base64):\n    {signature_b64}")

    # ===== STEP 7: Build payload =====
    # Get local IP based on route to receiver (so Tailscale IP is detected correctly)
    s_temp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s_temp.connect((receiver_ip, receiver_port))
        local_ip = s_temp.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    finally:
        s_temp.close()

    payload = {
        "source_ip": local_ip,
        "destination_ip": receiver_ip,
        "ciphertext": ciphertext_b64,
        "encrypted_key": encrypted_aes_key_b64,
        "iv": base64.b64encode(aes_iv).decode("utf-8"),
        "hash": hash_hex,
        "signature": signature_b64,
        "hash_algorithm": "SHA-256",
        "symmetric_algorithm": "AES-256-CBC",
        "asymmetric_algorithm": "RSA-2048",
    }

    log(2, f"\n[7] Payload JSON:")
    log(2, json.dumps(payload, indent=2))

    # Send via TCP socket
    log(1, f"\n[*] Sending payload to {receiver_ip}:{receiver_port} ...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect((receiver_ip, receiver_port))
        payload_bytes = json.dumps(payload).encode("utf-8")
        # send length (4 bytes) then payload
        sock.sendall(len(payload_bytes).to_bytes(4, "big"))
        sock.sendall(payload_bytes)
        log(1, "[+] Payload sent successfully!")

        # Wait for response
        try:
            response = sock.recv(1024).decode("utf-8")
            log(1, f"[+] Response from receiver: {response}")
        except socket.timeout:
            log(1, "[!] No response (timeout).")
        sock.close()
    except ConnectionRefusedError:
        print("[!] ERROR: Cannot connect to receiver. Make sure receiver is running.")
    except socket.timeout:
        print("[!] ERROR: Connection timeout.")
    except Exception as e:
        print(f"[!] ERROR: {e}")

    log(1, "\n" + "=" * 60)
    log(1, "Done.")
    log(1, "=" * 60)


if __name__ == "__main__":
    main()
