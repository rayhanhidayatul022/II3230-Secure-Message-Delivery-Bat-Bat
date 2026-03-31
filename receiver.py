import sys
import json
import socket
import base64
import argparse
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Util.Padding import unpad

def load_key(filepath):
    with open(filepath, "rb") as f:
        return RSA.import_key(f.read())

def main():
    parser = argparse.ArgumentParser(description="Secure Message Receiver")
    parser.add_argument("port", type=int, help="Port to listen on")
    parser.add_argument("-q", "--quiet", action="store_true", help="Minimal output (for assignment)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output (show all intermediate values)")
    parser.add_argument("--receiver-priv", help="Path to receiver private key (PEM)")
    parser.add_argument("--sender-pub", help="Path to sender public key (PEM)")
    args = parser.parse_args()

    port = args.port

    verbosity = 1
    if args.quiet:
        verbosity = 0
    if args.verbose:
        verbosity = 2

    def log(level, *messages):
        if verbosity >= level:
            print(*messages)

    log(1, "=" * 60)
    log(1, "Secure Message Receiver")
    log(1, "=" * 60)

    # Buka server socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", port))
    server.listen(1)

    # Dapatkan semua IP yang tersedia
    import subprocess
    tailscale_ip = None
    try:
        result = subprocess.run(["tailscale", "ip", "-4"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            tailscale_ip = result.stdout.strip()
    except Exception:
        pass

    if tailscale_ip:
        local_ip = tailscale_ip
    else:
        s_temp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s_temp.connect(("8.8.8.8", 80))
            local_ip = s_temp.getsockname()[0]
        except Exception:
            local_ip = "127.0.0.1"
        finally:
            s_temp.close()

    log(1, f"\n[*] Menunggu koneksi di {local_ip}:{port} ...")
    log(2, f"[*] Beritahu sender untuk mengirim ke IP: {local_ip} Port: {port}")

    conn, addr = server.accept()
    log(1, f"\n[+] Koneksi diterima dari {addr[0]}:{addr[1]}")

    raw_len = conn.recv(4)
    if not raw_len:
        log(1, "[!] Tidak ada data diterima.")
        return
    data_len = int.from_bytes(raw_len, "big")

    data = b""
    while len(data) < data_len:
        chunk = conn.recv(min(4096, data_len - len(data)))
        if not chunk:
            break
        data += chunk

    payload = json.loads(data.decode("utf-8"))

    log(1, f"\n[1] Payload diterima dari {payload.get('source_ip', 'unknown')}:")
    log(2, json.dumps(payload, indent=2))

    # ===== STEP 2: Decrypt AES key dengan RSA private key receiver =====
    import os as _os
    if args.receiver_priv:
        receiver_priv_path = args.receiver_priv
    else:
        possible_receiver_priv = [
            "keys/receiver_private.pem",
        ]
        receiver_priv_path = next((p for p in possible_receiver_priv if _os.path.exists(p)), possible_receiver_priv[0])
    receiver_private_key = load_key(receiver_priv_path)
    cipher_rsa = PKCS1_OAEP.new(receiver_private_key)
    encrypted_aes_key = base64.b64decode(payload["encrypted_key"])
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    log(2, f"    AES Key (hex): {aes_key.hex()}")

    # ===== STEP 3: Decrypt ciphertext dengan AES =====
    log(2, "\n[3] Mendekripsi ciphertext dengan AES-256-CBC...")
    iv = base64.b64decode(payload["iv"])
    ciphertext = base64.b64decode(payload["ciphertext"])
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext_bytes = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)
    plaintext = plaintext_bytes.decode("utf-8")
    log(1, f"    Plaintext hasil dekripsi:\n    \"{plaintext}\"")

    # ===== STEP 4: Verifikasi Hash =====
    log(2, "\n[4] Memverifikasi hash (SHA-256)...")
    hash_local = SHA256.new(plaintext_bytes)
    hash_local_hex = hash_local.hexdigest()
    hash_received = payload["hash"]
    log(2, f"    Hash dari payload : {hash_received}")
    log(2, f"    Hash dihitung ulang: {hash_local_hex}")

    if hash_local_hex == hash_received:
        log(1, "    >> HASH VALID - Pesan tidak berubah selama transmisi!")
        hash_valid = True
    else:
        log(1, "    >> HASH TIDAK VALID - Pesan mungkin telah dimodifikasi!")
        hash_valid = False

    # ===== STEP 5: Verifikasi Digital Signature =====
    log(2, "\n[5] Memverifikasi digital signature dengan public key sender...")
    if args.sender_pub:
        sender_pub_path = args.sender_pub
    else:
        possible_sender_pub = [
            "keys/sender_public.pem",
        ]
        sender_pub_path = next((p for p in possible_sender_pub if _os.path.exists(p)), possible_sender_pub[0])
    sender_public_key = load_key(sender_pub_path)
    signature = base64.b64decode(payload["signature"])

    try:
        # Verifikasi signature terhadap hash yang dihitung ulang dari plaintext
        pkcs1_15.new(sender_public_key).verify(hash_local, signature)
        log(1, "    >> SIGNATURE VALID - Pesan benar berasal dari sender!")
        sig_valid = True
    except (ValueError, TypeError):
        log(1, "    >> SIGNATURE TIDAK VALID - Pengirim tidak terverifikasi!")
        sig_valid = False

    log(1, "\n" + "=" * 60)
    log(1, "KESIMPULAN:")
    log(1, "=" * 60)
    log(1, f"  Pesan berhasil didekripsi : Ya")
    log(1, f"  Integritas pesan (hash)   : {'Terjaga' if hash_valid else 'GAGAL'}")
    log(1, f"  Autentikasi pengirim      : {'Terverifikasi (sender)' if sig_valid else 'GAGAL'}")
    log(2, f"\n  Algoritma yang digunakan:")
    log(2, f"    - Symmetric  : {payload.get('symmetric_algorithm', 'AES-256-CBC')}")
    log(2, f"    - Asymmetric : {payload.get('asymmetric_algorithm', 'RSA-2048')}")
    log(2, f"    - Hash       : {payload.get('hash_algorithm', 'SHA-256')}")
    log(2, f"\n  IP Pengirim  : {payload.get('source_ip', '-')}")
    log(2, f"  IP Penerima  : {payload.get('destination_ip', '-')}")
    log(1, "=" * 60)

    # Kirim konfirmasi ke sender
    if hash_valid and sig_valid:
        conn.sendall("OK - Pesan diterima, terverifikasi, dan terdekripsi.".encode("utf-8"))
    else:
        conn.sendall("WARNING - Pesan diterima tapi verifikasi gagal.".encode("utf-8"))

    conn.close()
    server.close()
    print("\n[*] Koneksi ditutup.")


if __name__ == "__main__":
    main()