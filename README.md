# II3230-Secure-Message-Delivery-Bat-Bat

Panduan singkat untuk menjalankan demo secure message delivery berbasis RSA dan AES.

## Prasyarat

- Dua perangkat (sender dan receiver) yang terhubung ke jaringan yang sama melalui Tailscale.
- Python 3.10+ terpasang di kedua perangkat.
- Paket PyCryptodome (`python -m pip install pycryptodome`).

## Langkah Persiapan Jaringan

1. Install Tailscale di kedua perangkat dan login ke jaringan yang sama.
2. Buka terminal lalu periksa IP Tailscale masing-masing:
	- `tailscale ip`
3. Lakukan uji konektivitas:
	- `ping <ip-device-lawan>`

## Langkah Membuat Kunci

Eksekusi perintah berikut di masing-masing perangkat sesuai peran:

```bash
python generate_keys.py sender      # dijalankan di sisi pengirim
python generate_keys.py receiver    # dijalankan di sisi penerima
```

File akan tersimpan di folder `keys/`:

- Sender: `sender_private.pem` dan `sender_public.pem`
- Receiver: `receiver_private.pem` dan `receiver_public.pem`

Berbagilah **hanya** public key ke partner, jangan pernah mengirimkan private key.

## Langkah Menjalankan Receiver

1. Pastikan file `receiver_private.pem` tersedia di `keys/` atau siapkan path khusus.
2. Jalankan receiver dengan port yang disepakati (contoh 5000):

```bash
python receiver.py 5000
```

Receiver akan menampilkan IP Tailscale yang perlu diberi tahu ke pengirim.

## Langkah Menjalankan Sender

1. Pastikan file `sender_private.pem` ada di `keys/`.
2. Dapatkan IP Tailscale receiver dari langkah sebelumnya.
3. Kirim pesan dengan format:

```bash
python sender.py <IP_Tailscale_receiver> <port>
# contoh: python sender.py 100.64.0.5 5000
```

## Anggota Kelompok

| Nama | NIM | Role |
| --- | --- | --- | 
| Rayhan Hidayatul Fikri | 18223022 | Bob (Receiver) |
| Princessfa Azzahra Alvin | 18223044 | Alice (Sender) |

