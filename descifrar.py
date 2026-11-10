import sys
from scapy.all import rdpcap, Raw, IP, TCP
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

PCAP = sys.argv[1] if len(sys.argv) > 1 else "transacciones_cifradas.pcap"
PRIV = sys.argv[2] if len(sys.argv) > 2 else "clave_privada.pem"

RSA_TAG = b"RSA_PIN|"
AES_TAG = b"AESGCM|"
SALT_LEN, NONCE_LEN = 16, 12

paquetes = []
for n, p in enumerate(rdpcap(PCAP), 1):
    if p.haslayer(TCP) and p.haslayer(Raw):
        paquetes.append((n, bytes(p[Raw].load)))

pkt_rsa = next((n, d) for n, d in paquetes if d.startswith(RSA_TAG))
n_rsa, d = pkt_rsa
cuerpo = d[len(RSA_TAG):]
salt, pin_cifrado = cuerpo[:SALT_LEN], cuerpo[SALT_LEN:]
print(f"Paquete RSA_PIN: #{n_rsa} | salt={salt.hex()} | PIN cifrado={len(pin_cifrado)} bytes")

with open(PRIV, "rb") as f:
    priv = serialization.load_pem_private_key(f.read(), password=None)
pin = priv.decrypt(
    pin_cifrado,
    padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
).decode()
print("PIN recuperado con RSA")
print(f"PIN: {pin}")

key = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(pin.encode())
print(f"Clave AES-256 derivada: {key.hex()}")

tx = [(n, d) for n, d in paquetes if d.startswith(AES_TAG)]
print(f"Mensajes cifrados encontrados: {len(tx)}\n")
print("Mensajes cifrados\n")

aes, ok = AESGCM(key), 0
for i, (n, d) in enumerate(tx, 1):
    cuerpo = d[len(AES_TAG):]
    nonce, ct = cuerpo[:NONCE_LEN], cuerpo[NONCE_LEN:]
    try:
        texto = aes.decrypt(nonce, ct, None).decode()
        ok += 1
        print(f"Mensaje {i} (paquete #{n}, nonce={nonce.hex()})\n{texto}\n")
    except InvalidTag:
        print(f"Mensaje {i} (paquete #{n}) falla en la autenticación\n")

print(f"[+] {ok}/{len(tx)} mensajes autenticados correctamente (tag GCM válido)")
