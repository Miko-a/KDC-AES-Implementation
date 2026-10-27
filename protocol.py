import getpass
import ipaddress
import json
from pathlib import Path
import re
import secrets
import socket
import string
import struct
import time
from dataclasses import dataclass, field

from crypto import (
    AES128, compute_hmac, crypt_ctr, derive_mac_key, validate_ascii_key,
)

MAX_FRAME = 262144
MAX_TEXT = 4096
HANDSHAKE_TIMEOUT = 30
DEFAULT_CONFIG = Path(__file__).with_name("network.json")


class ProtocolError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise ProtocolError(message)


def ascii_json(value):
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ).encode("ascii")


def nonce():
    return secrets.token_hex(16)


def is_nonce(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value) is not None


def new_session_key():
    # Key sesi 16 karakter ASCII, sesuai format input/output tugas.
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(16))


def _mac_input(message_type, counter_hex, ciphertext_hex):
    return ascii_json(["kdc-aes-v1", message_type, counter_hex, ciphertext_hex])


def protect(key_text, message_type, data):
    key = validate_ascii_key(key_text)
    raw = ascii_json(data)
    require(len(raw) <= MAX_FRAME // 3, "Data terenkripsi terlalu besar")
    # 96 bit acak untuk tiap record, 32 bit terakhir untuk counter blok.
    # Batas ukuran record menjamin counter blok tidak keluar dari 32 bit.
    counter = secrets.token_bytes(12) + b"\x00" * 4
    ciphertext = crypt_ctr(AES128(key), raw, counter)
    record = {"counter": counter.hex(), "ciphertext": ciphertext.hex()}
    record["tag"] = compute_hmac(
        derive_mac_key(key),
        _mac_input(message_type, record["counter"], record["ciphertext"]),
    )
    return record


def unprotect(key_text, message_type, record):
    from crypto import verify_hmac

    require(isinstance(record, dict), "Record harus berupa object")
    require(set(record) == {"counter", "ciphertext", "tag"}, "Format record salah")
    counter_hex, ciphertext_hex = record["counter"], record["ciphertext"]
    require(is_nonce(counter_hex), "Counter harus 16 byte dalam Hex")
    require(
        isinstance(ciphertext_hex, str)
        and 0 < len(ciphertext_hex) <= 2 * (MAX_FRAME // 3)
        and len(ciphertext_hex) % 2 == 0
        and re.fullmatch(r"[0-9a-f]+", ciphertext_hex) is not None,
        "Ciphertext Hex tidak valid",
    )
    key = validate_ascii_key(key_text)
    # Autentikasi ciphertext dan jenis pesan SEBELUM dekripsi.
    require(verify_hmac(
        derive_mac_key(key),
        _mac_input(message_type, counter_hex, ciphertext_hex), record["tag"],
    ), "HMAC tidak valid: key salah atau pesan berubah")
    raw = crypt_ctr(AES128(key), bytes.fromhex(ciphertext_hex), bytes.fromhex(counter_hex))
    try:
        value = json.loads(raw.decode("ascii"))
    except (UnicodeError, ValueError) as error:
        raise ProtocolError("Plaintext protokol tidak valid") from error
    require(isinstance(value, dict), "Payload harus berupa object")
    return value


def send_frame(sock, message):
    raw = ascii_json(message)
    require(0 < len(raw) <= MAX_FRAME, "Ukuran frame tidak valid")
    sock.sendall(struct.pack("!I", len(raw)) + raw)


def _recv_exact(sock, length):
    result = bytearray()
    while len(result) < length:
        chunk = sock.recv(length - len(result))
        if not chunk:
            if not result:
                raise EOFError("Koneksi ditutup")
            raise ProtocolError("Koneksi terputus di tengah frame")
        result.extend(chunk)
    return bytes(result)


def recv_frame(sock):
    length = struct.unpack("!I", _recv_exact(sock, 4))[0]
    require(0 < length <= MAX_FRAME, "Ukuran frame tidak valid")
    try:
        value = json.loads(_recv_exact(sock, length).decode("ascii"))
    except (UnicodeError, ValueError) as error:
        raise ProtocolError("Frame harus berupa JSON ASCII") from error
    require(isinstance(value, dict), "Frame harus berupa object")
    if value.get("type") == "error":
        raise ProtocolError("Pihak lain menolak permintaan")
    return value


def expect_step(message, step):
    require(type(message.get("step")) is int and message["step"] == step, f"Menunggu langkah {step}")


def connect(ip, port, source_ip=None):
    # source_ip hanya diperlukan harness pengujian tiga IP loopback.
    source = (source_ip, 0) if source_ip else None
    return socket.create_connection((ip, port), HANDSHAKE_TIMEOUT, source)


def load_network(path=DEFAULT_CONFIG):
    with open(path, encoding="ascii") as handle:
        network = json.load(handle)
    ips = []
    for role in ("kdc", "alice", "bob"):
        ips.append(str(ipaddress.IPv4Address(network[role]["ip"])))
    require(len(set(ips)) == 3, "KDC, Alice, dan Bob harus memiliki IP berbeda")
    for role in ("kdc", "bob"):
        port = network[role]["port"]
        require(type(port) is int and 1 <= port <= 65535, "Port tidak valid")
    return network


def read_key(label):
    while True:
        try:
            value = getpass.getpass(f"{label} (16 karakter ASCII; ketik lalu Enter, input tersembunyi): ")
        except EOFError as error:
            raise ValueError("Jalankan program di terminal interaktif untuk memasukkan key") from error
        try:
            validate_ascii_key(value, label)
            return value
        except (TypeError, ValueError) as error:
            print(error, flush=True)


def log_record(label, record):
    print(f"{label}\n  Ciphertext (Hex): {record['ciphertext']}", flush=True)


@dataclass
class Session:
    key: str = field(repr=False)
    sid: str
    alice: str
    bob: str
    created: int
    expires: int

    def validate(self):
        validate_ascii_key(self.key, "Session key")
        require(is_nonce(self.sid), "ID sesi tidak valid")
        require(self.alice == "alice" and self.bob == "bob", "Identitas sesi salah")
        require(type(self.created) is int and type(self.expires) is int, "Waktu tidak valid")
        require(0 < self.expires - self.created <= 3600, "Masa berlaku tidak valid")
        require(self.created <= time.time() + 30, "Jam perangkat tidak sinkron")
        self.check_alive()

    def check_alive(self):
        require(time.time() < self.expires, "Sesi kedaluwarsa; lakukan distribusi kunci baru")

    @classmethod
    def from_payload(cls, payload):
        fields = ("key", "sid", "alice", "bob", "created", "expires")
        require(all(name in payload for name in fields), "Data sesi tidak lengkap")
        session = cls(**{name: payload[name] for name in fields})
        session.validate()
        return session

    def payload(self):
        return {name: getattr(self, name) for name in (
            "key", "sid", "alice", "bob", "created", "expires",
        )}
