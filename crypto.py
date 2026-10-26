import hashlib
import hmac
from typing import List, Sequence


# Ukuran blok dan kunci AES-128 dalam byte.
BLOCK_SIZE = 16
KEY_SIZE = 16


# Memvalidasi key sebagai tepat 16 karakter ASCII yang dapat dicetak.
def validate_ascii_key(value: str, name: str = "key") -> bytes:
    if not isinstance(value, str):
        raise TypeError(f"{name} harus berupa string.")

    try:
        encoded = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(
            f"{name} hanya boleh berisi karakter ASCII."
        ) from exc

    if len(encoded) != KEY_SIZE:
        raise ValueError(
            f"{name} harus tepat 16 karakter ASCII untuk AES-128."
        )

    # Batasi key ke karakter yang bisa diketik dan ditampilkan.
    if any(byte < 0x20 or byte > 0x7E for byte in encoded):
        raise ValueError(
            f"{name} harus terdiri dari karakter ASCII yang dapat dicetak."
        )

    return encoded


# Mengubah plaintext string menjadi bytes ASCII, tanpa batas panjang 16 byte.
def encode_ascii_plaintext(value: str) -> bytes:
    if not isinstance(value, str):
        raise TypeError("Plaintext harus berupa string.")

    try:
        return value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError(
            "Plaintext hanya boleh berisi karakter ASCII."
        ) from exc


# Memvalidasi hasil dekripsi lalu mengubah bytes menjadi string ASCII.
def decode_ascii_plaintext(value: bytes) -> str:
    if not isinstance(value, bytes):
        raise TypeError("Plaintext harus bertipe bytes.")

    try:
        return value.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError(
            "Plaintext hasil dekripsi bukan ASCII."
        ) from exc


# S-Box AES untuk transformasi SubBytes.
S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]


# Inverse S-Box AES untuk proses dekripsi.
INV_S_BOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
]


# Konstanta round untuk proses key expansion AES-128.
RCON = [
    0x00, 0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
]


# Mengalikan byte dengan x pada medan hingga GF(2^8).
def _xtime(value: int) -> int:
    value &= 0xFF
    return (
        (((value << 1) ^ 0x1B) & 0xFF)
        if (value & 0x80)
        else ((value << 1) & 0xFF)
    )


# Mengalikan dua byte dalam GF(2^8), digunakan oleh MixColumns.
def _gf_mul(a: int, b: int) -> int:
    result = 0
    a &= 0xFF
    b &= 0xFF

    while b:
        if b & 1:
            result ^= a
        a = _xtime(a)
        b >>= 1

    return result & 0xFF


# Memutar empat byte word satu posisi ke kiri.
def _rot_word(word: Sequence[int]) -> List[int]:
    return list(word[1:]) + [word[0]]


# Mengganti setiap byte word menggunakan S-Box AES.
def _sub_word(word: Sequence[int]) -> List[int]:
    return [S_BOX[b] for b in word]


# Menggabungkan state dengan round key menggunakan XOR.
def _add_round_key(
    state: List[int],
    round_key: Sequence[int],
) -> None:
    for i in range(BLOCK_SIZE):
        state[i] ^= round_key[i]


# Melakukan substitusi byte state menggunakan S-Box.
def _sub_bytes(state: List[int]) -> None:
    for i, value in enumerate(state):
        state[i] = S_BOX[value]


# Melakukan substitusi invers byte saat dekripsi.
def _inv_sub_bytes(state: List[int]) -> None:
    for i, value in enumerate(state):
        state[i] = INV_S_BOX[value]


# Menggeser baris state ke kiri sesuai indeks baris.
def _shift_rows(state: List[int]) -> None:
    # State disimpan column-major: indeks = baris + 4 * kolom.
    old = state[:]

    for row in range(4):
        for col in range(4):
            state[row + 4 * col] = old[
                row + 4 * ((col + row) % 4)
            ]


# Menggeser baris state ke kanan saat dekripsi.
def _inv_shift_rows(state: List[int]) -> None:
    old = state[:]

    for row in range(4):
        for col in range(4):
            state[row + 4 * col] = old[
                row + 4 * ((col - row) % 4)
            ]


# Mencampur byte pada setiap kolom state.
def _mix_columns(state: List[int]) -> None:
    for col in range(4):
        i = 4 * col
        a0, a1, a2, a3 = state[i:i + 4]

        state[i] = (
            _gf_mul(a0, 2)
            ^ _gf_mul(a1, 3)
            ^ a2
            ^ a3
        )
        state[i + 1] = (
            a0
            ^ _gf_mul(a1, 2)
            ^ _gf_mul(a2, 3)
            ^ a3
        )
        state[i + 2] = (
            a0
            ^ a1
            ^ _gf_mul(a2, 2)
            ^ _gf_mul(a3, 3)
        )
        state[i + 3] = (
            _gf_mul(a0, 3)
            ^ a1
            ^ a2
            ^ _gf_mul(a3, 2)
        )


# Membalik transformasi MixColumns saat dekripsi.
def _inv_mix_columns(state: List[int]) -> None:
    for col in range(4):
        i = 4 * col
        a0, a1, a2, a3 = state[i:i + 4]

        state[i] = (
            _gf_mul(a0, 14)
            ^ _gf_mul(a1, 11)
            ^ _gf_mul(a2, 13)
            ^ _gf_mul(a3, 9)
        )
        state[i + 1] = (
            _gf_mul(a0, 9)
            ^ _gf_mul(a1, 14)
            ^ _gf_mul(a2, 11)
            ^ _gf_mul(a3, 13)
        )
        state[i + 2] = (
            _gf_mul(a0, 13)
            ^ _gf_mul(a1, 9)
            ^ _gf_mul(a2, 14)
            ^ _gf_mul(a3, 11)
        )
        state[i + 3] = (
            _gf_mul(a0, 11)
            ^ _gf_mul(a1, 13)
            ^ _gf_mul(a2, 9)
            ^ _gf_mul(a3, 14)
        )


# Implementasi AES-128 manual untuk blok 16 byte.
class AES128:

    rounds = 10

    # Memvalidasi ukuran key dan membentuk round key.
    def __init__(self, key: bytes):
        if not isinstance(key, bytes):
            raise TypeError("Kunci harus bertipe bytes.")

        if len(key) != KEY_SIZE:
            raise ValueError(
                "AES-128 membutuhkan kunci tepat 16 byte (128 bit)."
            )

        self.key = key
        self.round_keys = self._key_expansion(key)

    # Membentuk 11 round key AES-128 dari key awal.
    @staticmethod
    def _key_expansion(key: bytes) -> List[List[int]]:
        # AES-128: 4 word awal, total 44 word = 11 round key.
        words: List[List[int]] = [
            list(key[i:i + 4])
            for i in range(0, KEY_SIZE, 4)
        ]

        for i in range(4, 44):
            temp = words[i - 1][:]

            if i % 4 == 0:
                temp = _sub_word(_rot_word(temp))
                temp[0] ^= RCON[i // 4]

            words.append([
                words[i - 4][j] ^ temp[j]
                for j in range(4)
            ])

        round_keys = []

        for round_number in range(11):
            round_key = []

            for word in words[
                round_number * 4:(round_number + 1) * 4
            ]:
                round_key.extend(word)

            round_keys.append(round_key)

        return round_keys

    # Mengenkripsi satu blok plaintext tepat 16 byte.
    def encrypt_block(self, plaintext: bytes) -> bytes:
        if not isinstance(plaintext, bytes):
            raise TypeError("Plaintext harus bertipe bytes.")

        if len(plaintext) != BLOCK_SIZE:
            raise ValueError("AES menerima satu blok tepat 16 byte.")

        state = list(plaintext)
        _add_round_key(state, self.round_keys[0])

        for round_number in range(1, self.rounds):
            _sub_bytes(state)
            _shift_rows(state)
            _mix_columns(state)
            _add_round_key(state, self.round_keys[round_number])

        # Round terakhir tidak menggunakan MixColumns.
        _sub_bytes(state)
        _shift_rows(state)
        _add_round_key(state, self.round_keys[self.rounds])

        return bytes(state)

    # Mendekripsi satu blok ciphertext tepat 16 byte.
    def decrypt_block(self, ciphertext: bytes) -> bytes:
        if not isinstance(ciphertext, bytes):
            raise TypeError("Ciphertext harus bertipe bytes.")

        if len(ciphertext) != BLOCK_SIZE:
            raise ValueError("AES menerima satu blok tepat 16 byte.")

        state = list(ciphertext)
        _add_round_key(state, self.round_keys[self.rounds])

        for round_number in range(self.rounds - 1, 0, -1):
            _inv_shift_rows(state)
            _inv_sub_bytes(state)
            _add_round_key(state, self.round_keys[round_number])
            _inv_mix_columns(state)

        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, self.round_keys[0])

        return bytes(state)


# Menguji AES dengan test vector standar yang telah diketahui.
def _self_test() -> None:
    # Test vector AES-128 untuk menguji implementasi inti AES.
    # Key dan plaintext ini berupa data biner uji, bukan input pengguna.
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    expected_ciphertext = bytes.fromhex(
        "69c4e0d86a7b0430d8cdb78070b4c55a"
    )

    aes = AES128(key)
    ciphertext = aes.encrypt_block(plaintext)
    recovered_plaintext = aes.decrypt_block(ciphertext)

    assert ciphertext == expected_ciphertext, (
        f"Enkripsi tidak cocok: "
        f"{ciphertext.hex()} != {expected_ciphertext.hex()}"
    )
    assert recovered_plaintext == plaintext, (
        f"Dekripsi tidak cocok: "
        f"{recovered_plaintext.hex()} != {plaintext.hex()}"
    )

    print("Uji AES-128 berhasil.")
    print("Plaintext :", plaintext.hex())
    print("Kunci     :", key.hex())
    print("Ciphertext:", ciphertext.hex())
    print("Dekripsi  :", recovered_plaintext.hex())


# Nilai maksimum counter AES berukuran 128 bit.
MAX_COUNTER = (1 << 128) - 1


# Mengenkripsi atau mendekripsi data dengan AES-CTR.
def crypt_ctr(
    aes: AES128,
    data: bytes,
    initial_counter: bytes,
) -> bytes:
    if not isinstance(aes, AES128):
        raise TypeError("aes harus berupa instance AES128.")

    if not isinstance(data, bytes):
        raise TypeError("data harus berupa bytes.")

    if not isinstance(initial_counter, bytes):
        raise TypeError("initial_counter harus berupa bytes.")

    if len(initial_counter) != BLOCK_SIZE:
        raise ValueError("initial_counter harus tepat 16 byte.")

    start = int.from_bytes(initial_counter, byteorder="big")
    output = bytearray()

    for block_index, offset in enumerate(
        range(0, len(data), BLOCK_SIZE)
    ):
        counter_value = start + block_index

        if counter_value > MAX_COUNTER:
            raise OverflowError(
                "Counter AES-CTR melampaui batas 128 bit."
            )

        counter_block = counter_value.to_bytes(
            BLOCK_SIZE,
            byteorder="big",
        )

        keystream = aes.encrypt_block(counter_block)
        chunk = data[offset:offset + BLOCK_SIZE]

        output.extend(
            byte ^ stream_byte
            for byte, stream_byte in zip(chunk, keystream)
        )

    return bytes(output)


# ============================================================
# FUNGSI KRIPTOGRAFI HMAC
# ============================================================

# Konteks khusus untuk memisahkan key MAC dari key sesi AES.
MAC_KEY_CONTEXT = b"aes128-relay-demo|hmac-key|v1"


# Menurunkan key MAC terpisah dari key sesi AES-128.
def derive_mac_key(session_key: bytes) -> bytes:
    if not isinstance(session_key, bytes):
        raise TypeError("session_key harus bertipe bytes.")

    if len(session_key) != KEY_SIZE:
        raise ValueError(
            "Session key AES-128 harus tepat 16 byte."
        )

    return hmac.new(
        session_key,
        MAC_KEY_CONTEXT,
        hashlib.sha256,
    ).digest()


# Membuat tag HMAC-SHA256 dari data yang hendak diautentikasi.
def compute_hmac(mac_key: bytes, data: bytes) -> str:
    if not isinstance(mac_key, bytes):
        raise TypeError("mac_key harus bertipe bytes.")

    if len(mac_key) < 16:
        raise ValueError(
            "mac_key harus memiliki panjang minimal 16 byte."
        )

    if not isinstance(data, bytes):
        raise TypeError(
            "data yang diautentikasi harus berupa bytes."
        )

    return hmac.new(
        mac_key,
        data,
        hashlib.sha256,
    ).hexdigest()


# Memverifikasi tag HMAC tanpa membocorkan informasi perbandingan.
def verify_hmac(
    mac_key: bytes,
    data: bytes,
    tag_hex: str,
) -> bool:
    if not isinstance(mac_key, bytes):
        raise TypeError("mac_key harus bertipe bytes.")

    if len(mac_key) < 16:
        raise ValueError(
            "mac_key harus memiliki panjang minimal 16 byte."
        )

    if not isinstance(data, bytes):
        raise TypeError(
            "data yang diautentikasi harus berupa bytes."
        )

    # Tag harus berupa 64 karakter hexadecimal (32 byte).
    if (
        not isinstance(tag_hex, str)
        or len(tag_hex) != 64
        or any(
            char not in "0123456789abcdefABCDEF"
            for char in tag_hex
        )
    ):
        return False

    supplied_tag = bytes.fromhex(tag_hex)
    expected_tag = hmac.new(
        mac_key,
        data,
        hashlib.sha256,
    ).digest()

    return hmac.compare_digest(supplied_tag, expected_tag)


# ============================================================
# PENGUJIAN
# ============================================================

# Menguji penerimaan key ASCII valid dan penolakan input tidak valid.
def _test_ascii_validation() -> None:
    key = validate_ascii_key("Abcdefgh12345678")
    assert len(key) == KEY_SIZE

    plaintext = encode_ascii_plaintext("Pesan Alice ke Bob")
    assert decode_ascii_plaintext(plaintext) == "Pesan Alice ke Bob"

    # Key yang panjangnya salah harus ditolak.
    try:
        validate_ascii_key("terlalu pendek")
    except ValueError:
        pass
    else:
        raise AssertionError(
            "Key dengan panjang salah seharusnya ditolak."
        )

    # Key dengan karakter non-ASCII harus ditolak.
    try:
        validate_ascii_key("Abcdefgh12345é78")
    except ValueError:
        pass
    else:
        raise AssertionError(
            "Key non-ASCII seharusnya ditolak."
        )

    # Plaintext non-ASCII harus ditolak.
    try:
        encode_ascii_plaintext("Halo é")
    except ValueError:
        pass
    else:
        raise AssertionError(
            "Plaintext non-ASCII seharusnya ditolak."
        )

    print("Uji validasi ASCII berhasil.")


# Menguji bahwa HMAC menerima data asli dan menolak data yang diubah.
def _test_hmac() -> None:
    session_key = validate_ascii_key("Abcdefgh12345678")
    mac_key = derive_mac_key(session_key)
    data = b"alice|bob|message-001|ciphertext"

    tag = compute_hmac(mac_key, data)

    assert verify_hmac(mac_key, data, tag)
    assert not verify_hmac(mac_key, data + b"x", tag)
    assert not verify_hmac(mac_key, data, "00" * 32)

    print("Uji HMAC berhasil.")


# Menjalankan tes AES, validasi ASCII, dan HMAC saat file dijalankan langsung.
if __name__ == "__main__":
    _self_test()
    _test_ascii_validation()
    _test_hmac()
