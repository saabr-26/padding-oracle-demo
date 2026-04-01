from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length")

    pad_len = data[-1]

    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding length")

    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding bytes")

    return data[:-pad_len]


def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> list[bytes]:
    return [data[i:i + block_size] for i in range(0, len(data), block_size)]


class VulnerableOracle:
    """
    Local demo oracle for educational use.

    It encrypts data using AES-CBC and exposes a vulnerable API:
    the attacker can only ask whether the padding is valid or not.
    """

    def __init__(self) -> None:
        self.key = get_random_bytes(BLOCK_SIZE)

    def encrypt(self, plaintext: bytes) -> bytes:
        iv = get_random_bytes(BLOCK_SIZE)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pkcs7_pad(plaintext))
        return iv + ciphertext

    def decrypt_raw(self, data: bytes) -> bytes:
        if len(data) < 2 * BLOCK_SIZE or len(data) % BLOCK_SIZE != 0:
            raise ValueError("Ciphertext must contain IV + at least 1 block")

        iv = data[:BLOCK_SIZE]
        ciphertext = data[BLOCK_SIZE:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return cipher.decrypt(ciphertext)

    def has_valid_padding(self, data: bytes) -> bool:
        """
        This is the vulnerable oracle.
        Returns True if PKCS#7 padding is valid, otherwise False.
        """
        try:
            plaintext = self.decrypt_raw(data)
            pkcs7_unpad(plaintext)
            return True
        except ValueError:
            return False
