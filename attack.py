from oracle import VulnerableOracle, BLOCK_SIZE, split_blocks, pkcs7_unpad


def recover_block_with_oracle(oracle: VulnerableOracle, prev_block: bytes, target_block: bytes) -> bytes:
    """
    Recovers the plaintext of target_block using the padding oracle
    and the previous ciphertext block.
    """
    if len(prev_block) != BLOCK_SIZE or len(target_block) != BLOCK_SIZE:
        raise ValueError("Both blocks must be exactly 16 bytes")

    recovered_plaintext = bytearray(BLOCK_SIZE)
    intermediate = bytearray(BLOCK_SIZE)

    for pad_value in range(1, BLOCK_SIZE + 1):
        idx = BLOCK_SIZE - pad_value
        found = False

        for guess in range(256):
            crafted_prev = bytearray(prev_block)

            # Set already recovered bytes to produce current padding value
            for j in range(BLOCK_SIZE - 1, idx, -1):
                crafted_prev[j] = intermediate[j] ^ pad_value

            # Guess the current byte
            crafted_prev[idx] = guess

            test_ciphertext = bytes(crafted_prev) + target_block

            if oracle.has_valid_padding(test_ciphertext):
                intermediate[idx] = guess ^ pad_value
                recovered_plaintext[idx] = intermediate[idx] ^ prev_block[idx]
                found = True
                break

        if not found:
            raise RuntimeError(f"Failed to recover byte at position {idx}")

    return bytes(recovered_plaintext)


def decrypt_full_ciphertext(oracle: VulnerableOracle, ciphertext: bytes) -> bytes:
    """
    Decrypts full ciphertext of the form IV || C1 || C2 || ... || Cn
    using the padding oracle.
    """
    blocks = split_blocks(ciphertext)

    if len(blocks) < 2:
        raise ValueError("Need at least IV + 1 ciphertext block")

    recovered = b""

    for i in range(1, len(blocks)):
        prev_block = blocks[i - 1]
        target_block = blocks[i]
        recovered_block = recover_block_with_oracle(oracle, prev_block, target_block)
        recovered += recovered_block

    return pkcs7_unpad(recovered)


def main() -> None:
    oracle = VulnerableOracle()

    secret_message = b"Padding oracle attacks break CBC when padding errors leak."

    ciphertext = oracle.encrypt(secret_message)

    print("=" * 60)
    print("Original secret message:")
    print(secret_message.decode())
    print("=" * 60)

    print("Ciphertext (hex):")
    print(ciphertext.hex())
    print("=" * 60)

    recovered = decrypt_full_ciphertext(oracle, ciphertext)

    print("Recovered plaintext:")
    print(recovered.decode())
    print("=" * 60)

    print("Attack success:", recovered == secret_message)


if __name__ == "__main__":
    main()
