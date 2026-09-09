"""AES helpers used by the Free Fire login/session protocol.

``ENVELOPE_KEY``/``ENVELOPE_IV`` are the fixed AES-CBC key/IV every client
uses to wrap the very first ``MajorLogin`` request, before any per-session
key exists yet. They are not secret to this project — they are baked into
the mobile client itself and are the same for every player/account.

Once login succeeds, the server hands back a per-session key/IV (``chave``/
``iv``) that ``encrypt_packet`` uses to encrypt every packet sent over the
TCP game connection from then on.
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

ENVELOPE_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
ENVELOPE_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])


def encrypt_envelope(data_hex: str) -> str:
    """Encrypts the initial MajorLogin request with the fixed client key."""
    data = bytes.fromhex(data_hex)
    cipher = AES.new(ENVELOPE_KEY, AES.MODE_CBC, ENVELOPE_IV)
    return cipher.encrypt(pad(data, AES.block_size)).hex()


def as_bytes(value) -> bytes:
    if isinstance(value, str):
        return bytes.fromhex(value)
    return value


def encrypt_packet(plaintext, key, iv) -> str:
    """Encrypts a packet body with the per-session key/IV (hex string in, hex string out)."""
    if isinstance(plaintext, str):
        plaintext = bytes.fromhex(plaintext)
    key = as_bytes(key)
    iv = as_bytes(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, AES.block_size)).hex()


def int_to_hex(value: int) -> str:
    return f"{value:02x}"
