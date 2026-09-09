"""Funções AES usadas pelo protocolo de login/sessão do Free Fire.

``ENVELOPE_KEY``/``ENVELOPE_IV`` são a chave/IV AES-CBC fixas que todo
cliente usa pra embrulhar a primeiríssima requisição ``MajorLogin``, antes
de existir qualquer chave por sessão. Não são segredo deste projeto — vêm
embutidas no próprio app mobile e são as mesmas pra qualquer jogador/conta.

Depois que o login dá certo, o servidor devolve uma chave/IV por sessão
(``chave``/``iv``) que ``encrypt_packet`` usa pra criptografar todo pacote
mandado pela conexão TCP do jogo dali em diante.
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

ENVELOPE_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
ENVELOPE_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])


def encrypt_envelope(data_hex: str) -> str:
    """Criptografa a requisição inicial MajorLogin com a chave fixa do cliente."""
    data = bytes.fromhex(data_hex)
    cipher = AES.new(ENVELOPE_KEY, AES.MODE_CBC, ENVELOPE_IV)
    return cipher.encrypt(pad(data, AES.block_size)).hex()


def as_bytes(value) -> bytes:
    if isinstance(value, str):
        return bytes.fromhex(value)
    return value


def encrypt_packet(plaintext, key, iv) -> str:
    """Criptografa o corpo de um pacote com a chave/IV da sessão (entra hex, sai hex)."""
    if isinstance(plaintext, str):
        plaintext = bytes.fromhex(plaintext)
    key = as_bytes(key)
    iv = as_bytes(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(plaintext, AES.block_size)).hex()


def int_to_hex(value: int) -> str:
    return f"{value:02x}"
