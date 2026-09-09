"""Codificação mínima do wire-format do protobuf + montagem do MajorLogin.

Só o necessário pra montar o payload do ``MajorLoginReq`` está implementado
aqui (codificação de campos varint/string/int) - não é uma lib de protobuf
genérica, só o suficiente pra reproduzir o que o app mobile manda no login.
"""

import random
import time
import uuid
from datetime import datetime

GAME_VERSION = "1.126.1"  # atualize se o handshake começar a ser recusado

_DEVICES = [
    ("samsung SM-M526B", "Adreno (TM) 642L", "Android OS 13 / API-33 (TP1A.220624.014/M526BXXS7CYD2)"),
    ("samsung SM-G991B", "Mali-G78 MP20", "Android OS 14 / API-34 (UP1A.231005.007/G991BXXS9CXA1)"),
    ("Xiaomi M2102K1G", "Adreno (TM) 650", "Android OS 12 / API-31 (RKQ1.211001.001/V13.0.4.0)"),
    ("Google Pixel 7", "Mali-G710 MP7", "Android OS 14 / API-34 (AP2A.240305.005/11583682)"),
    ("OnePlus IN2023", "Adreno (TM) 660", "Android OS 13 / API-33 (TP1A.220624.014/A.10)"),
]


def encode_varint(value: int) -> bytes:
    bits = value & 0x7F
    value >>= 7
    result = b""
    while value:
        result += bytes([0x80 | bits])
        bits = value & 0x7F
        value >>= 7
    return result + bytes([bits])


def encode_string(field_num: int, value) -> bytes:
    tag = (field_num << 3) | 2
    encoded = value.encode("utf-8") if isinstance(value, str) else value
    return encode_varint(tag) + encode_varint(len(encoded)) + encoded


def encode_int(field_num: int, value: int) -> bytes:
    tag = field_num << 3
    return encode_varint(tag) + encode_varint(value)


def encode_bytes(field_num: int, value: bytes) -> bytes:
    return encode_string(field_num, value)


def build_major_login_packet(open_id: str, access_token: str, client_ip: str, uid) -> bytes:
    """Monta o corpo do MajorLoginReq (ainda precisa da criptografia de
    envelope com ``crypto.encrypt_envelope`` antes de mandar via HTTP)."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    rng = random.Random(str(uid))
    device, gpu, os_str = rng.choice(_DEVICES)
    carrier = rng.choice(["VIVO", "TIM", "CLARO", "OI", "ALGAR"])
    net = rng.choice(["WIFI", "WIFI", "4G", "5G"])
    width, height = rng.choice([(1666, 750), (2400, 1080), (1920, 1080), (2340, 1080)])
    device_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, str(uid)))

    proto = b""
    proto += encode_string(3, now)
    proto += encode_string(4, "free fire")
    proto += encode_int(5, 1)
    proto += encode_string(7, GAME_VERSION)
    proto += encode_string(8, os_str)
    proto += encode_string(9, "Handheld")
    proto += encode_string(10, carrier)
    proto += encode_string(11, net)
    proto += encode_int(12, width)
    proto += encode_int(13, height)
    proto += encode_string(14, str(rng.randint(100, 999)))
    proto += encode_string(
        15, f"ARM64 FP ASIMD AES | {rng.choice([2400, 2800, 3000, 3200])} | {rng.choice([4, 6, 8])}"
    )
    proto += encode_int(16, rng.randint(4000, 12000))
    proto += encode_string(17, gpu)
    proto += encode_string(18, rng.choice(["OpenGL ES 3.0", "OpenGL ES 3.1", "OpenGL ES 3.2"]))
    proto += encode_string(19, f"Google|{device_uuid}")
    proto += encode_string(20, client_ip)
    proto += encode_string(21, "pt-br")
    proto += encode_string(22, open_id)
    proto += encode_int(23, 4)
    proto += encode_string(24, "Handheld")
    proto += encode_string(25, device)
    proto += encode_string(29, access_token)
    proto += encode_int(30, 1)
    proto += encode_string(41, carrier)
    proto += encode_string(42, net)
    proto += encode_int(97, 1)
    proto += encode_int(98, 1)
    return proto
