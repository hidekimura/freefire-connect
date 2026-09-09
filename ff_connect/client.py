"""FreeFireClient: guest login + the raw TCP session with the game server.

Flow (mirrors what the mobile client does on boot):

1. ``_guest_oauth``      OAuth "guest" grant -> access_token + open_id
                         (POST 100067.connect.garena.com/oauth/guest/token/grant)
2. ``_major_login``      Build+encrypt a MajorLoginReq, POST it to the login
                         backend -> per-session AES key/IV + a JWT session token
                         (POST loginbp.ggwhitehawk.com/MajorLogin)
3. ``_get_login_data``   Exchange the JWT for the game server address
                         (POST client.us.freefiremobile.com/GetLoginData)
4. ``connect``           Open the raw TCP socket to that address and send the
                         session envelope built from the JWT + per-session key
5. ``keep_alive``        Read the socket and answer with a heartbeat whenever
                         the server goes quiet, so the session stays online.

Nothing here creates a room, joins a match, or touches gameplay - it only
gets (and keeps) a session online, which is the shared foundation any of
that would be built on top of.
"""

import asyncio
import random
import socket
import time
import uuid

import aiohttp
import jwt as pyjwt
from google.protobuf.timestamp_pb2 import Timestamp

from .crypto import encrypt_envelope, encrypt_packet, as_bytes, int_to_hex
from .packets import build_major_login_packet
from .protobufs import trick_pb2, GetLoginDataRes_pb2

GUEST_OAUTH_URL = "https://100067.connect.garena.com/oauth/guest/token/grant"
MAJOR_LOGIN_URL = "https://loginbp.ggwhitehawk.com/MajorLogin"
GET_LOGIN_DATA_URL = "https://client.us.freefiremobile.com/GetLoginData"
OAUTH_CLIENT_SECRET = "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
OAUTH_CLIENT_ID = "100067"

_HEARTBEAT = bytes.fromhex("0205")

# account_id hex length -> zero padding needed so header stays 16 hex chars.
_PADDING_BY_HEX_LEN = {7: "000000000", 8: "00000000", 9: "0000000", 10: "000000"}


def _random_user_agent(uid) -> str:
    rng = random.Random(str(uid))
    versao = rng.choice(["4.0.18P6", "4.0.19P7", "4.0.20P1", "4.1.0P3"])
    modelo = rng.choice(["G011A", "G012B", "SM-G973F", "Pixel 3", "Redmi Note 8"])
    android = rng.choice(["8.1", "9", "10", "11", "12"])
    idioma = rng.choice(["en", "en-US", "id", "es", "pt-BR"])
    pais = rng.choice(["USA", "IND", "IDN", "BRA", "MEX"])
    return f"GarenaMSDK/{versao}({modelo} ;Android {android};{idioma};{pais};)"


class LoginError(RuntimeError):
    pass


class FreeFireClient:
    def __init__(self, uid: str, password: str, client_ip: str = "20.171.73.202"):
        self.uid = str(uid)
        self.password = str(password)
        self.client_ip = client_ip

        self.session: aiohttp.ClientSession | None = None
        self.account_id: int | None = None
        self.nickname: str | None = None
        self.token: str | None = None  # session JWT
        self.chave = None  # per-session AES key (hex)
        self.iv = None  # per-session AES IV (hex)
        self._session_envelope: bytes | None = None

        self.main_ip = None
        self.main_porta = None
        self.online_ip = None
        self.online_porta = None

        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._running = False

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, *exc):
        await self.disconnect()
        if self.session:
            await self.session.close()

    # -- step 1: guest OAuth -------------------------------------------------

    async def _guest_oauth(self):
        headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": _random_user_agent(self.uid),
            "Content-Type": "application/x-www-form-urlencoded",
        }
        payload = {
            "uid": self.uid,
            "password": self.password,
            "response_type": "token",
            "client_type": "2",
            "client_secret": OAUTH_CLIENT_SECRET,
            "client_id": OAUTH_CLIENT_ID,
        }
        async with self.session.post(
            GUEST_OAUTH_URL, headers=headers, data=payload, ssl=False,
            timeout=aiohttp.ClientTimeout(total=12),
        ) as resp:
            if resp.status != 200:
                raise LoginError(f"guest oauth http {resp.status}")
            data = await resp.json()
            access_token, open_id = data.get("access_token"), data.get("open_id")
            if not access_token or not open_id:
                raise LoginError("guest oauth: resposta sem access_token/open_id")
            return access_token, open_id

    # -- step 2: MajorLogin ---------------------------------------------------

    async def _major_login(self, access_token: str, open_id: str):
        proto = build_major_login_packet(open_id, access_token, self.client_ip, self.uid)
        payload = bytes.fromhex(encrypt_envelope(proto.hex()))
        headers = {
            "User-Agent": _random_user_agent(self.uid),
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Unity-Version": "2022.3.47f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB56",
        }
        async with self.session.post(
            MAJOR_LOGIN_URL, data=payload, headers=headers, ssl=False,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status != 200:
                raise LoginError(f"major login http {resp.status}")
            body = await resp.read()

        res = trick_pb2.MajorLoginRes()
        res.ParseFromString(body)
        if res.blacklist and (res.blacklist.ban_reason or res.blacklist.ban_time):
            kind = "temporary" if res.blacklist.expire_duration > 0 else "permanent"
            raise LoginError(f"account banned ({kind}, code={res.blacklist.ban_reason})")
        if not res.token:
            raise LoginError("major login: no session token in response")

        ts = Timestamp()
        ts.FromNanoseconds(res.kts)
        timestamp = ts.seconds * 1_000_000_000 + ts.nanos
        chave = res.ak.hex() if isinstance(res.ak, bytes) else res.ak
        iv = res.aiv.hex() if isinstance(res.aiv, bytes) else res.aiv
        return timestamp, chave, iv, res.token

    # -- step 3: GetLoginData ---------------------------------------------------

    async def _get_login_data(self, token_jwt: str, payload: bytes):
        headers = {
            "Authorization": f"Bearer {token_jwt}",
            "X-Unity-Version": "2022.3.47f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB56",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)",
        }
        async with self.session.post(
            GET_LOGIN_DATA_URL, headers=headers, data=payload, ssl=False,
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status != 200:
                raise LoginError(f"get login data http {resp.status}")
            body = await resp.read()

        proto = GetLoginDataRes_pb2.GetLoginData()
        proto.ParseFromString(body)
        online_ip, online_porta = proto.Online_IP_Port.split(":")
        ip, porta = proto.AccountIP_Port.split(":")
        return ip, porta, online_ip, online_porta, proto.AccountName

    # -- orchestration ---------------------------------------------------------

    async def login(self) -> bool:
        """Runs the full guest-login handshake. Returns True and fills in
        ``account_id``/``nickname``/``online_ip``/``online_porta`` on success."""
        access_token, open_id = await self._guest_oauth()
        timestamp, chave, iv, token_jwt = await self._major_login(access_token, open_id)

        decoded = pyjwt.decode(token_jwt, options={"verify_signature": False})
        self.account_id = decoded.get("account_id")
        self.nickname = decoded.get("nickname") or f"UID-{self.uid}"
        self.token = token_jwt
        self.chave, self.iv = chave, iv

        proto2 = build_major_login_packet(open_id, access_token, self.client_ip, self.uid)
        payload2 = bytes.fromhex(encrypt_envelope(proto2.hex()))
        ip, porta, online_ip, online_porta, account_name = await self._get_login_data(token_jwt, payload2)
        if account_name:
            self.nickname = account_name
        self.main_ip, self.main_porta = ip, porta
        self.online_ip, self.online_porta = online_ip, online_porta

        self._session_envelope = self._build_session_envelope(self.account_id, timestamp, token_jwt, chave, iv)
        return True

    @staticmethod
    def _build_session_envelope(account_id: int, timestamp: int, token_jwt: str, chave, iv) -> bytes:
        """The handshake packet sent right after opening the TCP socket:
        a small header (account id + timestamp) followed by the AES-CBC
        encrypted session token, framed for the game server to parse.

        The account id is right-padded with zeros to a fixed 16 hex-char
        (8 byte) width - ``_PADDING_BY_HEX_LEN`` covers the hex lengths an
        account id can realistically have.
        """
        account_hex = hex(account_id)[2:]
        timestamp_hex = int_to_hex(timestamp)
        token_hex = token_jwt.encode().hex()
        encrypted_token = encrypt_packet(token_hex, as_bytes(chave), as_bytes(iv))
        length_hex = hex(len(encrypted_token) // 2)[2:]

        padding = _PADDING_BY_HEX_LEN.get(len(account_hex), "00000000")
        header = f"0115{padding}{account_hex}{timestamp_hex}00000{length_hex}"
        return bytes.fromhex(header + encrypted_token)

    # -- TCP session -------------------------------------------------------

    async def connect(self, timeout: float = 15) -> None:
        if not self._session_envelope:
            raise RuntimeError("call login() before connect()")
        self._reader, self._writer = await asyncio.wait_for(
            asyncio.open_connection(self.online_ip, int(self.online_porta)), timeout=timeout
        )
        sock = self._writer.get_extra_info("socket")
        if sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self._writer.write(self._session_envelope)
        await self._writer.drain()
        self._running = True

    async def _send_heartbeat(self) -> bool:
        if not self._writer or self._writer.is_closing():
            return False
        try:
            self._writer.write(_HEARTBEAT)
            await self._writer.drain()
            return True
        except Exception:
            return False

    async def keep_alive(self, seconds: float, on_data=None) -> None:
        """Reads the socket for ``seconds``, replying with a heartbeat any
        time the server goes quiet for a while, so the session doesn't drop.
        Pass ``on_data(bytes)`` to inspect incoming packets."""
        if not self._reader:
            raise RuntimeError("call connect() before keep_alive()")
        deadline = time.monotonic() + seconds
        while self._running and time.monotonic() < deadline:
            try:
                data = await asyncio.wait_for(self._reader.read(16384), timeout=60)
            except asyncio.TimeoutError:
                if not await self._send_heartbeat():
                    break
                continue
            if not data:
                break
            if on_data:
                on_data(data)

    async def disconnect(self) -> None:
        self._running = False
        if self._writer and not self._writer.is_closing():
            self._writer.close()
            try:
                await asyncio.wait_for(self._writer.wait_closed(), timeout=3)
            except Exception:
                pass
        self._reader = self._writer = None
