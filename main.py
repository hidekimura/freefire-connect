#!/usr/bin/env python3
"""CLI: loga uma conta guest e mantém ela online por um tempo.

Sem .env, sem arquivo de config - as credenciais são passadas por
argumento (ou a senha é pedida no prompt se você deixar de fora).

    python main.py 123456789 minhasenha
    python main.py 123456789 minhasenha --seconds 120
"""

import argparse
import asyncio
import getpass
import sys

from ff_connect import FreeFireClient
from ff_connect.client import LoginError


async def run(uid: str, password: str, seconds: float) -> int:
    async with FreeFireClient(uid, password) as client:
        print(f"[login] autenticando uid={uid} ...")
        try:
            await client.login()
        except LoginError as exc:
            print(f"[login] falhou: {exc}")
            return 1

        print(f"[login] ok - account_id={client.account_id} nickname={client.nickname!r}")
        print(f"[connect] abrindo sessão TCP com {client.online_ip}:{client.online_porta} ...")
        await client.connect()
        print(f"[connect] online. mantendo sessão por {seconds:.0f}s (Ctrl+C pra parar antes)")

        try:
            await client.keep_alive(seconds)
        except KeyboardInterrupt:
            pass
        print("[disconnect] fechando sessão")
        return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Loga uma conta guest do Free Fire e mantém ela online.")
    parser.add_argument("uid", help="uid da conta guest")
    parser.add_argument("password", nargs="?", help="senha da conta guest (pedida no prompt se omitida)")
    parser.add_argument("--seconds", type=float, default=60, help="quanto tempo ficar conectado (padrão: 60)")
    args = parser.parse_args()

    password = args.password or getpass.getpass("senha: ")
    exit_code = asyncio.run(run(args.uid, password, args.seconds))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
