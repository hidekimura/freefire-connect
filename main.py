#!/usr/bin/env python3
"""CLI: log a guest account in and keep it online for a while.

No .env, no config file - credentials are passed as arguments (or you'll
be prompted for the password if you leave it out).

    python main.py 123456789 mypassword
    python main.py 123456789 mypassword --seconds 120
"""

import argparse
import asyncio
import getpass
import sys

from ff_connect import FreeFireClient
from ff_connect.client import LoginError


async def run(uid: str, password: str, seconds: float) -> int:
    async with FreeFireClient(uid, password) as client:
        print(f"[login] authenticating uid={uid} ...")
        try:
            await client.login()
        except LoginError as exc:
            print(f"[login] failed: {exc}")
            return 1

        print(f"[login] ok - account_id={client.account_id} nickname={client.nickname!r}")
        print(f"[connect] opening TCP session to {client.online_ip}:{client.online_porta} ...")
        await client.connect()
        print(f"[connect] online. keeping session alive for {seconds:.0f}s (Ctrl+C to stop early)")

        try:
            await client.keep_alive(seconds)
        except KeyboardInterrupt:
            pass
        print("[disconnect] closing session")
        return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Log a Free Fire guest account in and keep it online.")
    parser.add_argument("uid", help="guest account uid")
    parser.add_argument("password", nargs="?", help="guest account password (prompted if omitted)")
    parser.add_argument("--seconds", type=float, default=60, help="how long to stay connected (default: 60)")
    args = parser.parse_args()

    password = args.password or getpass.getpass("password: ")
    exit_code = asyncio.run(run(args.uid, password, args.seconds))
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
