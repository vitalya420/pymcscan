import asyncio
from mcstatus import JavaServer
import sys

async def ping_server(ip: str) -> None:
    try:
        status = await (await JavaServer.async_lookup(ip, timeout=10)).async_status()
    except Exception:
        return

    print(f"{ip}")  # handle somehow responses here


async def ping_ips(ips: list[str]) -> None:
    to_process: list[str] = []

    for ip in ips:
        if len(to_process) <= 200:  # 10 means here how many servers will be pinged at once
            to_process.append(ip)
            continue

        await asyncio.wait({asyncio.create_task(ping_server(ip_to_ping)) for ip_to_ping in to_process})
        to_process = []


def main() -> None:
    with open(sys.argv[1], 'r') as ips_file:
        ips = ips_file.read().split('\n')[:-1]
        asyncio.run(ping_ips(ips))


if __name__ == "__main__":
    main()
