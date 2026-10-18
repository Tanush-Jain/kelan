
from __future__ import annotations

import asyncio
from typing import AsyncGenerator


DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5432, 5900, 8000, 8080, 8443, 9000, 9090
]

async def scan_port(host: str, port: int, timeout: float = 0.5) -> dict:

    try:
        conn = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
    except asyncio.TimeoutError:
        return {"port": port, "status": "FILTERED", "banner": ""}
    except Exception:
        return {"port": port, "status": "CLOSED", "banner": ""}


    banner = ""
    try:

        if port in (80, 8080, 8000, 9000, 9090):
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()
        

        data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
        banner = data.decode("utf-8", "ignore").strip()
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    return {"port": port, "status": "OPEN", "banner": banner}


async def scan_host(host: str, ports: list[int], timeout: float = 0.5, concurrency: int = 100) -> AsyncGenerator[dict, None]:

    sem = asyncio.Semaphore(concurrency)
    
    async def worker(port: int):
        async with sem:
            return await scan_port(host, port, timeout=timeout)
            
    tasks = [worker(p) for p in ports]
    for fut in asyncio.as_completed(tasks):
        result = await fut
        yield result
