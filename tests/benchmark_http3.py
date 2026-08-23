import argparse
import asyncio
import ssl
import time

from aioquic.asyncio.client import connect
from aioquic.h3.connection import H3_ALPN
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.packet import QuicProtocolVersion

from test_quic_fingerprint import Http3Client


async def benchmark(host, port, requests, concurrency):
    configuration = QuicConfiguration(
        is_client=True,
        alpn_protocols=H3_ALPN,
        verify_mode=ssl.CERT_NONE,
    )
    configuration.supported_versions = [QuicProtocolVersion.VERSION_1]

    async with connect(
        host,
        port,
        configuration=configuration,
        create_protocol=Http3Client,
    ) as client:
        authority = f"{host}:{port}"

        async def batch(size):
            await asyncio.gather(
                *(client.get(authority) for _ in range(size))
            )

        await batch(min(requests, concurrency))
        started = time.perf_counter()
        remaining = requests
        while remaining:
            size = min(remaining, concurrency)
            await batch(size)
            remaining -= size
        elapsed = time.perf_counter() - started

    print(
        f"requests={requests} seconds={elapsed:.6f} "
        f"requests_per_second={requests / elapsed:.2f}"
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4434)
    parser.add_argument("--requests", type=int, default=5000)
    parser.add_argument("--concurrency", type=int, default=100)
    args = parser.parse_args()
    asyncio.run(
        benchmark(args.host, args.port, args.requests, args.concurrency)
    )


if __name__ == "__main__":
    main()
