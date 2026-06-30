# scripts/tester.py
"""
Proxy Config Tester
Fetches subscriptions, deduplicates, tests with Xray, categorizes results.
"""

import argparse
import asyncio
import json
import os
import shutil
import signal
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

import aiohttp

from converter import convert_link, get_protocol, build_xray_config


def fetch_subscriptions(sub_file: str) -> list[str]:
    """Fetch all configs from subscription URLs."""
    all_configs = []

    with open(sub_file, "r", encoding="utf-8") as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

    print(f"Fetching {len(urls)} subscription(s)...")

    for url in urls:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "v2rayN/6.0"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                content = resp.read().decode("utf-8").strip()

            lines = content.splitlines()
            count = 0
            for line in lines:
                line = line.strip()
                if line and "://" in line:
                    all_configs.append(line)
                    count += 1

            print(f"  {url[:60]}... -> {count} config(s)")

        except Exception as e:
            print(f"  {url[:60]}... -> FAILED: {e}")

    return all_configs


def deduplicate(configs: list[str]) -> list[str]:
    """Remove duplicate configs preserving order."""
    seen = set()
    unique = []
    for c in configs:
        key = c.strip()
        if key not in seen:
            seen.add(key)
            unique.append(key)
    return unique


async def test_single_config(
    sem: asyncio.Semaphore,
    link: str,
    xray_path: str,
    test_url: str,
    timeout: int,
    base_port: int,
    slot: int,
) -> tuple[str, int]:
    """
    Test a single config. Returns (link, delay_ms).
    delay_ms = -1 means failed.
    """
    async with sem:
        socks_port = base_port + slot
        proc = None
        config_file = None

        try:
            outbound, _ = convert_link(link)
            xray_config = build_xray_config(outbound, socks_port)

            config_file = tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False
            )
            json.dump(xray_config, config_file)
            config_file.close()

            # Start xray
            proc = await asyncio.create_subprocess_exec(
                xray_path, "run", "-c", config_file.name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )

            await asyncio.sleep(1)

            if proc.returncode is not None:
                return link, -1

            proxy = f"socks5://127.0.0.1:{socks_port}"
            connector = aiohttp.TCPConnector(ssl=False)

            start_time = time.monotonic()

            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(
                    test_url,
                    proxy=proxy,
                    timeout=aiohttp.ClientTimeout(total=timeout),
                ) as resp:
                    if resp.status in (200, 204):
                        delay_ms = int((time.monotonic() - start_time) * 1000)
                        return link, delay_ms
                    else:
                        return link, -1

        except Exception:
            return link, -1

        finally:
            if proc and proc.returncode is None:
                try:
                    proc.terminate()
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=3)
                    except asyncio.TimeoutError:
                        proc.kill()
                        await proc.wait()
                except ProcessLookupError:
                    pass

            if config_file:
                try:
                    os.unlink(config_file.name)
                except OSError:
                    pass


async def test_all_configs(
    configs: list[str],
    xray_path: str,
    test_url: str,
    timeout: int,
    concurrent: int,
) -> list[tuple[str, int]]:
    """Test all configs concurrently. Returns list of (link, delay_ms)."""
    sem = asyncio.Semaphore(concurrent)
    base_port = 20000

    print(f"Testing {len(configs)} config(s) with {concurrent} concurrent workers...")

    tasks = []
    for i, link in enumerate(configs):
        slot = i % concurrent
        task = test_single_config(sem, link, xray_path, test_url, timeout, base_port, slot)
        tasks.append(task)

    results = []
    done_count = 0
    total = len(tasks)

    for coro in asyncio.as_completed(tasks):
        result = await coro
        results.append(result)
        done_count += 1

        if done_count % 50 == 0 or done_count == total:
            working = sum(1 for _, d in results if d > 0)
            print(f"  Progress: {done_count}/{total} tested, {working} working")

    return results


def categorize_and_save(results: list[tuple[str, int]], per_file: int):
    """Categorize working configs by protocol and save to files."""
    by_protocol: dict[str, list[tuple[str, int]]] = {}

    for link, delay in results:
        if delay < 0:
            continue
        proto = get_protocol(link)
        if proto == "unknown":
            continue
        if proto not in by_protocol:
            by_protocol[proto] = []
        by_protocol[proto].append((link, delay))

    if not by_protocol:
        print("No working configs found.")
        return

    for proto in by_protocol:
        by_protocol[proto].sort(key=lambda x: x[1])

    for proto in ("vless", "vmess", "ss", "trojan"):
        proto_dir = Path(proto)
        if proto_dir.exists():
            shutil.rmtree(proto_dir)

    total_working = 0
    for proto, items in by_protocol.items():
        proto_dir = Path(proto)
        proto_dir.mkdir(exist_ok=True)

        links = [link for link, _ in items]
        total_working += len(links)

        chunks = [links[i:i + per_file] for i in range(0, len(links), per_file)]

        for idx, chunk in enumerate(chunks, 1):
            filename = proto_dir / f"{proto}-{idx}.txt"
            with open(filename, "w", encoding="utf-8") as f:
                f.write("\n".join(chunk) + "\n")

        print(f"  {proto}/: {len(links)} config(s) in {len(chunks)} file(s)")

    print(f"Total working: {total_working}")


def main():
    parser = argparse.ArgumentParser(description="Proxy Config Tester")
    parser.add_argument("--subscriptions", required=True, help="Path to subscription.txt")
    parser.add_argument("--xray", required=True, help="Path to xray binary")
    parser.add_argument("--test-url", default="http://gstatic.com/generate_204")
    parser.add_argument("--timeout", type=int, default=8)
    parser.add_argument("--concurrent", type=int, default=50)
    parser.add_argument("--per-file", type=int, default=500)
    args = parser.parse_args()

    configs = fetch_subscriptions(args.subscriptions)
    if not configs:
        print("Error: No configs fetched.")
        sys.exit(1)
    print(f"Total fetched: {len(configs)}")

    # Deduplicate
    configs = deduplicate(configs)
    print(f"After dedup: {len(configs)}")

    supported = []
    skipped = 0
    for c in configs:
        proto = get_protocol(c)
        if proto != "unknown":
            supported.append(c)
        else:
            skipped += 1
    if skipped:
        print(f"Skipped {skipped} unsupported link(s)")
    configs = supported

    if not configs:
        print("Error: No supported configs to test.")
        sys.exit(1)

    if not os.path.isfile(args.xray):
        print(f"Error: Xray binary not found: {args.xray}")
        sys.exit(1)

    results = asyncio.run(
        test_all_configs(configs, args.xray, args.test_url, args.timeout, args.concurrent)
    )

    working = sum(1 for _, d in results if d > 0)
    failed = sum(1 for _, d in results if d < 0)
    print(f"Results: {working} working, {failed} failed")

    categorize_and_save(results, args.per_file)


if __name__ == "__main__":
    main()