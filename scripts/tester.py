# scripts/tester.py

import argparse
import asyncio
import json
import os
import shutil
import sys
import tempfile
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import aiohttp

from converter import convert_link, get_protocol, build_xray_config


PROTOCOL_DISPLAY = {
    "vless": "VLESS",
    "vmess": "VMess",
    "ss": "Shadowsocks",
    "trojan": "Trojan",
}


def fetch_subscriptions(sub_file: str) -> list[str]:
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
    seen = set()
    unique = []
    for c in configs:
        key = c.strip()
        if key not in seen:
            seen.add(key)
            unique.append(key)
    return unique


class PortPool:
    def __init__(self, base_port: int, size: int):
        self._queue = asyncio.Queue()
        for i in range(size):
            self._queue.put_nowait(base_port + i)

    async def acquire(self) -> int:
        return await self._queue.get()

    def release(self, port: int):
        self._queue.put_nowait(port)


async def test_single_config(
    sem: asyncio.Semaphore,
    port_pool: PortPool,
    link: str,
    xray_path: str,
    test_url: str,
    timeout: int,
) -> tuple[str, int]:
    async with sem:
        port = await port_pool.acquire()
        proc = None
        config_file = None

        try:
            outbound, _ = convert_link(link)
            xray_config = build_xray_config(outbound, port)

            config_file = tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False
            )
            json.dump(xray_config, config_file)
            config_file.close()

            proc = await asyncio.create_subprocess_exec(
                xray_path, "run", "-c", config_file.name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )

            await asyncio.sleep(1.5)

            if proc.returncode is not None:
                return link, -1

            proxy = f"socks5://127.0.0.1:{port}"
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

            port_pool.release(port)


async def test_all_configs(
    configs: list[str],
    xray_path: str,
    test_url: str,
    timeout: int,
    concurrent: int,
) -> list[tuple[str, int]]:
    sem = asyncio.Semaphore(concurrent)
    port_pool = PortPool(base_port=20000, size=concurrent)

    print(f"Testing {len(configs)} config(s) with {concurrent} concurrent workers...")

    tasks = []
    for link in configs:
        task = test_single_config(sem, port_pool, link, xray_path, test_url, timeout)
        tasks.append(task)

    results = []
    done_count = 0
    total = len(tasks)

    for coro in asyncio.as_completed(tasks):
        result = await coro
        results.append(result)
        done_count += 1

        if done_count % 100 == 0 or done_count == total:
            working = sum(1 for _, d in results if d > 0)
            print(f"  Progress: {done_count}/{total} tested, {working} working")

    return results


def categorize_and_save(
    results: list[tuple[str, int]],
    per_file: int,
) -> dict[str, list[dict]]:
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
        return {}

    for proto in by_protocol:
        by_protocol[proto].sort(key=lambda x: x[1])

    for proto in ("vless", "vmess", "ss", "trojan"):
        proto_dir = Path(proto)
        if proto_dir.exists():
            shutil.rmtree(proto_dir)

    file_info: dict[str, list[dict]] = {}
    total_working = 0

    for proto, items in by_protocol.items():
        proto_dir = Path(proto)
        proto_dir.mkdir(exist_ok=True)

        links = [link for link, _ in items]
        total_working += len(links)

        chunks = [links[i:i + per_file] for i in range(0, len(links), per_file)]
        file_info[proto] = []

        for idx, chunk in enumerate(chunks, 1):
            filename = f"{proto}-{idx}.txt"
            filepath = proto_dir / filename
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("\n".join(chunk) + "\n")

            file_info[proto].append({
                "index": idx,
                "count": len(chunk),
                "path": f"{proto}/{filename}",
            })

        print(f"  {proto}/: {len(links)} config(s) in {len(chunks)} file(s)")

    print(f"Total working: {total_working}")
    return file_info


def generate_readme(file_info: dict[str, list[dict]], repo_url: str):
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "# v2ray Config Collector",
        "",
        "Auto-tested proxy configurations, updated every 6 hours.",
        "",
        f"> Last update: {now}",
        "",
        "---",
        "",
        "## Statistics",
        "",
        "| Protocol | Working Configs | Files |",
        "|:--------:|:---------------:|:-----:|",
    ]

    total_configs = 0
    total_files = 0
    protocol_order = ["vless", "vmess", "ss", "trojan"]

    for proto in protocol_order:
        if proto in file_info:
            configs_count = sum(f["count"] for f in file_info[proto])
            files_count = len(file_info[proto])
            display_name = PROTOCOL_DISPLAY.get(proto, proto)
            lines.append(f"| {display_name} | {configs_count} | {files_count} |")
            total_configs += configs_count
            total_files += files_count

    lines.append(f"| **Total** | **{total_configs}** | **{total_files}** |")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Subscription Links")

    for proto in protocol_order:
        if proto not in file_info:
            continue

        display_name = PROTOCOL_DISPLAY.get(proto, proto)
        lines.append("")
        lines.append(f"### {display_name}")
        lines.append("")

        for f in file_info[proto]:
            idx = f["index"]
            count = f["count"]
            path = f["path"]
            url = f"{repo_url}/{path}"

            lines.append(f"> {display_name} {idx} ({count} configs)")
            lines.append("```")
            lines.append(url)
            lines.append("```")
            lines.append("")

    readme_content = "\n".join(lines)

    with open("README.md", "w", encoding="utf-8") as f:
        f.write(readme_content)

    print("README.md generated.")


def main():
    parser = argparse.ArgumentParser(description="Proxy Config Tester")
    parser.add_argument("--subscriptions", required=True, help="Path to subscription.txt")
    parser.add_argument("--xray", required=True, help="Path to xray binary")
    parser.add_argument("--test-url", default="http://gstatic.com/generate_204")
    parser.add_argument("--timeout", type=int, default=8)
    parser.add_argument("--concurrent", type=int, default=50)
    parser.add_argument("--per-file", type=int, default=500)
    parser.add_argument("--repo-url", required=True)
    args = parser.parse_args()

    configs = fetch_subscriptions(args.subscriptions)
    if not configs:
        print("Error: No configs fetched.")
        sys.exit(1)
    print(f"Total fetched: {len(configs)}")

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

    file_info = categorize_and_save(results, args.per_file)

    if file_info:
        generate_readme(file_info, args.repo_url)


if __name__ == "__main__":
    main()