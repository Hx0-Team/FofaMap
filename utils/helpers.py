"""Optional HTTP helpers with DNS rebinding-aware private-network blocking."""

from __future__ import annotations

import asyncio
import codecs
import ipaddress
import socket
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx
import mmh3

from config import settings
from utils.logger import logger

# Clash / Surge / Quantumult X fake-ip (RFC 2544 benchmarking range). Python marks
# these as non-global, but the actual HTTP fetch still egresses via the local proxy.
_FAKE_IP_NETWORKS = (ipaddress.ip_network("198.18.0.0/15"),)
_METADATA_NETWORKS = (
    ipaddress.ip_network("169.254.169.254/32"),
    ipaddress.ip_network("100.100.100.200/32"),
    ipaddress.ip_network("fd00:ec2::254/128"),
)


def is_cloud_metadata_address(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return any(ip in network for network in _METADATA_NETWORKS)


def is_blocked_ssrf_address(address: str, *, allow_private: bool = False) -> bool:
    if is_cloud_metadata_address(address):
        return True
    if allow_private:
        return False
    ip = ipaddress.ip_address(address)
    if any(ip in network for network in _FAKE_IP_NETWORKS):
        return False
    return not ip.is_global


def assert_public_http_url(url: str, *, allow_private: bool | None = None) -> str:
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("仅支持不带账号密码的 HTTP(S) URL")
    if allow_private is None:
        allow_private = settings.system.allow_private_network
    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(
                parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM
            )
        }
    except socket.gaierror as exc:
        raise ValueError(f"无法解析 {parsed.hostname}") from exc
    blocked = [address for address in addresses if is_blocked_ssrf_address(address, allow_private=allow_private)]
    if blocked:
        if any(is_cloud_metadata_address(address) for address in blocked):
            raise ValueError("已拦截云元数据目标")
        raise ValueError("已拦截私网、回环、链路本地、保留地址目标")
    return url


_REDIRECT_STATUS = {301, 302, 303, 307, 308}
_MAX_ICON_REDIRECTS = 5


async def _get_with_safe_redirects(client: httpx.AsyncClient, url: str) -> httpx.Response:
    current = assert_public_http_url(url)
    for _ in range(_MAX_ICON_REDIRECTS + 1):
        response = await client.get(current)
        if response.status_code in _REDIRECT_STATUS:
            location = (response.headers.get("location") or "").strip()
            if not location:
                response.raise_for_status()
            current = assert_public_http_url(urljoin(current, location))
            continue
        response.raise_for_status()
        return response
    raise ValueError("图标地址跳转次数过多")


class IconHashCalculator:
    MAX_ICON_BYTES = 4 * 1024 * 1024

    @staticmethod
    def from_bytes(content: bytes) -> str:
        if not content:
            raise ValueError("图标内容为空")
        if len(content) > IconHashCalculator.MAX_ICON_BYTES:
            raise ValueError("图标文件超过 4 MiB 安全上限")
        icon_hash = mmh3.hash(codecs.lookup("base64").encode(content)[0])
        return f'icon_hash="{icon_hash}"'

    @staticmethod
    def from_file(path_value: str) -> str:
        path = Path(path_value).expanduser()
        if not path.is_file():
            raise ValueError(f"图标文件不存在：{path}")
        if path.stat().st_size > IconHashCalculator.MAX_ICON_BYTES:
            raise ValueError("图标文件超过 4 MiB 安全上限")
        return IconHashCalculator.from_bytes(path.read_bytes())

    @staticmethod
    async def get_hash(url: str) -> str | None:
        safe_url = assert_public_http_url(url)
        parsed = urlparse(safe_url)
        explicit_icon = Path(parsed.path).suffix.lower() in {".ico", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp"}
        favicon_url = safe_url if explicit_icon else f"{parsed.scheme}://{parsed.netloc}/favicon.ico"
        async with httpx.AsyncClient(verify=True, timeout=10, follow_redirects=False) as client:
            try:
                response = await _get_with_safe_redirects(client, favicon_url)
                return IconHashCalculator.from_bytes(response.content)
            except (httpx.HTTPError, ValueError) as exc:
                logger.warning(f"图标计算失败: {exc}")
                return None


def insert_alive_status_field(fields: list[str]) -> list[str]:
    """Keep the alive column near host/port so it stays visible in compact tables."""
    if "alive_status" in fields:
        return fields
    for anchor in ("protocol", "port", "ip", "host"):
        if anchor in fields:
            index = fields.index(anchor) + 1
            return [*fields[:index], "alive_status", *fields[index:]]
    return ["alive_status", *fields]


class FastChecker:
    @staticmethod
    async def check_alive(targets: list[str], timeout: int = 5) -> dict[str, int | str]:
        results: dict[str, int | str] = {}
        semaphore = asyncio.Semaphore(settings.system.concurrency)
        safe_targets: list[str] = []
        for target in dict.fromkeys(targets):
            try:
                safe_targets.append(assert_public_http_url(target))
            except ValueError as exc:
                results[target] = f"Blocked: {exc}"
        async with httpx.AsyncClient(verify=True, timeout=timeout, follow_redirects=False) as client:
            responses = await asyncio.gather(
                *(FastChecker._fetch(client, url, semaphore) for url in safe_targets),
                return_exceptions=True,
            )
        for item, url in zip(responses, safe_targets, strict=True):
            if isinstance(item, Exception):
                results[url] = "Error"
            else:
                results[item[0]] = item[1]
        return results

    @staticmethod
    async def _fetch(client: httpx.AsyncClient, url: str, semaphore: asyncio.Semaphore) -> tuple[str, int | str]:
        async with semaphore:
            try:
                # DNS was validated immediately before the request; redirects remain disabled.
                response = await client.get(url)
                return url, response.status_code
            except httpx.TimeoutException:
                return url, "Timeout"
            except httpx.ConnectError:
                return url, "ConnErr"
            except (httpx.HTTPError, OSError):
                return url, "Error"
