from __future__ import annotations

import asyncio
import ipaddress
import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import SplitResult, urlsplit, urlunsplit


FIXED_DENY_ADDRESSES = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("100.100.100.200"),
        ipaddress.ip_address("fd00:ec2::254"),
    }
)
PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)


class ScopeViolation(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _normalized_host(value: str) -> str:
    host = value.strip().lower().rstrip(".")
    if not host:
        raise ScopeViolation("SCOPE_HOST_INVALID", "主机名为空")
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ScopeViolation("SCOPE_HOST_INVALID", f"非法主机名：{value}") from exc


def _domain_matches(host: str, domain: str) -> bool:
    return host == domain or host.endswith(f".{domain}")


def _parse_networks(values: Any, field: str) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for raw in values or []:
        try:
            network = ipaddress.ip_network(str(raw).strip(), strict=False)
        except ValueError as exc:
            raise ScopeViolation("SCOPE_CIDR_INVALID", f"{field} 包含非法 CIDR：{raw}") from exc
        if network not in networks:
            networks.append(network)
    return tuple(networks)


def _parse_ports(values: Any, field: str) -> frozenset[int]:
    ports: set[int] = set()
    for raw in values or []:
        try:
            port = int(raw)
        except (TypeError, ValueError) as exc:
            raise ScopeViolation("SCOPE_PORT_INVALID", f"{field} 包含非法端口：{raw}") from exc
        if not 1 <= port <= 65535:
            raise ScopeViolation("SCOPE_PORT_INVALID", f"端口超出范围：{port}")
        ports.add(port)
    return frozenset(ports)


def _parse_expiry(value: Any) -> datetime | None:
    if value in {None, ""}:
        return None
    if isinstance(value, datetime):
        expiry = value
    else:
        try:
            expiry = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ScopeViolation("SCOPE_EXPIRY_INVALID", "授权截止时间格式无效") from exc
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return expiry.astimezone(timezone.utc)


@dataclass(frozen=True, slots=True)
class ScopePolicy:
    allowed_domains: tuple[str, ...]
    exact_hosts: tuple[str, ...]
    allowed_cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    allowed_ports: frozenset[int]
    allowed_schemes: frozenset[str]
    excluded_domains: tuple[str, ...]
    excluded_cidrs: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]
    excluded_ports: frozenset[int]
    valid_until: datetime | None

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ScopePolicy":
        allowed_domains = tuple(dict.fromkeys(_normalized_host(item) for item in payload.get("allowed_domains", [])))
        exact_hosts = tuple(dict.fromkeys(_normalized_host(item) for item in payload.get("exact_hosts", [])))
        excluded_domains = tuple(
            dict.fromkeys(_normalized_host(item) for item in payload.get("excluded_domains", []))
        )
        schemes = frozenset(str(item).strip().lower() for item in payload.get("allowed_schemes", []))
        if not schemes or not schemes <= {"http", "https"}:
            raise ScopeViolation("SCOPE_SCHEME_INVALID", "允许协议只能是非空的 http/https 集合")
        ports = _parse_ports(payload.get("allowed_ports", []), "允许端口")
        if not ports:
            raise ScopeViolation("SCOPE_PORT_INVALID", "允许端口不能为空")
        expiry = _parse_expiry(payload.get("valid_until"))
        policy = cls(
            allowed_domains=allowed_domains,
            exact_hosts=exact_hosts,
            allowed_cidrs=_parse_networks(payload.get("allowed_cidrs", []), "允许 CIDR"),
            allowed_ports=ports,
            allowed_schemes=schemes,
            excluded_domains=excluded_domains,
            excluded_cidrs=_parse_networks(payload.get("excluded_cidrs", []), "排除 CIDR"),
            excluded_ports=_parse_ports(payload.get("excluded_ports", []), "排除端口"),
            valid_until=expiry,
        )
        policy.check_authorization()
        return policy

    def check_authorization(self, now: datetime | None = None) -> None:
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            current = current.replace(tzinfo=timezone.utc)
        if self.valid_until is not None and current.astimezone(timezone.utc) >= self.valid_until:
            raise ScopeViolation("SCOPE_EXPIRED", "目标授权已过期")

    def validate_url_shape(self, url: str) -> SplitResult:
        self.check_authorization()
        parsed = urlsplit(url.strip())
        scheme = parsed.scheme.lower()
        if scheme not in self.allowed_schemes:
            raise ScopeViolation("SCOPE_SCHEME_DENIED", f"协议不在授权范围：{scheme or '-'}")
        if parsed.username is not None or parsed.password is not None:
            raise ScopeViolation("SCOPE_USERINFO_DENIED", "URL 不允许包含用户信息")
        if not parsed.hostname:
            raise ScopeViolation("SCOPE_HOST_INVALID", "URL 缺少主机名")
        host = _normalized_host(parsed.hostname)
        if host == "localhost" or host.endswith(".localhost"):
            raise ScopeViolation("SCOPE_HOST_DENIED", "禁止访问 localhost")
        if any(_domain_matches(host, item) for item in self.excluded_domains):
            raise ScopeViolation("SCOPE_DOMAIN_EXCLUDED", f"主机命中排除域名：{host}")
        host_allowed = host in self.exact_hosts or any(
            _domain_matches(host, item) for item in self.allowed_domains
        )
        if not host_allowed:
            raise ScopeViolation("SCOPE_DOMAIN_DENIED", f"主机不在授权范围：{host}")
        try:
            port = parsed.port or (443 if scheme == "https" else 80)
        except ValueError as exc:
            raise ScopeViolation("SCOPE_PORT_INVALID", "URL 端口格式无效") from exc
        if port in self.excluded_ports:
            raise ScopeViolation("SCOPE_PORT_EXCLUDED", f"端口命中排除规则：{port}")
        if port not in self.allowed_ports:
            raise ScopeViolation("SCOPE_PORT_DENIED", f"端口不在授权范围：{port}")
        netloc = f"[{host}]" if ":" in host else host
        if port != (443 if scheme == "https" else 80):
            netloc = f"{netloc}:{port}"
        return SplitResult(scheme, netloc, parsed.path or "/", parsed.query, "")

    def validate_ip(self, address: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise ScopeViolation("SCOPE_IP_INVALID", f"非法 IP 地址：{address}") from exc
        if (
            ip in FIXED_DENY_ADDRESSES
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_unspecified
            or ip.is_multicast
            or ip.is_reserved
        ):
            raise ScopeViolation("SCOPE_IP_DENIED", f"禁止访问特殊地址：{ip}")
        if any(ip in network for network in self.excluded_cidrs if network.version == ip.version):
            raise ScopeViolation("SCOPE_IP_EXCLUDED", f"地址命中排除 CIDR：{ip}")
        private = any(ip in network for network in PRIVATE_NETWORKS if network.version == ip.version)
        explicitly_allowed = any(
            ip in network for network in self.allowed_cidrs if network.version == ip.version
        )
        if private and not explicitly_allowed:
            raise ScopeViolation("SCOPE_PRIVATE_IP_DENIED", f"私网地址未获得 CIDR 授权：{ip}")
        return ip

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed_domains": list(self.allowed_domains),
            "exact_hosts": list(self.exact_hosts),
            "allowed_cidrs": [str(item) for item in self.allowed_cidrs],
            "allowed_ports": sorted(self.allowed_ports),
            "allowed_schemes": sorted(self.allowed_schemes),
            "excluded_domains": list(self.excluded_domains),
            "excluded_cidrs": [str(item) for item in self.excluded_cidrs],
            "excluded_ports": sorted(self.excluded_ports),
            "valid_until": self.valid_until.isoformat() if self.valid_until else None,
        }


@dataclass(frozen=True, slots=True)
class ValidatedTarget:
    url: str
    host: str
    port: int
    addresses: tuple[str, ...]


class ScopeGuard:
    def __init__(self, policy: ScopePolicy) -> None:
        self.policy = policy

    async def validate_target(self, url: str) -> ValidatedTarget:
        parsed = self.policy.validate_url_shape(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        if literal is not None:
            addresses = (str(self.policy.validate_ip(str(literal))),)
        else:
            try:
                rows = await asyncio.to_thread(
                    socket.getaddrinfo,
                    host,
                    port,
                    socket.AF_UNSPEC,
                    socket.SOCK_STREAM,
                )
            except socket.gaierror as exc:
                raise ScopeViolation("SCOPE_DNS_FAILED", f"DNS 解析失败：{host}") from exc
            resolved = tuple(dict.fromkeys(str(row[4][0]) for row in rows))
            if not resolved:
                raise ScopeViolation("SCOPE_DNS_FAILED", f"DNS 未返回地址：{host}")
            addresses = tuple(str(self.policy.validate_ip(item)) for item in resolved)
        normalized_url = urlunsplit(parsed)
        return ValidatedTarget(normalized_url, host, port, addresses)
