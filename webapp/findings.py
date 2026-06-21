from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit, urlunsplit


class ReviewStatus(StrEnum):
    PENDING_RETEST = "PENDING_RETEST"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    FIXED = "FIXED"
    ACCEPTED_RISK = "ACCEPTED_RISK"


def normalize_endpoint(url: str) -> str:
    parsed = urlsplit(url.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"非法发现 URL：{url}")
    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower().rstrip(".").encode("idna").decode("ascii")
    port = parsed.port
    default_port = 443 if scheme == "https" else 80
    netloc = f"[{host}]" if ":" in host else host
    if port and port != default_port:
        netloc = f"{netloc}:{port}"
    path = "/" + parsed.path.lstrip("/")
    if path != "/":
        path = path.rstrip("/")
    return urlunsplit((scheme, netloc, path, parsed.query, ""))


def finding_fingerprint(endpoint_url: str, category: str) -> str:
    source = f"{normalize_endpoint(endpoint_url)}\n{category.strip().upper()}"
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class FindingReviewUpdate:
    status: ReviewStatus
    assignee: str
    notes: str
    tags: tuple[str, ...]
    evidence_summary: str
    mark_retested: bool

    @classmethod
    def create(
        cls,
        *,
        status: str,
        assignee: str,
        notes: str,
        tags: list[str] | tuple[str, ...],
        evidence_summary: str,
        mark_retested: bool,
    ) -> "FindingReviewUpdate":
        review_status = ReviewStatus(status)
        clean_assignee = assignee.strip()
        clean_notes = notes.strip()
        clean_evidence = evidence_summary.strip()
        clean_tags = tuple(dict.fromkeys(item.strip() for item in tags if item.strip()))
        if len(clean_assignee) > 80:
            raise ValueError("负责人不能超过 80 个字符")
        if len(clean_notes) > 5000:
            raise ValueError("备注不能超过 5000 个字符")
        if len(clean_evidence) > 5000:
            raise ValueError("证据摘要不能超过 5000 个字符")
        if len(clean_tags) > 20 or any(len(item) > 50 for item in clean_tags):
            raise ValueError("标签最多 20 个且每个不超过 50 个字符")
        if review_status == ReviewStatus.ACCEPTED_RISK and not clean_notes:
            raise ValueError("接受风险时必须填写备注")
        return cls(
            status=review_status,
            assignee=clean_assignee,
            notes=clean_notes,
            tags=clean_tags,
            evidence_summary=clean_evidence,
            mark_retested=bool(mark_retested),
        )
