"""Optional Nuclei worker. It accepts only fields from an approved ScanPlanRequest."""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from core.scans import ScanPlanRequest, nuclei_severity_filter

NUCLEI_FOFA_ENV_KEYS = ("FOFA_EMAIL", "FOFA_KEY", "FOFA_API_KEY")
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[mK]")
_TARGETS_RE = re.compile(r"Targets loaded for current scan:\s*(\d+)", re.IGNORECASE)
_TEMPLATES_RE = re.compile(r"Templates loaded for current scan:\s*(\d+)", re.IGNORECASE)
_LOG_RE = re.compile(r"\[(?:INF|WRN|ERR|FTL|DBG)\]")
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "unknown")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITY_ORDER)}
SEVERITY_LABELS = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
    "unknown": "未知",
}


def nuclei_subprocess_env(base: dict[str, str] | None = None) -> dict[str, str]:
    """Drop FOFA credentials so Nuclei's uncover provider does not abort the scan."""
    env = dict(os.environ if base is None else base)
    for key in NUCLEI_FOFA_ENV_KEYS:
        env.pop(key, None)
    return env


def resolve_nuclei_executable(explicit: str | None = None) -> str | None:
    """Prefer an explicit path, then env, then ./nuclei in cwd/project root, then PATH."""
    if explicit:
        return explicit
    env = os.environ.get("FOFAMAP_NUCLEI")
    if env:
        env_path = Path(env).expanduser()
        if env_path.is_file():
            return str(env_path)
    names = ("nuclei.exe", "nuclei") if os.name == "nt" else ("nuclei", "nuclei.exe")
    roots = [Path.cwd(), Path(__file__).resolve().parent.parent]
    seen: set[Path] = set()
    for root in roots:
        resolved = root.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        for name in names:
            candidate = resolved / name
            if candidate.is_file():
                return str(candidate)
    return shutil.which("nuclei") or shutil.which("nuclei.exe")


def strip_nuclei_ansi(value: str) -> str:
    return _ANSI_RE.sub("", value).strip()


def is_nuclei_progress_line(line: str) -> bool:
    return bool(_LOG_RE.search(line) or _TARGETS_RE.search(line) or _TEMPLATES_RE.search(line))


@dataclass(frozen=True)
class NucleiFinding:
    template_id: str = ""
    name: str = ""
    severity: str = "unknown"
    host: str = ""
    matched_at: str = ""
    matcher_name: str = ""
    extracted: tuple[str, ...] = ()
    ip: str = ""

    @property
    def target(self) -> str:
        return self.matched_at or self.host

    @property
    def site(self) -> str:
        """Normalize HTTP URLs and TLS host:port matches to one asset hostname."""
        value = self.target.strip()
        parsed = urlparse(value if "://" in value else f"//{value}")
        return (parsed.hostname or value).lower()

    @property
    def details(self) -> tuple[str, ...]:
        if self.matcher_name:
            return (self.matcher_name, *self.extracted)
        return self.extracted


@dataclass(frozen=True)
class NucleiGroupedHit:
    target: str
    ip: str
    template_id: str
    name: str
    severity: str
    details: tuple[str, ...]
    count: int


@dataclass
class NucleiProgressEvent:
    line: str
    findings: int = 0
    loaded_targets: int | None = None
    loaded_templates: int | None = None


@dataclass
class NucleiScanResult:
    artifact: Path
    findings: list[NucleiFinding] = field(default_factory=list)
    target_count: int = 0
    duration_seconds: float = 0.0
    summary_path: Path | None = None
    loaded_targets: int | None = None
    loaded_templates: int | None = None

    @property
    def host_count(self) -> int:
        return len({item.site for item in self.findings if item.site})

    @property
    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for item in self.findings:
            key = item.severity if item.severity in SEVERITY_RANK else "unknown"
            counts[key] = counts.get(key, 0) + 1
        return {name: counts[name] for name in SEVERITY_ORDER if name in counts}

    def grouped(self) -> list[NucleiGroupedHit]:
        buckets: dict[tuple[str, str, str], list[NucleiFinding]] = {}
        for item in self.findings:
            buckets.setdefault((item.target, item.template_id, item.severity), []).append(item)
        hits: list[NucleiGroupedHit] = []
        for (target, template_id, severity), items in buckets.items():
            labels: list[str] = []
            seen: set[str] = set()
            for item in items:
                for label in item.details:
                    if label and label not in seen:
                        seen.add(label)
                        labels.append(label)
            first = items[0]
            hits.append(
                NucleiGroupedHit(
                    target=target,
                    ip=first.ip,
                    template_id=template_id,
                    name=first.name or template_id,
                    severity=severity,
                    details=tuple(labels),
                    count=len(items),
                )
            )
        hits.sort(key=lambda hit: (SEVERITY_RANK.get(hit.severity, 99), hit.target))
        return hits

    def headline(self) -> str:
        scanned = self.loaded_targets or self.target_count
        if not self.findings:
            return f"已扫描 {scanned:,} 个目标，未发现命中。"
        counts = "、".join(
            f"{SEVERITY_LABELS.get(name, name)} {count:,}" for name, count in self.severity_counts.items()
        )
        return f"已扫描 {scanned:,} 个目标，命中 {len(self.findings):,} 条（{counts}），涉及 {self.host_count:,} 个站点。"

    def to_job_payload(self) -> dict[str, object]:
        return {
            "headline": self.headline(),
            "finding_count": len(self.findings),
            "host_count": self.host_count,
            "severity_counts": self.severity_counts,
            "summary_path": str(self.summary_path) if self.summary_path else None,
            "duration_seconds": round(self.duration_seconds, 2),
            "grouped": [
                {
                    "target": hit.target,
                    "severity": hit.severity,
                    "name": hit.name,
                    "details": list(hit.details),
                    "count": hit.count,
                }
                for hit in self.grouped()[:50]
            ],
        }


class _JsonlLineCounter:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.offset = 0
        self.count = 0
        self._partial = b""

    def refresh(self) -> int:
        if not self.path.exists():
            return self.count
        with self.path.open("rb") as handle:
            handle.seek(self.offset)
            chunk = handle.read()
            self.offset = handle.tell()
        buffer = self._partial + chunk
        lines = buffer.split(b"\n")
        self._partial = lines[-1]
        for line in lines[:-1]:
            if line.strip():
                self.count += 1
        return self.count


def parse_nuclei_jsonl(path: Path) -> list[NucleiFinding]:
    if not path.exists():
        return []
    findings: list[NucleiFinding] = []
    with path.open(encoding="utf-8", errors="replace") as handle:
        for raw in handle:
            line = raw.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict):
                continue
            info = item.get("info") if isinstance(item.get("info"), dict) else {}
            extracted = item.get("extracted-results") or []
            if isinstance(extracted, str):
                extracted = [extracted]
            findings.append(
                NucleiFinding(
                    template_id=str(item.get("template-id") or ""),
                    name=str(info.get("name") or item.get("template-id") or ""),
                    severity=str(info.get("severity") or item.get("severity") or "unknown").lower(),
                    host=str(item.get("host") or ""),
                    matched_at=str(item.get("matched-at") or item.get("url") or ""),
                    matcher_name=str(item.get("matcher-name") or ""),
                    extracted=tuple(str(value) for value in extracted if value),
                    ip=str(item.get("ip") or ""),
                )
            )
    return findings


def format_nuclei_summary_markdown(result: NucleiScanResult, *, preview: int = 80) -> str:
    lines = [
        "# Nuclei 扫描摘要",
        "",
        result.headline(),
        "",
        f"- 目标数量：{result.target_count:,}",
        f"- 命中条数：{len(result.findings):,}",
        f"- 涉及站点：{result.host_count:,}",
        f"- 耗时：{result.duration_seconds:.1f}s",
        f"- 原始结果：`{result.artifact}`",
        "",
    ]
    if result.severity_counts:
        lines.extend(["## 严重级别", "", "| 级别 | 数量 |", "|---|---:|"])
        for name, count in result.severity_counts.items():
            lines.append(f"| {SEVERITY_LABELS.get(name, name)} (`{name}`) | {count:,} |")
        lines.append("")
    grouped = result.grouped()
    if not grouped:
        lines.extend(["未发现可展示的命中项。", ""])
        return "\n".join(lines)
    lines.extend(
        [
            "## 按站点汇总",
            "",
            "| 严重级别 | 站点 | 检测项 | 命中详情 |",
            "|---|---|---|---|",
        ]
    )
    for hit in grouped[:preview]:
        details = ", ".join(hit.details) if hit.details else f"{hit.count} 条命中"
        lines.append(
            f"| {SEVERITY_LABELS.get(hit.severity, hit.severity)} | {hit.target} | "
            f"{hit.name or hit.template_id} | {details} |"
        )
    if len(grouped) > preview:
        lines.extend(["", f"> 仅展示前 {preview:,} 个站点；完整命中见 `{result.artifact}`。"])
    lines.append("")
    return "\n".join(lines)


def write_nuclei_summary(result: NucleiScanResult) -> Path:
    path = result.artifact.with_name("nuclei_summary.md")
    path.write_text(format_nuclei_summary_markdown(result), encoding="utf-8")
    result.summary_path = path
    return path


def load_nuclei_result(path: Path, *, target_count: int = 0) -> NucleiScanResult:
    artifact = Path(path)
    return NucleiScanResult(artifact=artifact, findings=parse_nuclei_jsonl(artifact), target_count=target_count)


class NucleiScanner:
    def __init__(self, executable: str | None = None) -> None:
        self.executable = resolve_nuclei_executable(executable)

    @staticmethod
    def _target(value: str) -> str:
        parsed = urlparse(value if "://" in value else f"https://{value}")
        return parsed.geturl()

    async def run_plan(
        self,
        plan: ScanPlanRequest,
        output_dir: Path,
        *,
        on_progress: Callable[[NucleiProgressEvent], None] | None = None,
    ) -> NucleiScanResult:
        if not self.executable:
            raise RuntimeError("未安装 Nuclei；请在工作节点安装可选扫描组件")
        output_dir.mkdir(parents=True, exist_ok=True)
        targets_path = output_dir / "targets.txt"
        result_path = output_dir / "nuclei.jsonl"
        targets_path.write_text("\n".join(self._target(value) for value in plan.targets) + "\n", encoding="utf-8")
        command = [
            self.executable,
            "-l",
            str(targets_path),
            "-jsonl",
            "-o",
            str(result_path),
            "-nc",
        ]
        severity_filter = nuclei_severity_filter(
            plan.template_ids,
            plan.severities,
            all_severities=plan.all_severities,
        )
        if severity_filter:
            command.extend(["-severity", ",".join(severity_filter)])
        for template in plan.templates:
            command.extend(["-t", template])
        for template_id in plan.template_ids:
            command.extend(["-id", template_id])
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
            env=nuclei_subprocess_env(),
        )
        stderr_lines: list[str] = []
        loaded_targets: int | None = None
        loaded_templates: int | None = None
        counter = _JsonlLineCounter(result_path)
        started = time.monotonic()

        def handle_line(text: str) -> None:
            nonlocal loaded_targets, loaded_templates
            cleaned = strip_nuclei_ansi(text)
            if not cleaned:
                return
            stderr_lines.append(cleaned)
            match = _TARGETS_RE.search(cleaned)
            if match:
                loaded_targets = int(match.group(1))
            match = _TEMPLATES_RE.search(cleaned)
            if match:
                loaded_templates = int(match.group(1))
            if on_progress and is_nuclei_progress_line(cleaned):
                on_progress(
                    NucleiProgressEvent(
                        line=cleaned,
                        findings=counter.refresh(),
                        loaded_targets=loaded_targets,
                        loaded_templates=loaded_templates,
                    )
                )

        stream = getattr(process, "stderr", None)
        if stream is not None:
            while True:
                raw = await stream.readline()
                if not raw:
                    break
                handle_line(raw.decode(errors="replace"))
            returncode = await process.wait()
        else:
            _, stderr = await process.communicate()
            returncode = process.returncode
            for line in stderr.decode(errors="replace").splitlines():
                handle_line(line)
        duration = time.monotonic() - started
        if returncode != 0:
            raise RuntimeError(f"Nuclei 退出码 {returncode}：{''.join(stderr_lines)[-1000:]}")
        result = NucleiScanResult(
            artifact=result_path,
            findings=parse_nuclei_jsonl(result_path),
            target_count=len(plan.targets),
            duration_seconds=duration,
            loaded_targets=loaded_targets,
            loaded_templates=loaded_templates,
        )
        write_nuclei_summary(result)
        return result
