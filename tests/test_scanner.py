from pathlib import Path

import pytest

from core.scanner import NucleiFinding, NucleiScanner, parse_nuclei_jsonl
from core.scans import ScanPlanRequest


class FakeProcess:
    returncode = 0

    async def communicate(self):
        return b"", b""


@pytest.mark.asyncio
async def test_scanner_builds_command_only_from_typed_plan(tmp_path: Path, monkeypatch):
    captured = []

    async def fake_exec(*command, **kwargs):
        captured.append((command, kwargs))
        return FakeProcess()

    monkeypatch.setattr("core.scanner.asyncio.create_subprocess_exec", fake_exec)
    plan = ScanPlanRequest(
        targets=["https://example.com"],
        template_ids=["http-missing-security-headers"],
        severities=["medium", "high"],
    )
    result = await NucleiScanner(executable="/opt/tools/nuclei").run_plan(plan, tmp_path)
    command = captured[0][0]
    assert command == (
        "/opt/tools/nuclei",
        "-l",
        str(tmp_path / "targets.txt"),
        "-jsonl",
        "-o",
        str(tmp_path / "nuclei.jsonl"),
        "-nc",
        "-severity",
        "medium,high,info",
        "-id",
        "http-missing-security-headers",
    )
    assert result.artifact == tmp_path / "nuclei.jsonl"
    assert result.summary_path == tmp_path / "nuclei_summary.md"
    assert result.summary_path.is_file()
    assert "未发现命中" in result.summary_path.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_scanner_all_scope_omits_template_and_severity_filters(tmp_path: Path, monkeypatch):
    captured = []

    async def fake_exec(*command, **kwargs):
        captured.append(command)
        return FakeProcess()

    monkeypatch.setattr("core.scanner.asyncio.create_subprocess_exec", fake_exec)
    plan = ScanPlanRequest(
        targets=["https://example.com"],
        template_ids=["all"],
        severities=["all"],
    )
    await NucleiScanner(executable="/opt/tools/nuclei").run_plan(plan, tmp_path)

    command = captured[0]
    assert "-id" not in command
    assert "-t" not in command
    assert "-severity" not in command


@pytest.mark.asyncio
async def test_scanner_does_not_forward_fofa_credentials_to_nuclei(tmp_path: Path, monkeypatch):
    captured = []

    async def fake_exec(*command, **kwargs):
        captured.append(kwargs)
        return FakeProcess()

    monkeypatch.setenv("FOFA_EMAIL", "user@example.test")
    monkeypatch.setenv("FOFA_API_KEY", "secret-key")
    monkeypatch.delenv("FOFA_KEY", raising=False)
    monkeypatch.setattr("core.scanner.asyncio.create_subprocess_exec", fake_exec)
    await NucleiScanner(executable="/opt/tools/nuclei").run_plan(
        ScanPlanRequest(
            targets=["https://example.com"],
            template_ids=["http-missing-security-headers"],
            severities=["medium", "high"],
        ),
        tmp_path,
    )
    env = captured[0]["env"]
    assert "FOFA_EMAIL" not in env
    assert "FOFA_API_KEY" not in env
    assert "FOFA_KEY" not in env


@pytest.mark.asyncio
async def test_scanner_omits_severity_filter_for_unknown_template_ids(tmp_path: Path, monkeypatch):
    captured = []

    async def fake_exec(*command, **kwargs):
        captured.append(command)
        return FakeProcess()

    monkeypatch.setenv("FOFAMAP_NUCLEI_ID_ALLOWLIST", "custom-http-check")
    monkeypatch.setattr("core.scanner.asyncio.create_subprocess_exec", fake_exec)
    await NucleiScanner(executable="/opt/tools/nuclei").run_plan(
        ScanPlanRequest(
            targets=["https://example.com"],
            template_ids=["custom-http-check"],
            severities=["medium", "high"],
        ),
        tmp_path,
    )
    assert "-severity" not in captured[0]
    assert captured[0][-2:] == ("-id", "custom-http-check")


class StreamingProcess:
    returncode = 0

    def __init__(self, lines: list[bytes]) -> None:
        self.stderr = _LineStream(lines)

    async def wait(self):
        return self.returncode


class _LineStream:
    def __init__(self, lines: list[bytes]) -> None:
        self._lines = list(lines)

    async def readline(self) -> bytes:
        if not self._lines:
            return b""
        return self._lines.pop(0)


@pytest.mark.asyncio
async def test_scanner_streams_progress_and_parses_findings(tmp_path: Path, monkeypatch):
    events = []
    jsonl = tmp_path / "nuclei.jsonl"

    async def fake_exec(*command, **kwargs):
        jsonl.write_text(
            (
                '{"template-id":"http-missing-security-headers","info":{"name":"HTTP Missing Security Headers",'
                '"severity":"info"},"host":"example.com","matched-at":"https://example.com",'
                '"matcher-name":"content-security-policy","ip":"203.0.113.10"}\n'
                '{"template-id":"http-missing-security-headers","info":{"name":"HTTP Missing Security Headers",'
                '"severity":"info"},"host":"example.com","matched-at":"https://example.com",'
                '"matcher-name":"x-frame-options","ip":"203.0.113.10"}\n'
            ),
            encoding="utf-8",
        )
        return StreamingProcess(
            [
                b"[INF] Targets loaded for current scan: 1\n",
                b"[INF] Templates loaded for current scan: 1\n",
                b"[INF] Scan completed in 1.2s. 2 matches found.\n",
            ]
        )

    monkeypatch.setattr("core.scanner.asyncio.create_subprocess_exec", fake_exec)
    result = await NucleiScanner(executable="/opt/tools/nuclei").run_plan(
        ScanPlanRequest(
            targets=["https://example.com"],
            template_ids=["http-missing-security-headers"],
            severities=["info"],
        ),
        tmp_path,
        on_progress=events.append,
    )
    assert [event.line for event in events] == [
        "[INF] Targets loaded for current scan: 1",
        "[INF] Templates loaded for current scan: 1",
        "[INF] Scan completed in 1.2s. 2 matches found.",
    ]
    assert events[-1].findings == 2
    assert result.loaded_targets == 1
    assert len(result.findings) == 2
    grouped = result.grouped()
    assert len(grouped) == 1
    assert grouped[0].target == "https://example.com"
    assert grouped[0].details == ("content-security-policy", "x-frame-options")
    assert "信息 2" in result.headline()
    assert "content-security-policy" in result.summary_path.read_text(encoding="utf-8")


def test_parse_nuclei_jsonl_skips_invalid_lines(tmp_path: Path):
    path = tmp_path / "nuclei.jsonl"
    path.write_text(
        "not-json\n"
        '{"template-id":"http-missing-security-headers","info":{"name":"Missing Headers","severity":"info"},'
        '"matched-at":"https://a.example","matcher-name":"strict-transport-security"}\n',
        encoding="utf-8",
    )
    findings = parse_nuclei_jsonl(path)
    assert findings == [
        NucleiFinding(
            template_id="http-missing-security-headers",
            name="Missing Headers",
            severity="info",
            host="",
            matched_at="https://a.example",
            matcher_name="strict-transport-security",
            extracted=(),
            ip="",
        )
    ]


def test_host_count_unifies_http_and_tls_target_formats():
    from core.scanner import NucleiScanResult

    result = NucleiScanResult(
        artifact=Path("nuclei.jsonl"),
        findings=[
            NucleiFinding(template_id="tech-detect", matched_at="https://example.com/"),
            NucleiFinding(template_id="deprecated-tls", matched_at="example.com:443"),
        ],
    )

    assert result.host_count == 1
    assert "涉及 1 个站点" in result.headline()


def test_resolve_nuclei_prefers_project_root_binary(tmp_path, monkeypatch):
    binary = tmp_path / "nuclei"
    binary.write_text("#!/bin/sh\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("FOFAMAP_NUCLEI", raising=False)
    monkeypatch.setattr("core.scanner.shutil.which", lambda *_args, **_kwargs: None)
    from core.scanner import resolve_nuclei_executable

    assert Path(resolve_nuclei_executable()).resolve() == binary.resolve()
