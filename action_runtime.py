"""Runtime helpers for the standalone DeployWhisper GitHub Action bundle."""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Iterable
from urllib import error, parse, request
import uuid

COMMENT_MARKER = "<!-- deploywhisper:pr-comment -->"
SCAN_META_MARKER = "deploywhisper:scan-meta"
GITHUB_API_BASE_URL = "https://api.github.com"
SENSITIVE_FILE_MARKERS = {
    ".env",
    ".pem",
    ".key",
    ".tfstate",
    "id_rsa",
    "kubeconfig",
    "credentials",
}
SUPPORTED_TOOL_TYPES = {
    "terraform",
    "kubernetes",
    "ansible",
    "jenkins",
    "cloudformation",
}


class ActionRuntimeError(RuntimeError):
    """Raised when the GitHub Action cannot complete its operational work."""


def _shorten(text: str, limit: int) -> str:
    normalized = " ".join(text.split())
    if len(normalized) <= limit:
        return normalized
    return normalized[: max(limit - 1, 0)].rstrip() + "…"


def _format_timestamp(value: str | None) -> str:
    if not value:
        return "timestamp unavailable"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


def _split_changed_files(raw_value: str) -> list[str]:
    normalized = raw_value.replace(",", "\n")
    return [item.strip() for item in normalized.splitlines() if item.strip()]


def _dedupe_paths(paths: Iterable[str]) -> list[str]:
    unique_paths: list[str] = []
    seen: set[str] = set()
    for raw_path in paths:
        normalized = Path(raw_path).as_posix().lstrip("./")
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        unique_paths.append(normalized)
    return unique_paths


def _load_event_payload(environ: dict[str, str] | None = None) -> dict:
    env = environ or os.environ
    event_path = env.get("GITHUB_EVENT_PATH")
    if not event_path:
        return {}
    payload_path = Path(event_path)
    if not payload_path.is_file():
        return {}
    try:
        return json.loads(payload_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ActionRuntimeError(
            f"GITHUB_EVENT_PATH does not contain valid JSON: {payload_path}"
        ) from exc


def _decode_content(raw_content: bytes | None) -> str:
    if not raw_content:
        return ""
    return raw_content.decode("utf-8", errors="ignore")


def _content_preview(content: str, *, line_limit: int = 100) -> str:
    return "\n".join(content.splitlines()[:line_limit])


def is_sensitive_file(name: str) -> bool:
    lower_name = name.lower()
    path = Path(lower_name)
    if path.name in SENSITIVE_FILE_MARKERS:
        return True
    return any(marker in lower_name for marker in SENSITIVE_FILE_MARKERS)


def detect_tool_type(name: str, raw_content: bytes | None = None) -> str:
    lower_name = name.lower()
    path = Path(lower_name)
    content = _decode_content(raw_content)

    if lower_name == "jenkinsfile" or path.name == "jenkinsfile":
        return "jenkins"

    if path.suffix in {".tf", ".tfvars", ".hcl"}:
        return "terraform"

    if path.suffix == ".json":
        try:
            payload = json.loads(content) if content else {}
        except json.JSONDecodeError:
            payload = {}
        if isinstance(payload, dict):
            if "resource_changes" in payload:
                return "terraform"
            if any(
                key in payload
                for key in (
                    "AWSTemplateFormatVersion",
                    "Resources",
                    "Parameters",
                    "Outputs",
                )
            ):
                return "cloudformation"

    if path.suffix in {".yaml", ".yml"}:
        preview = _content_preview(content)
        if re.search(
            r"(?m)^(AWSTemplateFormatVersion|Resources|Parameters|Outputs)\s*:",
            preview,
        ) or re.search(
            r"(?m)(!Ref\b|!Sub\b|!GetAtt\b|Fn::Sub\b|Fn::Join\b|Fn::GetAtt\b|AWS::)",
            preview,
        ):
            return "cloudformation"
        if re.search(r"(?m)^\s*apiVersion\s*:\s*\S+", content) and re.search(
            r"(?m)^\s*kind\s*:\s*\S+", content
        ):
            return "kubernetes"
        if re.search(r"(?m)^\s*Transform\s*:\s*AWS::", content):
            return "cloudformation"
        if re.search(r"(?m)^\s*(hosts|tasks|roles)\s*:", content):
            return "ansible"

    return "unsupported"


def load_github_context(environ: dict[str, str] | None = None) -> dict[str, object]:
    """Load the GitHub event context required for changed-file discovery."""
    env = environ or os.environ
    payload = _load_event_payload(env)
    pull_request = payload.get("pull_request") or {}
    base_ref = pull_request.get("base") or {}
    head_ref = pull_request.get("head") or {}
    return {
        "event_name": str(env.get("GITHUB_EVENT_NAME") or ""),
        "repository": str(env.get("GITHUB_REPOSITORY") or ""),
        "sha": str(env.get("GITHUB_SHA") or ""),
        "pull_request_number": payload.get("number") or pull_request.get("number"),
        "base_sha": base_ref.get("sha"),
        "head_sha": head_ref.get("sha") or env.get("GITHUB_SHA"),
    }


def _git_output(repo_root: Path, *args: str) -> str:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        message = (exc.stderr or exc.stdout or "").strip()
        raise ActionRuntimeError(
            f"Git command failed: git {' '.join(args)}"
            + (f" ({message})" if message else "")
        ) from exc
    return completed.stdout.strip()


def _ensure_commit_available(repo_root: Path, sha: str) -> None:
    if not sha:
        return
    try:
        subprocess.run(
            ["git", "cat-file", "-e", f"{sha}^{{commit}}"],
            cwd=repo_root,
            check=True,
            capture_output=True,
            text=True,
        )
        return
    except subprocess.CalledProcessError:
        pass

    _git_output(repo_root, "fetch", "--no-tags", "--depth=1", "origin", sha)


def discover_changed_files(repo_root: Path, context: dict[str, object]) -> list[str]:
    """Determine changed files for the current GitHub event."""
    base_sha = str(context.get("base_sha") or "")
    head_sha = str(context.get("head_sha") or "")

    if base_sha and head_sha:
        _ensure_commit_available(repo_root, base_sha)
        _ensure_commit_available(repo_root, head_sha)
        output = _git_output(
            repo_root,
            "diff",
            "--name-only",
            "--diff-filter=ACMR",
            f"{base_sha}...{head_sha}",
        )
        return _dedupe_paths(output.splitlines())

    output = _git_output(
        repo_root,
        "diff-tree",
        "--no-commit-id",
        "--name-only",
        "-r",
        "HEAD",
    )
    return _dedupe_paths(output.splitlines())


def select_artifacts_for_upload(
    repo_root: Path, changed_files: Iterable[str]
) -> tuple[list[tuple[str, bytes]], list[str]]:
    """Filter changed files down to supported DeployWhisper artifacts."""
    candidates: list[tuple[str, bytes]] = []
    skipped: list[str] = []

    for relative_path in _dedupe_paths(changed_files):
        file_path = (repo_root / relative_path).resolve()
        try:
            file_path.relative_to(repo_root.resolve())
        except ValueError:
            skipped.append(f"{relative_path} (outside working directory)")
            continue

        if not file_path.is_file():
            skipped.append(f"{relative_path} (missing or deleted)")
            continue
        candidates.append((relative_path, file_path.read_bytes()))

    upload_files: list[tuple[str, bytes]] = []
    for name, raw_content in candidates:
        if is_sensitive_file(name):
            skipped.append(f"{name} (sensitive)")
            continue
        if detect_tool_type(name, raw_content) not in SUPPORTED_TOOL_TYPES:
            skipped.append(f"{name} (unsupported)")
            continue
        upload_files.append((name, raw_content))

    return upload_files, skipped


def _resolve_analysis_endpoint(api_url: str) -> str:
    parsed = parse.urlparse(api_url)
    if not parsed.scheme or not parsed.netloc:
        raise ActionRuntimeError(
            "The `api-url` input must be an absolute DeployWhisper URL."
        )

    path = parsed.path.rstrip("/")
    if not path:
        path = "/api/v1/analyses"
    elif path.endswith("/api/v1"):
        path = f"{path}/analyses"
    elif not path.endswith("/api/v1/analyses"):
        path = f"{path}/api/v1/analyses"

    return parse.urlunparse(
        parsed._replace(path=path, params="", query="", fragment="")
    )


def _multipart_body(
    files: list[tuple[str, bytes]], fields: dict[str, str] | None = None
) -> tuple[bytes, str]:
    boundary = f"deploywhisper-{uuid.uuid4().hex}"
    body = bytearray()
    for name, value in (fields or {}).items():
        if value == "":
            continue
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        body.extend(
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("utf-8")
        )
        body.extend(value.encode("utf-8"))
        body.extend(b"\r\n")
    for filename, content in files:
        body.extend(f"--{boundary}\r\n".encode("utf-8"))
        disposition = (
            'Content-Disposition: form-data; name="files"; '
            f'filename="{Path(filename).name}"\r\n'
        )
        body.extend(disposition.encode("utf-8"))
        body.extend(b"Content-Type: application/octet-stream\r\n\r\n")
        body.extend(content)
        body.extend(b"\r\n")
    body.extend(f"--{boundary}--\r\n".encode("utf-8"))
    return bytes(body), boundary


def _http_json(request_obj: request.Request) -> dict:
    try:
        with request.urlopen(request_obj, timeout=120) as response:
            return json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:
        payload = exc.read().decode("utf-8", errors="ignore")
        raise ActionRuntimeError(
            f"DeployWhisper API request failed with HTTP {exc.code}: "
            f"{payload or exc.reason}"
        ) from exc
    except error.URLError as exc:
        raise ActionRuntimeError(
            f"DeployWhisper API request could not be completed: {exc.reason}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise ActionRuntimeError(
            "DeployWhisper API returned a non-JSON response."
        ) from exc


def _truthy_input(value: object) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def validate_scope_inputs(
    *,
    project_key: str | None,
    project_id: str | None,
    workspace_key: str | None,
    workspace_id: str | None,
    allow_derived_project_scope: bool,
) -> dict[str, str]:
    project_key = (project_key or "").strip()
    project_id = (project_id or "").strip()
    workspace_key = (workspace_key or "").strip()
    workspace_id = (workspace_id or "").strip()

    for label, value in {
        "project-key": project_key,
        "project-id": project_id,
        "workspace-key": workspace_key,
        "workspace-id": workspace_id,
    }.items():
        if "\r" in value or "\n" in value:
            raise ActionRuntimeError(f"{label} must not contain newline characters.")

    for label, value in {
        "project-id": project_id,
        "workspace-id": workspace_id,
    }.items():
        if value and not re.fullmatch(r"[1-9][0-9]*", value):
            raise ActionRuntimeError(f"{label} must be a positive numeric id.")

    if project_key and project_id:
        raise ActionRuntimeError(
            "Provide only one project scope input: project-key or project-id."
        )
    if workspace_key and workspace_id:
        raise ActionRuntimeError(
            "Provide only one workspace scope input: workspace-key or workspace-id."
        )
    if (workspace_key or workspace_id) and not project_key and not project_id:
        raise ActionRuntimeError(
            "Workspace scope is project-local. Provide project-key or project-id "
            "with workspace-key or workspace-id."
        )
    if not project_key and not project_id and not allow_derived_project_scope:
        raise ActionRuntimeError(
            "Project scope is required. Provide project-key or project-id, "
            "or set allow-derived-project-scope to true when the API endpoint "
            "derives project scope."
        )

    return {
        "project_key": project_key,
        "project_id": project_id,
        "workspace_key": workspace_key,
        "workspace_id": workspace_id,
    }


def _github_api_json(
    url: str,
    *,
    github_token: str,
    method: str = "GET",
    payload: dict | None = None,
) -> dict | list[dict]:
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {github_token}",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    data = None
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = request.Request(url, data=data, headers=headers, method=method)
    try:
        with request.urlopen(req, timeout=120) as response:
            return json.loads(response.read().decode("utf-8"))
    except error.HTTPError as exc:
        response_body = exc.read().decode("utf-8", errors="ignore")
        raise ActionRuntimeError(
            f"GitHub API request failed with HTTP {exc.code}: "
            f"{response_body or exc.reason}"
        ) from exc
    except error.URLError as exc:
        raise ActionRuntimeError(
            f"GitHub API request could not be completed: {exc.reason}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise ActionRuntimeError("GitHub API returned a non-JSON response.") from exc


def submit_analysis(
    api_url: str,
    artifacts: list[tuple[str, bytes]],
    *,
    api_token: str | None,
    project_key: str | None = None,
    project_id: str | None = None,
    workspace_key: str | None = None,
    workspace_id: str | None = None,
    trigger_type: str,
    trigger_id: str,
) -> dict:
    """POST artifacts to the existing analyses API."""
    endpoint = _resolve_analysis_endpoint(api_url)
    scope_fields = {
        "project_key": (project_key or "").strip(),
        "project_id": (project_id or "").strip(),
        "workspace_key": (workspace_key or "").strip(),
        "workspace_id": (workspace_id or "").strip(),
    }
    body, boundary = _multipart_body(artifacts, scope_fields)
    headers = {
        "Accept": "application/json",
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(body)),
        "X-DeployWhisper-Trigger-Type": trigger_type,
        "X-DeployWhisper-Trigger-Id": trigger_id,
    }
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"
    req = request.Request(endpoint, data=body, headers=headers, method="POST")
    return _http_json(req)


def _scan_meta_marker(scan_meta: dict[str, object]) -> str:
    return f"<!-- {SCAN_META_MARKER} {json.dumps(scan_meta, separators=(',', ':'))} -->"


def _scan_meta_int(payload: dict[str, object], key: str) -> int:
    value = payload[key]
    if isinstance(value, bool):
        raise ValueError(f"{key} must be an integer.")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"[0-9]+", value.strip()):
        return int(value.strip())
    raise ValueError(f"{key} must be an integer.")


def extract_comment_metadata(comment_body: str) -> dict[str, object] | None:
    match = re.search(
        r"<!--\s*deploywhisper:scan-meta\s+(\{.*?\})\s*-->",
        comment_body,
        re.DOTALL,
    )
    if not match:
        return None
    try:
        payload = json.loads(match.group(1))
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    try:
        report_id = _scan_meta_int(payload, "report_id")
        risk_score = _scan_meta_int(payload, "risk_score")
        if report_id <= 0 or risk_score < 0:
            return None
        return {
            "report_id": report_id,
            "risk_score": risk_score,
            "severity": str(payload.get("severity") or "").lower(),
            "recommendation": str(payload.get("recommendation") or "").lower(),
            "created_at": str(payload.get("created_at") or ""),
            "head_sha": str(payload.get("head_sha") or ""),
        }
    except (KeyError, TypeError, ValueError):
        return None


def _current_scan_meta(
    current_report: dict[str, object], *, head_sha: str | None
) -> dict[str, object]:
    return {
        "report_id": _safe_int(current_report.get("id")),
        "risk_score": _safe_int(current_report.get("risk_score")),
        "severity": str(current_report.get("severity") or "").lower(),
        "recommendation": str(current_report.get("recommendation") or "").lower(),
        "created_at": str(current_report.get("created_at") or ""),
        "head_sha": head_sha or "",
    }


def _nonblank_string(value: object) -> str:
    return str(value or "").strip()


def _single_line_string(value: object) -> str:
    return " ".join(_nonblank_string(value).split())


def _mapping_or_empty(value: object) -> dict:
    return dict(value) if isinstance(value, dict) else {}


def _dict_items(value: object) -> list[dict]:
    return (
        [item for item in value if isinstance(item, dict)]
        if isinstance(value, list)
        else []
    )


def _safe_int(value: object, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str) and re.fullmatch(r"[0-9]+", value.strip()):
        return int(value.strip())
    return default


def _markdown_text(value: object) -> str:
    text = _single_line_string(value)
    replacements = {
        "<!--": "<\\!--",
        "-->": "--\\>",
        "\\": "\\\\",
        "<": "\\<",
        ">": "\\>",
        "[": "\\[",
        "]": "\\]",
        "(": "\\(",
        ")": "\\)",
        "#": "\\#",
        "*": "\\*",
        "_": "\\_",
        "`": "\\`",
        "|": "\\|",
        "!": "\\!",
    }
    for source, replacement in replacements.items():
        text = text.replace(source, replacement)
    return text


def _comment_link(value: object) -> str:
    link = _nonblank_string(value)
    if not link:
        return ""
    if any(character.isspace() or character in '<>"' for character in link):
        return ""
    parsed = parse.urlparse(link)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    return link.replace("(", "%28").replace(")", "%29")


def _finite_rate(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    rate = float(value)
    return rate if math.isfinite(rate) else None


def _previous_scan_summary(
    previous_scan: dict[str, object] | None,
    current_report: dict[str, object] | None,
    *,
    current_head_sha: str | None = None,
) -> list[str]:
    if not previous_scan or not current_report:
        return []
    previous_head_sha = str(previous_scan.get("head_sha") or "")
    current_head_sha = current_head_sha or ""
    same_commit_rerun = (
        bool(previous_head_sha and current_head_sha)
        and (
            previous_head_sha == current_head_sha
            or (
                len(previous_head_sha) == 12
                and current_head_sha.startswith(previous_head_sha)
            )
        )
    )
    previous_score = _safe_int(previous_scan.get("risk_score"))
    current_score = _safe_int(current_report.get("risk_score"))
    previous_severity = str(previous_scan.get("severity") or "unknown").upper()
    current_severity = str(current_report.get("severity") or "unknown").upper()
    previous_report_id = _safe_int(previous_scan.get("report_id"))
    lines = [
        (
            f"- Change since last scan: Risk score changed {previous_score} → {current_score}, "
            f"previously {previous_severity}, now {current_severity}"
        ),
        (
            f"- Previous analysis: report #{previous_report_id} at "
            f"{_format_timestamp(str(previous_scan.get('created_at') or ''))}"
        ),
    ]
    if same_commit_rerun:
        lines.insert(
            1,
            "- Rerun context: same commit was scanned again; deltas may reflect changed rules, parser behavior, incidents, or action inputs.",
        )
    return lines


def _finding_evidence_count(finding: dict, evidence_items: list[dict[str, object]]) -> int:
    evidence_refs = finding.get("evidence_refs")
    evidence_ids = {
        _nonblank_string(item.get("evidence_id")) or _nonblank_string(item.get("id"))
        for item in evidence_items
    }
    evidence_ids.discard("")
    if isinstance(evidence_refs, list):
        refs = {_nonblank_string(item) for item in evidence_refs}
        refs.discard("")
        return len(refs & evidence_ids) if evidence_ids else 0
    finding_id = _nonblank_string(finding.get("finding_id")) or _nonblank_string(
        finding.get("id")
    )
    if not finding_id:
        return 0
    return sum(
        1
        for evidence_item in evidence_items
        if _nonblank_string(evidence_item.get("finding_id")) == finding_id
    )


def _derive_evidence_law(
    json_payload: dict,
    current_report: dict[str, object] | None,
) -> tuple[str, str]:
    report_findings = (
        current_report.get("findings") if isinstance(current_report, dict) else None
    )
    findings = _dict_items(report_findings)
    if not findings:
        findings = _dict_items(json_payload.get("top_findings"))
    evidence_items = (
        current_report.get("evidence_items")
        if isinstance(current_report, dict)
        else None
    )
    evidence_rows = _dict_items(evidence_items)
    severe_findings = [
        finding
        for finding in findings
        if _nonblank_string(finding.get("severity")).lower() in {"high", "critical"}
    ]
    if not severe_findings:
        return (
            "Satisfied",
            "No high or critical findings require Evidence Law support.",
        )
    unsupported_count = sum(
        1
        for finding in severe_findings
        if _finding_evidence_count(finding, evidence_rows) <= 0
    )
    if unsupported_count:
        return (
            "Needs review",
            f"{unsupported_count} high or critical finding(s) lack verified linked evidence in this payload.",
        )
    return (
        "Satisfied",
        "High and critical findings have linked evidence in this report.",
    )


def _evidence_law_summary(
    json_payload: dict,
    current_report: dict[str, object] | None,
    *,
    limit: int,
) -> str:
    derived_status, derived_detail = _derive_evidence_law(json_payload, current_report)
    payload_status = _nonblank_string(json_payload.get("evidence_law_status"))
    status_source = (
        derived_status if derived_status == "Needs review" else payload_status or derived_status
    )
    status = _shorten(_markdown_text(status_source), 48)
    detail_source = (
        derived_detail
        if derived_status == "Needs review"
        else _nonblank_string(json_payload.get("evidence_law_detail")) or derived_detail
    )
    detail = _shorten(
        _markdown_text(detail_source),
        limit,
    )
    return f"Evidence Law: {status} - {detail}"


def _pattern_match_summary(
    current_report: dict[str, object] | None, *, limit: int
) -> str:
    if not current_report:
        return "Pattern matches: not available in this action response."
    matches = current_report.get("incident_matches")
    if not isinstance(matches, list) or not matches:
        return "Pattern matches: none returned."

    valid_matches = [
        raw_match
        for raw_match in _dict_items(matches)
        if (
            _nonblank_string(raw_match.get("match_type"))
            or raw_match.get("incident_id") is not None
            or _nonblank_string(raw_match.get("public_pattern_id"))
        )
    ]
    labels: list[str] = []
    for raw_match in valid_matches:
        if len(labels) >= 2:
            break
        match_type = _single_line_string(raw_match.get("match_type"))
        if match_type == "public_risk_pattern":
            match_label = (
                "public pattern "
                + (
                    _markdown_text(raw_match.get("public_pattern_id"))
                    or "unidentified"
                )
            )
        elif raw_match.get("incident_id") is not None:
            match_label = "organization incident #" + _markdown_text(
                raw_match.get("incident_id")
            )
        else:
            match_label = _markdown_text(match_type.replace("_", " ")) or "matched pattern"
        confidence = _markdown_text(raw_match.get("confidence_label"))
        summary = _nonblank_string(raw_match.get("summary")) or _nonblank_string(
            raw_match.get("reason")
        )
        suffix_parts = [
            part for part in (confidence, _shorten(_markdown_text(summary), limit)) if part
        ]
        labels.append(
            match_label
            if not suffix_parts
            else f"{match_label} ({'; '.join(suffix_parts)})"
        )

    if not labels:
        return "Pattern matches: none returned."
    extra = max(len(valid_matches) - len(labels), 0)
    suffix = f"; +{extra} more" if extra > 0 else ""
    return "Pattern matches: " + "; ".join(labels) + suffix


def _scanner_context_summary(current_report: dict[str, object] | None) -> str:
    if not current_report:
        return "Scanner context: not available in this action response."

    parse_batch = current_report.get("parse_batch")
    if isinstance(parse_batch, dict):
        files = parse_batch.get("files")
        if isinstance(files, list) and files:
            totals: dict[str, int] = {}
            parsed: dict[str, int] = {}
            for raw_file in files:
                if not isinstance(raw_file, dict):
                    continue
                tool = _markdown_text(raw_file.get("tool")) or "unknown"
                totals[tool] = totals.get(tool, 0) + 1
                if _nonblank_string(raw_file.get("status")).lower() == "parsed":
                    parsed[tool] = parsed.get(tool, 0) + 1
            if totals:
                return "Scanner context: " + "; ".join(
                    f"{tool} {parsed.get(tool, 0)}/{total} parsed"
                    for tool, total in totals.items()
                )

    context = current_report.get("context_completeness")
    if isinstance(context, dict):
        parser_success = context.get("parser_success_by_tool")
        if isinstance(parser_success, dict) and parser_success:
            parts = []
            for tool, rate in sorted(parser_success.items()):
                finite_rate = _finite_rate(rate)
                if finite_rate is not None:
                    parts.append(
                        f"{_markdown_text(tool)} {round(finite_rate * 100)}% parser success"
                    )
            if parts:
                return "Scanner context: " + "; ".join(parts)

    return "Scanner context: unavailable."


def _uncertainty_summary(
    json_payload: dict,
    current_report: dict[str, object] | None,
    *,
    limit: int,
) -> str:
    context = (
        current_report.get("context_completeness")
        if isinstance(current_report, dict)
        else None
    )
    uncertainty = _nonblank_string(context.get("uncertainty")) if isinstance(context, dict) else ""
    if not uncertainty:
        flags = json_payload.get("uncertainty_flags")
        if isinstance(flags, list) and flags:
            uncertainty = "Flags: " + ", ".join(
                _nonblank_string(flag) for flag in flags if _nonblank_string(flag)
            )
    if not uncertainty:
        uncertainty = "None reported."
    return "Uncertainty: " + _shorten(_markdown_text(uncertainty), limit)


def _render_pr_comment(
    share_summary: dict,
    *,
    current_report: dict[str, object] | None,
    previous_scan: dict[str, object] | None,
    head_sha: str | None,
    headline_limit: int,
    finding_title_limit: int,
    summary_limit: int,
    compact_links: bool = False,
    compact_context: bool = False,
) -> str:
    share_summary = _mapping_or_empty(share_summary)
    json_payload = _mapping_or_empty(share_summary.get("json_payload"))
    verdict_banner = _shorten(
        _markdown_text(json_payload.get("verdict_banner") or "DeployWhisper advisory"),
        80,
    )
    headline = _shorten(
        _markdown_text(
            json_payload.get("headline")
            or share_summary.get("headline")
            or "DeployWhisper analysis completed."
        ),
        headline_limit,
    )
    evidence_count = _safe_int(json_payload.get("evidence_count"))
    blast_radius_summary = _shorten(
        _markdown_text(json_payload.get("blast_radius_summary") or "No blast radius summary."),
        summary_limit,
    )
    rollback_summary = _shorten(
        _markdown_text(json_payload.get("rollback_summary") or "Rollback summary unavailable."),
        summary_limit,
    )
    advisory_summary = _shorten(
        _markdown_text(
            json_payload.get("advisory_summary")
            or "This result requires additional human review before release."
        ),
        summary_limit,
    )
    context = _mapping_or_empty(json_payload.get("context_completeness"))
    context_label = _shorten(_markdown_text(context.get("label") or "UNKNOWN CONTEXT"), 32)
    context_summary = _shorten(
        _markdown_text(context.get("summary") or "Context completeness unavailable."),
        summary_limit,
    )
    report_link = _comment_link(json_payload.get("report_link"))
    rollback_link = _comment_link(json_payload.get("rollback_link"))

    top_findings = _dict_items(json_payload.get("top_findings"))[:3]
    current_scan_lines = []
    if current_report:
        current_report_id = _safe_int(current_report.get("id"))
        current_scan_lines.append(
            f"- Current analysis: report #{current_report_id} at "
            f"{_format_timestamp(str(current_report.get('created_at') or ''))}"
        )
    current_scan_lines.extend(
        _previous_scan_summary(
            previous_scan,
            current_report,
            current_head_sha=head_sha,
        )
    )
    links_line = (
        f"- Links: [Report]({report_link}) · [Rollback]({rollback_link})"
        if compact_links and report_link and rollback_link
        else (
            f"- Links: [Open full report]({report_link}) · [View rollback plan]({rollback_link})"
            if report_link and rollback_link
            else (
                f"- Link: [Open full report]({report_link})"
                if report_link
                else (
                    f"- Link: [View rollback plan]({rollback_link})"
                    if rollback_link
                    else "- Link: Report unavailable"
                )
            )
        )
    )
    lines = [
        COMMENT_MARKER,
        f"## {verdict_banner}",
        f"**Summary:** {headline}",
        f"- Evidence: {evidence_count} evidence items",
        f"- {_evidence_law_summary(json_payload, current_report, limit=summary_limit)}",
        f"- Blast radius: {blast_radius_summary}",
        f"- Rollback: {rollback_summary}",
        f"- {_pattern_match_summary(current_report, limit=summary_limit)}",
        f"- {_scanner_context_summary(current_report)}",
        f"- {_uncertainty_summary(json_payload, current_report, limit=summary_limit)}",
        "- Advisory: advisory-only; does not block merge.",
        links_line,
        (
            f"- Context: {context_label}"
            if compact_context
            else f"- Context: {context_label} · {context_summary}"
        ),
        *current_scan_lines,
        "<details>",
        "<summary>Top risks and evidence</summary>",
        "",
    ]
    if top_findings:
        lines.extend(
            f"- {_markdown_text(finding.get('severity') or 'medium').upper()}: "
            f"{_shorten(_markdown_text(finding.get('title') or 'Untitled finding'), finding_title_limit)} "
            f"({_safe_int(finding.get('evidence_count'))} evidence)"
            for finding in top_findings
        )
    else:
        lines.append("- No findings were returned in the share summary.")
    lines.extend(
        [
            f"- Rollback summary: {rollback_summary}",
            f"- Advisory only: {advisory_summary}",
            "</details>",
        ]
    )
    if current_report:
        lines.append(_scan_meta_marker(_current_scan_meta(current_report, head_sha=head_sha)))
    return "\n".join(lines)


def build_pr_comment(
    share_summary: dict,
    *,
    current_report: dict[str, object] | None = None,
    previous_scan: dict[str, object] | None = None,
    head_sha: str | None = None,
) -> str:
    """Format a GitHub-ready PR comment from the shared summary contract."""
    candidates = [
        _render_pr_comment(
            share_summary,
            current_report=current_report,
            previous_scan=previous_scan,
            head_sha=head_sha,
            headline_limit=120,
            finding_title_limit=72,
            summary_limit=120,
        ),
        _render_pr_comment(
            share_summary,
            current_report=current_report,
            previous_scan=previous_scan,
            head_sha=head_sha,
            headline_limit=96,
            finding_title_limit=52,
            summary_limit=72,
            compact_links=True,
        ),
        _render_pr_comment(
            share_summary,
            current_report=current_report,
            previous_scan=previous_scan,
            head_sha=head_sha,
            headline_limit=72,
            finding_title_limit=36,
            summary_limit=48,
            compact_links=True,
            compact_context=True,
        ),
    ]
    for comment in candidates:
        if len(comment) <= 2000:
            return comment

    fallback = _render_pr_comment(
        share_summary,
        current_report=current_report,
        previous_scan=previous_scan,
        head_sha=head_sha,
        headline_limit=48,
        finding_title_limit=24,
        summary_limit=32,
        compact_links=True,
        compact_context=True,
    )
    if len(fallback) <= 2000:
        return fallback
    meta_prefix = f"\n<!-- {SCAN_META_MARKER} "
    meta_suffix = ""
    meta_index = fallback.rfind(meta_prefix)
    if meta_index != -1:
        meta_suffix = fallback[meta_index:]
        fallback = fallback[:meta_index]
    closing = "\n</details>"
    opening, _, _ = fallback.rpartition(closing)
    reserved = len(closing) + len(meta_suffix) + 8
    available = max(2000 - reserved, 64)
    return _shorten(opening, available).rstrip() + closing + meta_suffix


def _find_existing_pr_comment(
    comments_url: str, *, github_token: str
) -> dict[str, object] | None:
    page = 1
    while True:
        comments = _github_api_json(
            f"{comments_url}?per_page=100&page={page}",
            github_token=github_token,
        )
        if not isinstance(comments, list):
            raise ActionRuntimeError("GitHub issue-comments API returned an unexpected payload.")
        existing_comment = next(
            (
                comment
                for comment in comments
                if COMMENT_MARKER in str(comment.get("body") or "")
            ),
            None,
        )
        if existing_comment is not None:
            return existing_comment
        if len(comments) < 100:
            return None
        page += 1


def find_existing_pr_comment(
    context: dict[str, object], *, github_token: str
) -> dict[str, object] | None:
    repository = str(context.get("repository") or "").strip()
    pull_request_number = context.get("pull_request_number")
    if not repository or pull_request_number is None:
        return None
    comments_url = (
        f"{GITHUB_API_BASE_URL}/repos/{repository}/issues/{int(pull_request_number)}/comments"
    )
    return _find_existing_pr_comment(
        comments_url,
        github_token=github_token,
    )


def upsert_pr_comment(
    context: dict[str, object],
    comment_body: str,
    *,
    github_token: str,
    existing_comment: dict[str, object] | None = None,
) -> dict[str, object]:
    """Create or update the action's PR conversation comment."""
    repository = str(context.get("repository") or "").strip()
    pull_request_number = context.get("pull_request_number")
    if not repository or pull_request_number is None:
        raise ActionRuntimeError(
            "Cannot post a PR comment without repository and pull request context."
        )
    if not github_token.strip():
        raise ActionRuntimeError(
            "GITHUB_TOKEN is required to post or update the pull request comment."
        )

    comments_url = (
        f"{GITHUB_API_BASE_URL}/repos/{repository}/issues/{int(pull_request_number)}/comments"
    )
    if existing_comment is None:
        existing_comment = _find_existing_pr_comment(
            comments_url,
            github_token=github_token,
        )
    if existing_comment:
        comment_id = int(existing_comment["id"])
        updated = _github_api_json(
            f"{GITHUB_API_BASE_URL}/repos/{repository}/issues/comments/{comment_id}",
            github_token=github_token,
            method="PATCH",
            payload={"body": comment_body},
        )
        return {
            "id": int(updated["id"]),
            "html_url": str(updated.get("html_url") or ""),
            "updated": True,
        }

    created = _github_api_json(
        comments_url,
        github_token=github_token,
        method="POST",
        payload={"body": comment_body},
    )
    return {
        "id": int(created["id"]),
        "html_url": str(created.get("html_url") or ""),
        "updated": False,
    }


def _write_env_file(path_value: str | None, key: str, value: str) -> None:
    if not path_value:
        return
    destination = Path(path_value)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("a", encoding="utf-8") as handle:
        if "\n" in value:
            marker = f"EOF_{uuid.uuid4().hex}"
            handle.write(f"{key}<<{marker}\n{value}\n{marker}\n")
            return
        handle.write(f"{key}={value}\n")


def write_github_output(
    key: str, value: object, environ: dict[str, str] | None = None
) -> None:
    env = environ or os.environ
    serialized = value if isinstance(value, str) else json.dumps(value)
    _write_env_file(env.get("GITHUB_OUTPUT"), key, serialized)


def write_step_summary(markdown: str, environ: dict[str, str] | None = None) -> None:
    env = environ or os.environ
    summary_path = env.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return
    summary_file = Path(summary_path)
    summary_file.parent.mkdir(parents=True, exist_ok=True)
    with summary_file.open("a", encoding="utf-8") as handle:
        handle.write(markdown.rstrip() + "\n")


def _success_summary(
    *,
    analysis_payload: dict,
    changed_files: list[str],
    uploaded_files: list[tuple[str, bytes]],
    skipped_files: list[str],
) -> str:
    analysis_payload = _mapping_or_empty(analysis_payload)
    data = _mapping_or_empty(analysis_payload.get("data"))
    share_summary = _mapping_or_empty(data.get("share_summary"))
    share_json = _mapping_or_empty(share_summary.get("json_payload"))
    persisted_report = _mapping_or_empty(data.get("persisted_report"))
    report_id = persisted_report.get("id")
    report_link = _comment_link(share_json.get("report_link"))

    lines = [
        "## DeployWhisper analysis submitted",
        f"- Changed files detected: {len(changed_files)}",
        f"- Artifacts uploaded: {len(uploaded_files)}",
        f"- Report ID: {report_id if report_id is not None else 'unavailable'}",
    ]
    if report_link:
        lines.append(f"- Report link: {report_link}")
    if skipped_files:
        lines.append("- Skipped files:")
        lines.extend(f"  - {item}" for item in skipped_files)
    markdown = _nonblank_string(share_summary.get("markdown"))
    if markdown:
        lines.extend(["", markdown])
    return "\n".join(lines)


def _comment_warning_summary(message: str) -> str:
    return "\n".join(
        [
            "## PR comment not published",
            f"- Reason: {message}",
            "- DeployWhisper analysis still completed successfully and remains advisory-only.",
        ]
    )


def _skip_summary(reason: str, skipped_files: list[str]) -> str:
    lines = [
        "## DeployWhisper analysis skipped",
        f"- Reason: {reason}",
    ]
    if skipped_files:
        lines.append("- Skipped files:")
        lines.extend(f"  - {item}" for item in skipped_files)
    return "\n".join(lines)


def _build_trigger_id(context: dict[str, object]) -> str:
    pull_request_number = context.get("pull_request_number")
    head_sha = str(context.get("head_sha") or context.get("sha") or "")
    sha_fragment = head_sha[:12] if head_sha else "unknown-sha"
    if pull_request_number is not None:
        return f"pr-{pull_request_number}@{sha_fragment}"
    return f"github@{sha_fragment}"


def _build_trigger_type(context: dict[str, object]) -> str:
    event_name = str(context.get("event_name") or "").strip()
    if event_name == "pull_request":
        return "github_pull_request"
    if event_name == "pull_request_target":
        return "github_pull_request_target"
    if event_name:
        return f"github_{event_name}"
    return "github_action"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the DeployWhisper GitHub Action.")
    parser.add_argument(
        "--api-url",
        required=True,
        help="DeployWhisper base URL or analyses endpoint.",
    )
    parser.add_argument(
        "--api-token",
        default="",
        help="Optional bearer token for the DeployWhisper API.",
    )
    parser.add_argument(
        "--project-key",
        default="",
        help=(
            "Project key for DeployWhisper project-scoped analysis. "
            "Leave blank only when the API endpoint derives project scope."
        ),
    )
    parser.add_argument(
        "--project-id",
        default="",
        help="Numeric project id for DeployWhisper project-scoped analysis.",
    )
    parser.add_argument(
        "--workspace-key",
        default="",
        help="Optional workspace or environment key within the selected project.",
    )
    parser.add_argument(
        "--workspace-id",
        default="",
        help="Optional numeric workspace or environment id within the selected project.",
    )
    parser.add_argument(
        "--allow-derived-project-scope",
        default="true",
        help=(
            "Set true only when the DeployWhisper API endpoint derives project "
            "scope without a project-key or project-id input."
        ),
    )
    parser.add_argument(
        "--changed-files",
        default="",
        help=(
            "Optional comma or newline separated file list. "
            "When omitted, the action discovers PR changes from git."
        ),
    )
    parser.add_argument(
        "--working-directory",
        default=".",
        help="Repository root containing the checked-out pull request.",
    )
    return parser


def run_action(args: argparse.Namespace, environ: dict[str, str] | None = None) -> int:
    env = environ or os.environ
    repo_root = Path(args.working_directory).resolve()
    context = load_github_context(env)

    changed_files = _dedupe_paths(_split_changed_files(args.changed_files))
    if not changed_files:
        changed_files = discover_changed_files(repo_root, context)

    write_github_output("changed-file-count", len(changed_files), env)
    if not changed_files:
        write_github_output("created", "false", env)
        write_github_output("skipped-files", [], env)
        write_step_summary(_skip_summary("No changed files detected.", []), env)
        return 0

    upload_files, skipped_files = select_artifacts_for_upload(repo_root, changed_files)
    write_github_output("submitted-artifact-count", len(upload_files), env)
    write_github_output("skipped-files", skipped_files, env)

    if not upload_files:
        write_github_output("created", "false", env)
        write_step_summary(
            _skip_summary(
                "No supported DeployWhisper artifacts were found in the changed files.",
                skipped_files,
            ),
            env,
        )
        return 0

    scope_fields = validate_scope_inputs(
        project_key=args.project_key,
        project_id=args.project_id,
        workspace_key=args.workspace_key,
        workspace_id=args.workspace_id,
        allow_derived_project_scope=_truthy_input(
            getattr(args, "allow_derived_project_scope", "")
        ),
    )

    payload = submit_analysis(
        args.api_url,
        upload_files,
        api_token=args.api_token or None,
        project_key=scope_fields["project_key"] or None,
        project_id=scope_fields["project_id"] or None,
        workspace_key=scope_fields["workspace_key"] or None,
        workspace_id=scope_fields["workspace_id"] or None,
        trigger_type=_build_trigger_type(context),
        trigger_id=_build_trigger_id(context),
    )

    payload = _mapping_or_empty(payload)
    data = _mapping_or_empty(payload.get("data"))
    meta = _mapping_or_empty(payload.get("meta"))
    advisory = _mapping_or_empty(data.get("advisory"))
    share_summary = _mapping_or_empty(data.get("share_summary"))
    share_json = _mapping_or_empty(share_summary.get("json_payload"))
    persisted_report = _mapping_or_empty(data.get("persisted_report"))

    write_github_output("created", "true", env)
    write_github_output(
        "accepted-artifact-count",
        meta.get("accepted_artifact_count", len(upload_files)),
        env,
    )
    write_github_output("report-id", persisted_report.get("id", ""), env)
    write_github_output("report-link", share_json.get("report_link", ""), env)
    write_github_output(
        "severity",
        _nonblank_string(advisory.get("severity"))
        or _nonblank_string(share_summary.get("severity")),
        env,
    )
    write_github_output(
        "recommendation",
        _nonblank_string(advisory.get("recommendation"))
        or _nonblank_string(share_summary.get("recommendation")),
        env,
    )
    write_github_output("share-summary-json", share_json, env)
    write_github_output(
        "share-summary-markdown", share_summary.get("markdown", ""), env
    )
    extra_summary_sections: list[str] = []
    pull_request_number = context.get("pull_request_number")
    if pull_request_number is not None:
        github_token = str(env.get("GITHUB_TOKEN") or "").strip()
        if github_token:
            try:
                existing_comment = find_existing_pr_comment(
                    context,
                    github_token=github_token,
                )
                previous_scan = extract_comment_metadata(
                    str(existing_comment.get("body") or "")
                ) if existing_comment else None
                comment_result = upsert_pr_comment(
                    context,
                    build_pr_comment(
                        share_summary,
                        current_report=persisted_report,
                        previous_scan=previous_scan,
                        head_sha=str(context.get("head_sha") or context.get("sha") or ""),
                    ),
                    github_token=github_token,
                    existing_comment=existing_comment,
                )
            except ActionRuntimeError as exc:
                extra_summary_sections.append(_comment_warning_summary(str(exc)))
            else:
                write_github_output("comment-id", comment_result["id"], env)
                write_github_output("comment-url", comment_result["html_url"], env)
                write_github_output("comment-updated", comment_result["updated"], env)
        else:
            extra_summary_sections.append(
                _comment_warning_summary(
                    "GITHUB_TOKEN missing or not granted write access for pull request comments."
                )
            )
    summary_sections = [
        _success_summary(
            analysis_payload=payload,
            changed_files=changed_files,
            uploaded_files=upload_files,
            skipped_files=skipped_files,
        )
    ]
    summary_sections.extend(extra_summary_sections)
    write_step_summary(
        "\n\n".join(summary_sections),
        env,
    )
    return 0


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        raise SystemExit(run_action(args))
    except ActionRuntimeError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
