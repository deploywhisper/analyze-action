"""Runtime helpers for the standalone DeployWhisper GitHub Action bundle."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Iterable
from urllib import error, parse, request
import uuid

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


def _multipart_body(files: list[tuple[str, bytes]]) -> tuple[bytes, str]:
    boundary = f"deploywhisper-{uuid.uuid4().hex}"
    body = bytearray()
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


def submit_analysis(
    api_url: str,
    artifacts: list[tuple[str, bytes]],
    *,
    api_token: str | None,
    trigger_type: str,
    trigger_id: str,
) -> dict:
    """POST artifacts to the existing analyses API."""
    endpoint = _resolve_analysis_endpoint(api_url)
    body, boundary = _multipart_body(artifacts)
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
    data = dict(analysis_payload.get("data") or {})
    share_summary = dict(data.get("share_summary") or {})
    persisted_report = dict(data.get("persisted_report") or {})
    report_id = persisted_report.get("id")
    report_link = (share_summary.get("json_payload") or {}).get("report_link")

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
    markdown = str(share_summary.get("markdown") or "").strip()
    if markdown:
        lines.extend(["", markdown])
    return "\n".join(lines)


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

    payload = submit_analysis(
        args.api_url,
        upload_files,
        api_token=args.api_token or None,
        trigger_type="github_pull_request",
        trigger_id=_build_trigger_id(context),
    )

    data = dict(payload.get("data") or {})
    meta = dict(payload.get("meta") or {})
    share_summary = dict(data.get("share_summary") or {})
    share_json = dict(share_summary.get("json_payload") or {})
    persisted_report = dict(data.get("persisted_report") or {})

    write_github_output("created", "true", env)
    write_github_output(
        "accepted-artifact-count",
        meta.get("accepted_artifact_count", len(upload_files)),
        env,
    )
    write_github_output("report-id", persisted_report.get("id", ""), env)
    write_github_output("report-link", share_json.get("report_link", ""), env)
    write_github_output("severity", share_summary.get("severity", ""), env)
    write_github_output("recommendation", share_summary.get("recommendation", ""), env)
    write_github_output("share-summary-json", share_json, env)
    write_github_output(
        "share-summary-markdown", share_summary.get("markdown", ""), env
    )
    write_step_summary(
        _success_summary(
            analysis_payload=payload,
            changed_files=changed_files,
            uploaded_files=upload_files,
            skipped_files=skipped_files,
        ),
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
