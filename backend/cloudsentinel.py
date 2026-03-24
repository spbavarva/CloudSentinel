#!/usr/bin/env python3
"""CloudSentinel — end-to-end pipeline.

Runs a scanner, parses the output, builds the analysis prompt,
and pipes it to the configured AI CLI. No API key wiring is needed here
as long as the selected CLI is already authenticated.

Importable by api.py:
    from cloudsentinel import run_pipeline
"""

from __future__ import annotations

import importlib
import json
from argparse import Namespace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from analysis_bridge import build_analysis_bundle
from credential_utils import sanitize_error
from llm_runner import extract_json_from_response, resolve_llm_provider, run_llm
from scan_parser import parse_scan_text
from scan_cancellation import ScanCancellationRegistry, ScanCancelledError


BASE_DIR = Path(__file__).resolve().parent          # backend/
PROJECT_ROOT = BASE_DIR.parent                       # CloudSentinel/
SCANNERS_DIR = BASE_DIR / "scanners"

SUPPORTED_SERVICES = {"ec2", "s3", "iam", "vpc", "rds", "ebs", "ami", "elb"}

# Ensure scanners/ is importable as top-level modules (e.g. ec2_scanner).
import sys as _sys
_scanners_str = str(SCANNERS_DIR)
if _scanners_str not in _sys.path:
    _sys.path.insert(0, _scanners_str)

def _build_aws_env(
    *,
    access_key: str,
    secret_key: str,
    region: str,
    session_token: str | None = None,
) -> dict[str, str]:
    env = {
        "AWS_ACCESS_KEY_ID": access_key,
        "AWS_SECRET_ACCESS_KEY": secret_key,
        "AWS_DEFAULT_REGION": region,
    }
    if session_token:
        env["AWS_SESSION_TOKEN"] = session_token
    return env


# ── Scanner loader ────────────────────────────────────────────────────────────

def _load_scanner(service: str) -> Callable[[Namespace], str]:
    if service not in SUPPORTED_SERVICES:
        raise ValueError(f"Unsupported service: {service}. Choose from: {sorted(SUPPORTED_SERVICES)}")
    module = importlib.import_module(f"{service}_scanner")
    return module.build_scan_output  # type: ignore[no-any-return]


def _scanner_args(
    *,
    region: str,
    profile: str | None = None,
    should_cancel: Callable[[], bool] | None = None,
    on_progress: Callable[[str | dict[str, Any]], None] | None = None,
    aws_env: dict[str, str] | None = None,
    session_id: str | None = None,
    cancellation_registry: ScanCancellationRegistry | None = None,
) -> Namespace:
    """Build the Namespace that every scanner's build_scan_output() expects."""
    return Namespace(
        region=region,
        profile=profile,
        timeout_seconds=60,
        output_file=None,
        should_cancel=should_cancel,
        on_progress=on_progress,
        aws_env=aws_env,
        session_id=session_id,
        cancellation_registry=cancellation_registry,
    )


def _raise_if_cancelled(should_cancel: Callable[[], bool] | None, context: str) -> None:
    if should_cancel and should_cancel():
        raise ScanCancelledError(f"Scan cancelled by user during {context}.")


def _emit_progress(
    progress: Callable[[str | dict[str, Any]], None],
    *,
    message: str,
    phase: str,
    progress_kind: str = "phase",
    detail: str | None = None,
    command_label: str | None = None,
    aws_service: str | None = None,
    command_name: str | None = None,
) -> None:
    payload: dict[str, Any] = {
        "message": message,
        "phase": phase,
        "progress_kind": progress_kind,
        "started_at": datetime.now(timezone.utc).isoformat(),
    }
    if detail:
        payload["detail"] = detail
    if command_label:
        payload["command_label"] = command_label
    if aws_service:
        payload["aws_service"] = aws_service
    if command_name:
        payload["command_name"] = command_name
    progress(payload)


# ── Main pipeline ─────────────────────────────────────────────────────────────

def run_pipeline(
    *,
    service: str,
    region: str,
    access_key: str | None = None,
    secret_key: str | None = None,
    session_token: str | None = None,
    profile: str | None = None,
    llm_provider: str | None = None,
    on_progress: Callable[[str | dict[str, Any]], None] | None = None,
    should_cancel: Callable[[], bool] | None = None,
    session_id: str | None = None,
    cancellation_registry: ScanCancellationRegistry | None = None,
) -> str:
    """
    Full CloudSentinel pipeline for one service.

    Blocks the calling thread. Designed to be run inside a thread pool
    when called from the async API server.

    Supports two credential modes:
    - **Key mode**: pass ``access_key`` and ``secret_key`` (+ optional ``session_token``).
    - **Profile mode**: pass ``profile`` name — credentials are read from ``~/.aws/credentials``.

    Returns the final analysis as a JSON string.
    Calls on_progress(message) at each major step so callers can stream
    progress events to the frontend.
    """
    use_profile = bool(profile)

    if not use_profile and (not access_key or not secret_key):
        raise ValueError("Either 'profile' or both 'access_key' and 'secret_key' must be provided.")

    # Collect credential strings for sanitization of any errors.
    _redact_keys: list[str] = []
    if access_key:
        _redact_keys.append(access_key)
    if secret_key:
        _redact_keys.append(secret_key)
    if session_token:
        _redact_keys.append(session_token)

    def progress(msg: str | dict[str, Any]) -> None:
        if on_progress:
            on_progress(msg)

    try:
        _raise_if_cancelled(should_cancel, "scan startup")
        aws_env = None
        if not use_profile:
            assert access_key is not None and secret_key is not None
            aws_env = _build_aws_env(
                access_key=access_key,
                secret_key=secret_key,
                region=region,
                session_token=session_token,
            )

        return _run_scan_and_analyze(
            service=service,
            region=region,
            profile=profile if use_profile else None,
            aws_env=aws_env,
            progress=progress,
            llm_provider=llm_provider,
            should_cancel=should_cancel,
            session_id=session_id,
            cancellation_registry=cancellation_registry,
        )
    except Exception as exc:
        # Sanitize credentials from any error that bubbles up.
        safe_msg = sanitize_error(str(exc), _redact_keys)
        if safe_msg != str(exc):
            raise RuntimeError(safe_msg) from None
        raise


def _run_scan_and_analyze(
    *,
    service: str,
    region: str,
    profile: str | None,
    aws_env: dict[str, str] | None,
    progress: Callable[[str | dict[str, Any]], None],
    llm_provider: str | None,
    should_cancel: Callable[[], bool] | None,
    session_id: str | None,
    cancellation_registry: ScanCancellationRegistry | None,
) -> str:
    """Inner pipeline logic shared by key-mode and profile-mode."""

    # 1. Run scanner
    _raise_if_cancelled(should_cancel, "scanner startup")
    _emit_progress(
        progress,
        message=f"Scanning {service.upper()} resources in {region}...",
        phase="scan",
        detail="Collecting AWS CLI evidence",
    )
    scanner_fn = _load_scanner(service)
    scan_text = scanner_fn(
        _scanner_args(
            region=region,
            profile=profile,
            should_cancel=should_cancel,
            on_progress=progress,
            aws_env=aws_env,
            session_id=session_id,
            cancellation_registry=cancellation_registry,
        )
    )

    if not scan_text.strip():
        raise RuntimeError(
            "Scanner returned empty output. "
            "Check that your AWS credentials are valid and have sufficient permissions."
        )

    # 2. Parse
    _raise_if_cancelled(should_cancel, "scan parsing")
    _emit_progress(
        progress,
        message="Parsing scan output...",
        phase="parse",
        detail="Transforming raw CLI output into structured evidence",
    )
    parsed_scan = parse_scan_text(scan_text)

    # 3. Build analysis prompt (service skill is auto-selected from parsed_scan.primary_service)
    _raise_if_cancelled(should_cancel, "analysis prompt build")
    _emit_progress(
        progress,
        message="Building analysis prompt...",
        phase="prompt",
        detail="Combining scan evidence with service-specific skills",
    )
    bundle = build_analysis_bundle(
        parsed_scan,
        scan_source=f"{service}:{region}",
    )
    resolved_provider = resolve_llm_provider(llm_provider)
    user_prompt = bundle["llm_request"]["user_prompt"]

    # Provider-specific contract selection:
    # - Claude: CLAUDE.md passed explicitly via --system-prompt flag
    # - Codex: AGENTS.md auto-loaded from cwd (no embedding needed)
    system_prompt: str | None = None
    if resolved_provider == "claude":
        claude_md = PROJECT_ROOT / "CLAUDE.md"
        if claude_md.exists():
            system_prompt = claude_md.read_text(encoding="utf-8")

    # 4. Send to the selected provider
    _raise_if_cancelled(should_cancel, "AI analysis")
    _emit_progress(
        progress,
        message=f"{resolved_provider.upper()} is analyzing findings — this may take a minute...",
        phase="analysis",
        detail=f"Running {resolved_provider.upper()} on the prepared evidence bundle",
    )
    raw_output = run_llm(
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        provider=resolved_provider,
        cwd=PROJECT_ROOT,
        should_cancel=should_cancel,
        on_progress=progress,
        session_id=session_id,
        cancellation_registry=cancellation_registry,
    ).output

    # 5. Clean and validate JSON
    _raise_if_cancelled(should_cancel, "result validation")
    _emit_progress(
        progress,
        message="Validating analysis output...",
        phase="validate",
        detail="Checking the final JSON response",
    )
    clean = extract_json_from_response(raw_output)
    try:
        parsed = json.loads(clean)
        return json.dumps(parsed, indent=2, sort_keys=False)
    except json.JSONDecodeError:
        return clean
