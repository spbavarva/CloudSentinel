#!/usr/bin/env python3
"""CloudSentinel — end-to-end pipeline.

Runs a scanner, parses the output, builds the analysis prompt,
and pipes it to the Claude Code CLI. No API key needed.

Importable by api.py:
    from cloudsentinel import run_pipeline
"""

from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
import threading
from argparse import Namespace
from contextlib import contextmanager
from pathlib import Path
from typing import Callable

from analysis_bridge import build_analysis_bundle
from scan_parser import parse_scan_text


BASE_DIR = Path(__file__).resolve().parent

SUPPORTED_SERVICES = {"ec2", "s3", "iam", "vpc"}

# Only one scan runs at a time — prevents concurrent env-var conflicts.
_scan_lock = threading.Lock()


# ── AWS credential context ────────────────────────────────────────────────────

@contextmanager
def _aws_env(*, access_key: str, secret_key: str, region: str, session_token: str | None = None):
    """Temporarily inject AWS credentials into the process environment.

    AWS CLI subprocesses spawned inside this block inherit these variables.
    Original values are restored on exit, even if an exception is raised.
    """
    inject = {
        "AWS_ACCESS_KEY_ID": access_key,
        "AWS_SECRET_ACCESS_KEY": secret_key,
        "AWS_DEFAULT_REGION": region,
    }
    if session_token:
        inject["AWS_SESSION_TOKEN"] = session_token

    previous = {k: os.environ.get(k) for k in inject}
    os.environ.update(inject)
    try:
        yield
    finally:
        for key, old_val in previous.items():
            if old_val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old_val


# ── Scanner loader ────────────────────────────────────────────────────────────

def _load_scanner(service: str) -> Callable[[Namespace], str]:
    if service not in SUPPORTED_SERVICES:
        raise ValueError(f"Unsupported service: {service}. Choose from: {sorted(SUPPORTED_SERVICES)}")
    module = importlib.import_module(f"{service}_scanner")
    return module.build_scan_output  # type: ignore[no-any-return]


def _scanner_args(*, region: str) -> Namespace:
    """Build the Namespace that every scanner's build_scan_output() expects."""
    return Namespace(
        region=region,
        profile=None,
        timeout_seconds=60,
        output_file=None,
    )


# ── Claude CLI ────────────────────────────────────────────────────────────────

def _call_claude(user_prompt: str) -> str:
    cmd = ["claude", "--print", "--output-format", "text", "--tools", ""]
    try:
        result = subprocess.run(
            cmd,
            input=user_prompt,
            capture_output=True,
            text=True,
            encoding="utf-8",
            cwd=str(BASE_DIR),
        )
    except FileNotFoundError:
        raise RuntimeError(
            "'claude' command not found. "
            "Make sure Claude Code CLI is installed and on your PATH."
        )
    if result.returncode != 0:
        raise RuntimeError(
            f"Claude CLI exited with code {result.returncode}.\n"
            + (result.stderr.strip() or "(no stderr)")
        )
    return result.stdout


def _strip_fences(text: str) -> str:
    """Remove markdown code fences if Claude wrapped the JSON in them."""
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped
    lines = stripped.splitlines()
    inner: list[str] = []
    in_block = False
    for line in lines:
        if line.startswith("```") and not in_block:
            in_block = True
            continue
        if line.startswith("```") and in_block:
            break
        if in_block:
            inner.append(line)
    return "\n".join(inner).strip()


# ── Main pipeline ─────────────────────────────────────────────────────────────

def run_pipeline(
    *,
    service: str,
    region: str,
    access_key: str,
    secret_key: str,
    session_token: str | None = None,
    on_progress: Callable[[str], None] | None = None,
) -> str:
    """
    Full CloudSentinel pipeline for one service.

    Blocks the calling thread. Designed to be run inside a thread pool
    when called from the async API server.

    Returns the final analysis as a JSON string.
    Calls on_progress(message) at each major step so callers can stream
    progress events to the frontend.
    """

    def progress(msg: str) -> None:
        if on_progress:
            on_progress(msg)

    with _scan_lock:
        with _aws_env(
            access_key=access_key,
            secret_key=secret_key,
            region=region,
            session_token=session_token,
        ):
            # 1. Run scanner
            progress(f"Scanning {service.upper()} resources in {region}...")
            scanner_fn = _load_scanner(service)
            scan_text = scanner_fn(_scanner_args(region=region))

            if not scan_text.strip():
                raise RuntimeError(
                    "Scanner returned empty output. "
                    "Check that your AWS credentials are valid and have sufficient permissions."
                )

            # 2. Parse
            progress("Parsing scan output...")
            parsed_scan = parse_scan_text(scan_text)

            # 3. Build analysis prompt (service skill is auto-selected from parsed_scan.primary_service)
            progress("Building analysis prompt...")
            bundle = build_analysis_bundle(
                parsed_scan,
                scan_source=f"{service}:{region}",
            )
            user_prompt = bundle["llm_request"]["user_prompt"]

            # 4. Send to Claude
            progress("AI is analyzing findings — this may take a minute...")
            raw_output = _call_claude(user_prompt)

    # 5. Clean and validate JSON
    clean = _strip_fences(raw_output)
    try:
        parsed = json.loads(clean)
        return json.dumps(parsed, indent=2, sort_keys=False)
    except json.JSONDecodeError:
        # Return raw if Claude didn't produce valid JSON for some reason
        return clean
