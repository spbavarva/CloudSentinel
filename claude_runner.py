#!/usr/bin/env python3
"""CloudSentinel CLI bridge for Codex or Claude.

Builds the analysis prompt from a scanner output file and pipes it directly
to the configured AI CLI in non-interactive mode. No API key wiring is needed
inside this script as long as the selected CLI is already authenticated.

Usage:
    python claude_runner.py --scan-file path/to/scan.txt
    python claude_runner.py --scan-file path/to/scan.txt --output-file result.json
    python claude_runner.py --scan-file path/to/scan.txt --provider codex
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from analysis_bridge import build_analysis_bundle
from llm_runner import (
    SUPPORTED_LLM_PROVIDERS,
    extract_json_from_response,
    run_llm,
)
from scan_parser import parse_scan_file


BASE_DIR = Path(__file__).resolve().parent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Pipe a CloudSentinel scan to Codex or Claude and return structured JSON."
    )
    parser.add_argument(
        "--scan-file",
        required=True,
        help="Path to the scanner output .txt file.",
    )
    parser.add_argument(
        "--output-file",
        help="Write the analysis JSON to this file instead of stdout.",
    )
    parser.add_argument(
        "--provider",
        default="auto",
        choices=sorted(SUPPORTED_LLM_PROVIDERS),
        help="LLM provider to use. 'auto' prefers Codex, then Claude.",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Optional provider-specific model name. "
             "Defaults to the selected CLI's configured default.",
    )
    parser.add_argument(
        "--include-raw-text",
        action="store_true",
        help="Include full raw scan text in the prompt payload sent to Claude.",
    )
    parser.add_argument(
        "--include-raw-command-bodies",
        action="store_true",
        help="Include raw command bodies in the prompt payload sent to Claude.",
    )
    return parser.parse_args()
def write_result(content: str, output_file: str | None) -> None:
    if output_file:
        Path(output_file).write_text(content + "\n", encoding="utf-8")
        print(f"[OK] Analysis written to: {output_file}", file=sys.stderr)
    else:
        print(content)


def main() -> int:
    args = parse_args()

    # ── 1. Parse the scan file ────────────────────────────────────────────────
    scan_path = Path(args.scan_file).resolve()
    if not scan_path.exists():
        print(f"[ERROR] Scan file not found: {scan_path}", file=sys.stderr)
        return 1

    print(f"[INFO] Parsing scan file: {scan_path}", file=sys.stderr)
    parsed_scan = parse_scan_file(scan_path)
    print(
        f"[INFO] Primary service: {parsed_scan.primary_service}  |  "
        f"Commands: {parsed_scan.total_commands}  |  "
        f"Errors: {parsed_scan.total_error_commands}",
        file=sys.stderr,
    )

    # ── 2. Build the analysis bundle (prompt assembly) ────────────────────────
    bundle = build_analysis_bundle(
        parsed_scan,
        scan_source=str(scan_path),
        include_raw_text=args.include_raw_text,
        include_raw_command_bodies=args.include_raw_command_bodies,
    )
    user_prompt = bundle["llm_request"]["user_prompt"]
    print(f"[INFO] Prompt size: {len(user_prompt):,} characters", file=sys.stderr)

    # ── 3. Run the selected LLM provider ──────────────────────────────────────
    invocation = run_llm(
        system_prompt=bundle["llm_request"]["system_prompt"],
        user_prompt=user_prompt,
        provider=args.provider,
        model=args.model,
        cwd=BASE_DIR,
    )
    print(f"[INFO] Provider: {invocation.provider}", file=sys.stderr)

    # ── 4. Clean up the response and validate JSON ────────────────────────────
    clean_output = extract_json_from_response(invocation.output)

    try:
        parsed = json.loads(clean_output)
        # Re-serialize with consistent formatting
        final_output = json.dumps(parsed, indent=2, sort_keys=False)
    except json.JSONDecodeError as exc:
        print(
            f"[WARN] Claude response is not valid JSON ({exc}). "
            "Writing raw output instead.",
            file=sys.stderr,
        )
        final_output = clean_output

    # ── 5. Write result ───────────────────────────────────────────────────────
    write_result(final_output, args.output_file)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
