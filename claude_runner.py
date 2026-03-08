#!/usr/bin/env python3
"""CloudSentinel → Claude Code CLI bridge.

Builds the analysis prompt from a scanner output file and pipes it directly
to the `claude` CLI in non-interactive print mode. No API key required.

Usage:
    python claude_runner.py --scan-file path/to/scan.txt
    python claude_runner.py --scan-file path/to/scan.txt --output-file result.json
    python claude_runner.py --scan-file path/to/scan.txt --model opus
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from analysis_bridge import build_analysis_bundle
from scan_parser import parse_scan_file


BASE_DIR = Path(__file__).resolve().parent


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Pipe a CloudSentinel scan to Claude Code CLI and return structured JSON."
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
        "--model",
        default=None,
        help="Claude model alias or ID (e.g. 'sonnet', 'opus', 'claude-sonnet-4-6'). "
             "Defaults to whatever Claude Code CLI is configured to use.",
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


def build_claude_cmd(*, model: str | None) -> list[str]:
    """Build the claude CLI command for non-interactive print mode."""
    cmd = [
        "claude",
        "--print",
        "--output-format", "text",
        # Disable all tools — we only want a text/JSON response, no file edits.
        "--tools", "",
        # Run from project dir so CLAUDE.md is loaded automatically.
    ]
    if model:
        cmd += ["--model", model]
    return cmd


def extract_json_from_response(text: str) -> str:
    """
    Claude may wrap the JSON in markdown fences even in print mode.
    Strip them if present and return clean JSON text.
    """
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        # Drop opening fence (e.g. ```json) and closing fence
        inner_lines = []
        in_block = False
        for line in lines:
            if line.startswith("```") and not in_block:
                in_block = True
                continue
            if line.startswith("```") and in_block:
                break
            if in_block:
                inner_lines.append(line)
        return "\n".join(inner_lines).strip()
    return stripped


def run_claude(user_prompt: str, *, cmd: list[str]) -> str:
    """Send user_prompt to claude CLI via stdin and return stdout."""
    try:
        result = subprocess.run(
            cmd,
            input=user_prompt,
            capture_output=True,
            text=True,
            encoding="utf-8",
            cwd=str(BASE_DIR),  # Run from project dir so CLAUDE.md is picked up
        )
    except FileNotFoundError:
        print(
            "[ERROR] 'claude' command not found. "
            "Make sure Claude Code CLI is installed and on your PATH.",
            file=sys.stderr,
        )
        sys.exit(1)

    if result.returncode != 0:
        print(
            f"[ERROR] Claude CLI exited with code {result.returncode}",
            file=sys.stderr,
        )
        if result.stderr.strip():
            print(result.stderr.strip(), file=sys.stderr)
        sys.exit(result.returncode)

    return result.stdout


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

    # ── 3. Build and run the claude CLI command ───────────────────────────────
    cmd = build_claude_cmd(model=args.model)
    print(f"[INFO] Running: {' '.join(cmd)}", file=sys.stderr)

    raw_output = run_claude(user_prompt, cmd=cmd)

    # ── 4. Clean up the response and validate JSON ────────────────────────────
    clean_output = extract_json_from_response(raw_output)

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
