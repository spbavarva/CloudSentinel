from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


SUPPORTED_LLM_PROVIDERS = {"auto", "codex", "claude"}


@dataclass(slots=True)
class LLMInvocationResult:
    provider: str
    output: str


def available_llm_providers() -> list[str]:
    available: list[str] = []
    for provider in ("codex", "claude"):
        if shutil.which(provider):
            available.append(provider)
    return available


def resolve_llm_provider(provider: str | None = None) -> str:
    requested = (
        provider
        or os.environ.get("CLOUDSENTINEL_LLM_PROVIDER")
        or "auto"
    ).strip().lower()

    if requested not in SUPPORTED_LLM_PROVIDERS:
        raise ValueError(
            f"Unsupported LLM provider: {requested}. "
            f"Choose from: {sorted(SUPPORTED_LLM_PROVIDERS)}"
        )

    available = available_llm_providers()
    if requested == "auto":
        for candidate in ("codex", "claude"):
            if candidate in available:
                return candidate
        raise RuntimeError(
            "No supported AI CLI found. Install the Codex CLI or Claude CLI."
        )

    if requested not in available:
        installed = ", ".join(available) if available else "none"
        raise RuntimeError(
            f"{requested} CLI is not installed. Available providers: {installed}."
        )

    return requested


def extract_json_from_response(text: str) -> str:
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped

    lines = stripped.splitlines()
    inner_lines: list[str] = []
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


def build_codex_prompt(*, system_prompt: str, user_prompt: str) -> str:
    return (
        "Follow the CloudSentinel system contract exactly.\n\n"
        "=== SYSTEM CONTRACT ===\n"
        f"{system_prompt.strip()}\n\n"
        "=== TASK AND EVIDENCE ===\n"
        f"{user_prompt.strip()}\n\n"
        "Return valid JSON only. Do not use markdown fences."
    )


def run_claude(
    *,
    user_prompt: str,
    cwd: Path,
    model: str | None = None,
) -> str:
    cmd = ["claude", "--print", "--output-format", "text", "--tools", ""]
    if model:
        cmd += ["--model", model]

    try:
        result = subprocess.run(
            cmd,
            input=user_prompt,
            capture_output=True,
            text=True,
            encoding="utf-8",
            cwd=str(cwd),
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            "'claude' command not found. "
            "Make sure Claude Code CLI is installed and on your PATH."
        ) from exc

    if result.returncode != 0:
        raise RuntimeError(
            f"Claude CLI exited with code {result.returncode}.\n"
            + (result.stderr.strip() or "(no stderr)")
        )

    return result.stdout


def run_codex(
    *,
    system_prompt: str,
    user_prompt: str,
    cwd: Path,
    model: str | None = None,
) -> str:
    prompt = build_codex_prompt(system_prompt=system_prompt, user_prompt=user_prompt)
    with tempfile.NamedTemporaryFile(
        prefix="cloudsentinel-codex-",
        suffix=".txt",
        delete=False,
    ) as output_file:
        output_path = Path(output_file.name)

    cmd = [
        "codex",
        "exec",
        "--ephemeral",
        "--skip-git-repo-check",
        "--sandbox",
        "read-only",
        "--color",
        "never",
        "--output-last-message",
        str(output_path),
        "-",
    ]
    if model:
        cmd[2:2] = ["--model", model]

    try:
        result = subprocess.run(
            cmd,
            input=prompt,
            capture_output=True,
            text=True,
            encoding="utf-8",
            cwd=str(cwd),
        )
    except FileNotFoundError as exc:
        output_path.unlink(missing_ok=True)
        raise RuntimeError(
            "'codex' command not found. "
            "Make sure the Codex CLI is installed and on your PATH."
        ) from exc

    try:
        if result.returncode != 0:
            raise RuntimeError(
                f"Codex CLI exited with code {result.returncode}.\n"
                + (result.stderr.strip() or result.stdout.strip() or "(no output)")
            )

        if not output_path.exists():
            raise RuntimeError("Codex CLI did not write a final response file.")

        content = output_path.read_text(encoding="utf-8").strip()
        if not content:
            raise RuntimeError("Codex CLI returned an empty final response.")
        return content
    finally:
        output_path.unlink(missing_ok=True)


def run_llm(
    *,
    system_prompt: str,
    user_prompt: str,
    provider: str | None = None,
    model: str | None = None,
    cwd: Path,
) -> LLMInvocationResult:
    resolved_provider = resolve_llm_provider(provider)
    if resolved_provider == "codex":
        output = run_codex(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            cwd=cwd,
            model=model,
        )
    else:
        output = run_claude(
            user_prompt=user_prompt,
            cwd=cwd,
            model=model,
        )
    return LLMInvocationResult(provider=resolved_provider, output=output)
