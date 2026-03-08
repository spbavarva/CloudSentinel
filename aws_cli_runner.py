from __future__ import annotations

import json
import shlex
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence


@dataclass(slots=True)
class CommandResult:
    label: str
    command: list[str]
    started_at: str
    duration_ms: int
    exit_code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit_code == 0

    @property
    def command_string(self) -> str:
        return " ".join(shlex.quote(part) for part in self.command)

    def parsed_stdout(self) -> object | None:
        if not self.stdout.strip():
            return None
        try:
            return json.loads(self.stdout)
        except json.JSONDecodeError:
            return None


class AWSCLIRunner:
    def __init__(
        self,
        *,
        region: str,
        profile: str | None = None,
        timeout_seconds: int = 60,
    ) -> None:
        self.region = region
        self.profile = profile
        self.timeout_seconds = timeout_seconds

    def run(
        self,
        service_args: Sequence[str],
        *,
        label: str,
        include_region: bool = True,
    ) -> CommandResult:
        command = ["aws"]
        if self.profile:
            command.extend(["--profile", self.profile])
        if include_region and self.region:
            command.extend(["--region", self.region])
        command.extend(service_args)
        if "--output" not in service_args:
            command.extend(["--output", "json"])
        if "--no-cli-pager" not in service_args:
            command.append("--no-cli-pager")

        start = time.perf_counter()
        started_at = datetime.now(timezone.utc).isoformat()
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=self.timeout_seconds,
            )
            duration_ms = int((time.perf_counter() - start) * 1000)
            return CommandResult(
                label=label,
                command=command,
                started_at=started_at,
                duration_ms=duration_ms,
                exit_code=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
            )
        except FileNotFoundError as exc:
            duration_ms = int((time.perf_counter() - start) * 1000)
            return CommandResult(
                label=label,
                command=command,
                started_at=started_at,
                duration_ms=duration_ms,
                exit_code=127,
                stdout="",
                stderr=str(exc),
            )
        except subprocess.TimeoutExpired as exc:
            duration_ms = int((time.perf_counter() - start) * 1000)
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", errors="replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", errors="replace")
            timeout_note = f"Command exceeded timeout of {self.timeout_seconds} seconds."
            stderr = f"{stderr}\n{timeout_note}".strip()
            return CommandResult(
                label=label,
                command=command,
                started_at=started_at,
                duration_ms=duration_ms,
                exit_code=124,
                stdout=stdout,
                stderr=stderr,
            )


def render_command_block(result: CommandResult) -> str:
    lines = [f"--- Command: {result.label} ---"]

    if result.ok:
        parsed = result.parsed_stdout()
        if parsed is not None:
            lines.append(json.dumps(parsed, indent=2, sort_keys=True))
        elif result.stdout.strip():
            lines.append(result.stdout.strip())
        else:
            lines.append(
                json.dumps(
                    {
                        "duration_ms": result.duration_ms,
                        "exit_code": result.exit_code,
                        "started_at": result.started_at,
                        "status": "ok",
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
        return "\n".join(lines)

    payload: dict[str, object] = {
        "command": result.command_string,
        "duration_ms": result.duration_ms,
        "error": True,
        "exit_code": result.exit_code,
        "started_at": result.started_at,
    }
    if result.stderr.strip():
        payload["stderr"] = result.stderr.strip()
    parsed = result.parsed_stdout()
    if parsed is not None:
        payload["stdout"] = parsed
    elif result.stdout.strip():
        payload["stdout"] = result.stdout.strip()
    lines.append(json.dumps(payload, indent=2, sort_keys=True))
    return "\n".join(lines)


def render_section(title: str, results: Iterable[CommandResult]) -> str:
    rendered_results = [render_command_block(result) for result in results]
    if not rendered_results:
        return ""
    return f"=== {title} ===\n" + "\n\n".join(rendered_results)


def write_output(text: str, output_file: str | None) -> None:
    if output_file:
        Path(output_file).write_text(text, encoding="utf-8")
        return
    print(text)
