from __future__ import annotations

import argparse
import json
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


SECTION_HEADER_RE = re.compile(r"^=== (?P<title>.+?) ===$", re.MULTILINE)
COMMAND_HEADER_RE = re.compile(r"^--- Command: (?P<label>.+?) ---$", re.MULTILINE)


@dataclass(slots=True)
class ParsedCommand:
    label: str
    raw_body: str
    payload: Any | None
    error: bool
    exit_code: int | None
    started_at: str | None
    command: str | None

    def to_dict(self, *, include_raw_body: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "label": self.label,
            "error": self.error,
            "exit_code": self.exit_code,
            "started_at": self.started_at,
            "command": self.command,
            "payload": self.payload,
        }
        if include_raw_body:
            data["raw_body"] = self.raw_body
        return data


@dataclass(slots=True)
class ParsedSection:
    title: str
    kind: str
    service: str
    commands: list[ParsedCommand]
    raw_body: str

    def to_dict(self, *, include_raw_body: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "title": self.title,
            "kind": self.kind,
            "service": self.service,
            "command_count": len(self.commands),
            "commands": [
                command.to_dict(include_raw_body=include_raw_body)
                for command in self.commands
            ],
        }
        if include_raw_body:
            data["raw_body"] = self.raw_body
        return data


@dataclass(slots=True)
class ParsedScan:
    primary_service: str
    sections: list[ParsedSection]
    raw_text: str

    @property
    def dependency_services(self) -> list[str]:
        seen: set[str] = set()
        ordered: list[str] = []
        for section in self.sections:
            if section.kind != "dependency":
                continue
            if section.service in seen:
                continue
            seen.add(section.service)
            ordered.append(section.service)
        return ordered

    @property
    def total_commands(self) -> int:
        return sum(len(section.commands) for section in self.sections)

    @property
    def total_error_commands(self) -> int:
        return sum(
            1
            for section in self.sections
            for command in section.commands
            if command.error
        )

    @property
    def scan_timestamp(self) -> str | None:
        timestamps: list[datetime] = []
        raw_map: dict[datetime, str] = {}
        for section in self.sections:
            for command in section.commands:
                if not command.started_at:
                    continue
                try:
                    parsed = datetime.fromisoformat(
                        command.started_at.replace("Z", "+00:00")
                    )
                except ValueError:
                    continue
                timestamps.append(parsed)
                raw_map[parsed] = command.started_at
        if not timestamps:
            return None
        earliest = min(timestamps)
        return raw_map[earliest]

    def to_dict(
        self,
        *,
        include_raw_text: bool = False,
        include_raw_bodies: bool = False,
    ) -> dict[str, Any]:
        data: dict[str, Any] = {
            "primary_service": self.primary_service,
            "scan_timestamp": self.scan_timestamp,
            "section_count": len(self.sections),
            "total_commands": self.total_commands,
            "total_error_commands": self.total_error_commands,
            "dependency_services": self.dependency_services,
            "sections": [
                section.to_dict(include_raw_body=include_raw_bodies)
                for section in self.sections
            ],
        }
        if include_raw_text:
            data["raw_text"] = self.raw_text
        return data


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Parse CloudSentinel scanner output into structured JSON."
    )
    parser.add_argument("--scan-file", required=True, help="Path to scanner output text.")
    parser.add_argument(
        "--output-file",
        help="Optional path to write parsed JSON output.",
    )
    parser.add_argument(
        "--include-raw-text",
        action="store_true",
        help="Include the full raw scan text in the JSON output.",
    )
    parser.add_argument(
        "--include-raw-command-bodies",
        action="store_true",
        help="Include each raw command body in the JSON output.",
    )
    return parser.parse_args()


def normalize_service_name(value: str) -> str:
    return value.strip().lower().replace(" ", "_")


def try_parse_json_block(block: str) -> Any | None:
    trimmed = block.strip()
    if not trimmed:
        return None
    try:
        return json.loads(trimmed)
    except json.JSONDecodeError:
        return None


def parse_command_block(label: str, body: str) -> ParsedCommand:
    payload = try_parse_json_block(body)
    error = False
    exit_code: int | None = None
    started_at: str | None = None
    command_string: str | None = None

    if isinstance(payload, dict):
        error = payload.get("error") is True
        raw_exit_code = payload.get("exit_code")
        raw_started_at = payload.get("started_at")
        raw_command = payload.get("command")
        if isinstance(raw_exit_code, int):
            exit_code = raw_exit_code
        if isinstance(raw_started_at, str):
            started_at = raw_started_at
        if isinstance(raw_command, str):
            command_string = raw_command

    return ParsedCommand(
        label=label,
        raw_body=body.strip(),
        payload=payload,
        error=error,
        exit_code=exit_code,
        started_at=started_at,
        command=command_string,
    )


def parse_section_title(title: str) -> tuple[str, str]:
    if title.startswith("PRIMARY SERVICE: "):
        return "primary", normalize_service_name(title.split(": ", 1)[1])
    if title.startswith("DEPENDENCY CONTEXT: "):
        return "dependency", normalize_service_name(title.split(": ", 1)[1])
    return "unknown", normalize_service_name(title)


def parse_section_body(body: str) -> tuple[list[ParsedCommand], str]:
    command_matches = list(COMMAND_HEADER_RE.finditer(body))
    if not command_matches:
        return [], body.strip()

    commands: list[ParsedCommand] = []
    for index, match in enumerate(command_matches):
        next_start = (
            command_matches[index + 1].start()
            if index + 1 < len(command_matches)
            else len(body)
        )
        label = match.group("label").strip()
        command_body = body[match.end():next_start].strip()
        commands.append(parse_command_block(label, command_body))
    return commands, body.strip()


def parse_scan_text(text: str) -> ParsedScan:
    section_matches = list(SECTION_HEADER_RE.finditer(text))
    if not section_matches:
        raise ValueError("No CloudSentinel section headers were found in the scan text.")

    sections: list[ParsedSection] = []
    primary_service: str | None = None

    for index, match in enumerate(section_matches):
        next_start = (
            section_matches[index + 1].start()
            if index + 1 < len(section_matches)
            else len(text)
        )
        title = match.group("title").strip()
        kind, service = parse_section_title(title)
        section_body = text[match.end():next_start].strip()
        commands, raw_body = parse_section_body(section_body)
        section = ParsedSection(
            title=title,
            kind=kind,
            service=service,
            commands=commands,
            raw_body=raw_body,
        )
        sections.append(section)
        if kind == "primary" and primary_service is None:
            primary_service = service

    if not primary_service:
        raise ValueError("Scan text does not contain a PRIMARY SERVICE section.")

    return ParsedScan(primary_service=primary_service, sections=sections, raw_text=text)


def parse_scan_file(path: str | Path) -> ParsedScan:
    text = Path(path).read_text(encoding="utf-8")
    return parse_scan_text(text)


def write_output(payload: dict[str, Any], output_file: str | None) -> None:
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    if output_file:
        Path(output_file).write_text(rendered + "\n", encoding="utf-8")
        return
    print(rendered)


def main() -> int:
    args = parse_args()
    parsed_scan = parse_scan_file(args.scan_file)
    write_output(
        parsed_scan.to_dict(
            include_raw_text=args.include_raw_text,
            include_raw_bodies=args.include_raw_command_bodies,
        ),
        args.output_file,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
