#!/usr/bin/env python3
"""CloudSentinel API server.

Exposes a single streaming endpoint that the frontend calls.
Runs the full scan → parse → AI analysis pipeline and streams
progress events back via Server-Sent Events (SSE).

Start with:
    uvicorn api:app --host 0.0.0.0 --port 8000 --reload

Endpoint:
    POST /scan
    Body: { "services": ["ec2", "s3"], "region": "us-east-1",
            "access_key": "AKIA...", "secret_key": "..." }

SSE events streamed back:
    { "type": "progress", "service": "ec2", "message": "Scanning EC2..." }
    { "type": "result",   "service": "ec2", "analysis": { ...findings JSON... } }
    { "type": "error",    "service": "ec2", "message": "..." }
    { "type": "done" }
"""

from __future__ import annotations

import asyncio
import json
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator

from cloudsentinel import SUPPORTED_SERVICES, run_pipeline


app = FastAPI(title="CloudSentinel API", version="1.0.0")

# Allow all origins so any frontend (Lovable, localhost, etc.) can connect.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["*"],
)


# ── Request model ─────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    services: list[str]
    region: str
    access_key: str
    secret_key: str
    session_token: str | None = None

    @field_validator("services")
    @classmethod
    def validate_services(cls, v: list[str]) -> list[str]:
        invalid = set(v) - SUPPORTED_SERVICES
        if invalid:
            raise ValueError(
                f"Unsupported services: {sorted(invalid)}. "
                f"Supported: {sorted(SUPPORTED_SERVICES)}"
            )
        if not v:
            raise ValueError("At least one service must be specified.")
        return v


# ── SSE helper ────────────────────────────────────────────────────────────────

def _sse(payload: dict) -> str:
    """Format a dict as a single SSE data line."""
    return f"data: {json.dumps(payload)}\n\n"


# ── Streaming scan endpoint ───────────────────────────────────────────────────

@app.post("/scan")
async def scan(request: ScanRequest) -> StreamingResponse:
    """
    Run one or more service scans sequentially and stream SSE events.

    The frontend opens this as an EventSource-compatible stream and
    receives progress updates + final analysis for each service.
    """

    async def generate() -> AsyncGenerator[str, None]:
        loop = asyncio.get_event_loop()

        for service in request.services:

            # ── Progress bridge ───────────────────────────────────────────
            # run_pipeline() is synchronous and runs in a thread pool.
            # on_progress() is called from that thread and needs to push
            # messages into the async generator. We use a Queue as the bridge.
            progress_queue: asyncio.Queue[str] = asyncio.Queue()

            def on_progress(message: str) -> None:
                loop.call_soon_threadsafe(progress_queue.put_nowait, message)

            # ── Start pipeline in thread pool ─────────────────────────────
            future = loop.run_in_executor(
                None,
                lambda svc=service: run_pipeline(
                    service=svc,
                    region=request.region,
                    access_key=request.access_key,
                    secret_key=request.secret_key,
                    session_token=request.session_token,
                    on_progress=on_progress,
                ),
            )

            # ── Drain progress queue until the pipeline finishes ──────────
            while not future.done():
                try:
                    message = await asyncio.wait_for(
                        progress_queue.get(), timeout=0.3
                    )
                    yield _sse({"type": "progress", "service": service, "message": message})
                except asyncio.TimeoutError:
                    pass  # pipeline still running, loop again

            # Flush any remaining progress messages
            while not progress_queue.empty():
                message = progress_queue.get_nowait()
                yield _sse({"type": "progress", "service": service, "message": message})

            # ── Emit result or error ──────────────────────────────────────
            try:
                result_json_str = await future
                analysis = json.loads(result_json_str)
                yield _sse({"type": "result", "service": service, "analysis": analysis})
            except Exception as exc:
                yield _sse({"type": "error", "service": service, "message": str(exc)})

        yield _sse({"type": "done"})

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",   # disable nginx buffering if behind a proxy
        },
    )


# ── Health check ──────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "supported_services": sorted(SUPPORTED_SERVICES)}
