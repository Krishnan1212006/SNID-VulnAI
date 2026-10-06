"""Asynchronous Scan Job Manager for VulnAI DevSecOps.

Tracks active scan executions, manages child processes, streams stdout/stderr,
computes live elapsed times, and safely cancels running tools without leaving orphans.
"""

from __future__ import annotations

import asyncio
import os
import signal
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ToolJobState:
    tool_name: str
    status: str = "queued"  # queued, running, completed, failed, cancelled, incomplete
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    start_time_monotonic: Optional[float] = None
    duration: float = 0.0
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    error_message: Optional[str] = None
    failure_stage: Optional[str] = None
    classification: str = "unverified"
    findings: List[Dict[str, Any]] = field(default_factory=list)
    process: Optional[Any] = None

    def elapsed_seconds(self) -> float:
        if self.status == "running" and self.start_time_monotonic is not None:
            return round(time.perf_counter() - self.start_time_monotonic, 2)
        return self.duration

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scanner": self.tool_name,
            "tool_name": self.tool_name,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration": self.elapsed_seconds(),
            "execution_seconds": self.elapsed_seconds(),
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "output": self.stdout or self.stderr,
            "error": self.error_message,
            "error_message": self.error_message,
            "failure_stage": self.failure_stage,
            "classification": self.classification,
            "findings_count": len(self.findings),
            "findings": self.findings,
        }


@dataclass
class ScanExecutionContext:
    scan_id: str
    target: str
    status: str = "queued"  # queued, running, completed, failed, cancelled, incomplete
    started_at: str = field(default_factory=_utc_now_iso)
    completed_at: Optional[str] = None
    start_time_monotonic: float = field(default_factory=time.perf_counter)
    duration: float = 0.0
    cancel_event: asyncio.Event = field(default_factory=asyncio.Event)
    tools: Dict[str, ToolJobState] = field(default_factory=dict)
    error_message: Optional[str] = None
    overall_progress: int = 0

    def elapsed_seconds(self) -> float:
        if self.status in {"queued", "running"}:
            return round(time.perf_counter() - self.start_time_monotonic, 2)
        return self.duration

    def to_dict(self) -> Dict[str, Any]:
        tool_dicts = {name: tool.to_dict() for name, tool in self.tools.items()}
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration": self.elapsed_seconds(),
            "progress": self.overall_progress,
            "error_message": self.error_message,
            "scanners": {name: tool.status for name, tool in self.tools.items()},
            "scanner_details": tool_dicts,
            "tools": tool_dicts,
        }


class ScanJobManager:
    """Singleton scan job manager managing active background scan jobs and processes."""

    def __init__(self) -> None:
        self._scans: Dict[str, ScanExecutionContext] = {}
        self._lock = asyncio.Lock()

    def register_scan(self, scan_id: str, target: str, tools: List[str]) -> ScanExecutionContext:
        ctx = ScanExecutionContext(
            scan_id=scan_id,
            target=target,
            status="queued",
            tools={name: ToolJobState(tool_name=name) for name in tools},
        )
        self._scans[scan_id] = ctx
        return ctx

    def get_scan(self, scan_id: str) -> Optional[ScanExecutionContext]:
        return self._scans.get(scan_id)

    def is_cancelled(self, scan_id: str) -> bool:
        ctx = self._scans.get(scan_id)
        return bool(ctx and ctx.cancel_event.is_set())

    def start_tool(self, scan_id: str, tool_name: str) -> None:
        ctx = self._scans.get(scan_id)
        if not ctx:
            return
        if ctx.status == "queued":
            ctx.status = "running"
        tool = ctx.tools.get(tool_name)
        if tool:
            tool.status = "running"
            tool.started_at = _utc_now_iso()
            tool.start_time_monotonic = time.perf_counter()

    def attach_process(self, scan_id: str, tool_name: str, process: Any) -> None:
        ctx = self._scans.get(scan_id)
        if ctx and tool_name in ctx.tools:
            ctx.tools[tool_name].process = process

    def append_output(self, scan_id: str, tool_name: str, stdout_text: Optional[str] = None, stderr_text: Optional[str] = None) -> None:
        ctx = self._scans.get(scan_id)
        if not ctx or tool_name not in ctx.tools:
            return
        tool = ctx.tools[tool_name]
        if stdout_text:
            tool.stdout += stdout_text
        if stderr_text:
            tool.stderr += stderr_text

    def complete_tool(
        self,
        scan_id: str,
        tool_name: str,
        exit_code: Optional[int],
        status: str = "completed",
        error_message: Optional[str] = None,
        findings: Optional[List[Dict[str, Any]]] = None,
        failure_stage: Optional[str] = None,
    ) -> None:
        ctx = self._scans.get(scan_id)
        if not ctx or tool_name not in ctx.tools:
            return
        tool = ctx.tools[tool_name]
        tool.status = status
        tool.exit_code = exit_code
        tool.completed_at = _utc_now_iso()
        tool.error_message = error_message
        tool.failure_stage = failure_stage
        if findings is not None:
            tool.findings = findings
        if tool.start_time_monotonic is not None:
            tool.duration = round(time.perf_counter() - tool.start_time_monotonic, 2)
        tool.process = None

    def terminate_process_safe(self, process: Any) -> None:
        """Safely terminate a process and all its child processes to prevent zombies."""
        if not process:
            return
        pid = getattr(process, "pid", None)
        if not pid:
            return

        try:
            if os.name == "nt":
                # Use taskkill /F /T on Windows to kill the process and its entire sub-tree
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(pid)],
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
            else:
                try:
                    os.killpg(os.getpgid(pid), signal.SIGTERM)
                except Exception:
                    process.terminate()
        except Exception:
            try:
                process.kill()
            except Exception:
                pass

    async def cancel_scan(self, scan_id: str) -> bool:
        """Cancel a running scan and safely terminate all underlying child processes."""
        ctx = self._scans.get(scan_id)
        if not ctx:
            return False

        ctx.cancel_event.set()
        ctx.status = "cancelled"
        ctx.completed_at = _utc_now_iso()
        ctx.duration = ctx.elapsed_seconds()

        for name, tool in ctx.tools.items():
            if tool.status in {"queued", "running"}:
                self.terminate_process_safe(tool.process)
                tool.status = "cancelled"
                tool.completed_at = _utc_now_iso()
                tool.error_message = "Scan was cancelled by the user"
                if tool.start_time_monotonic is not None:
                    tool.duration = round(time.perf_counter() - tool.start_time_monotonic, 2)
                tool.process = None

        return True

    def get_tool_states(self, scan_id: str) -> Dict[str, Dict[str, Any]]:
        ctx = self._scans.get(scan_id)
        if not ctx:
            return {}
        return {name: tool.to_dict() for name, tool in ctx.tools.items()}


# Global singleton instance
scan_job_manager = ScanJobManager()
