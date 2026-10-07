"""Small adapter for local and WSL scanner command execution."""

import asyncio
import os
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from app.core.config import settings


@dataclass
class CommandResult:
    status: str
    exit_code: Optional[int]
    stdout: bytes
    stderr: bytes
    error: Optional[str]
    duration: float


def decode_output(output: bytes) -> str:
    if b"\x00" in output and len(output) % 2 == 0:
        return output.decode("utf-16-le", errors="replace").strip("\x00\r\n \ufeff")
    return output.decode("utf-8", errors="replace").strip("\ufeff\r\n ")


class ScannerRuntime:
    """Run scanner tools locally on Linux or through the configured WSL distro."""

    @staticmethod
    def _normalize_distribution(distribution: Optional[str]) -> str:
        candidate = (distribution or settings.scanner_wsl_distribution or "kali-linux").strip()
        return candidate or "kali-linux"

    def __init__(self, distribution: Optional[str] = None):
        self.distribution = self._normalize_distribution(distribution)

    @property
    def uses_wsl(self) -> bool:
        return os.name == "nt"

    def wrap_runtime_command(self, command: Sequence[str]) -> list[str]:
        if self.uses_wsl:
            return ["wsl.exe", "-d", self.distribution, "--", *command]
        return list(command)

    async def capture_host(self, command: Sequence[str], timeout: Optional[float] = 60) -> CommandResult:
        started = time.perf_counter()
        if os.name == "nt":
            return await asyncio.to_thread(self._capture_sync, list(command), timeout, started)
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except (OSError, ValueError) as exc:
            return CommandResult("failed", None, b"", b"", str(exc) or repr(exc), time.perf_counter() - started)
        try:
            communicate_coro = process.communicate()
            if timeout is not None:
                stdout, stderr = await asyncio.wait_for(communicate_coro, timeout=timeout)
            else:
                stdout, stderr = await communicate_coro
            code = process.returncode
            return CommandResult("completed" if code == 0 else "failed", code, stdout, stderr,
                                 None if code == 0 else f"Command exited with code {code}", time.perf_counter() - started)
        except asyncio.TimeoutError:
            self._terminate_process_tree(process)
            stdout, stderr = await process.communicate()
            return CommandResult("timed_out", process.returncode, stdout, stderr,
                                 f"Command exceeded its {timeout}-second timeout", time.perf_counter() - started)

    async def capture_runtime(self, command: Sequence[str], timeout: Optional[float] = 60) -> CommandResult:
        return await self.capture_host(self.wrap_runtime_command(command), timeout)

    @staticmethod
    def _terminate_process_tree(process: Any) -> None:
        """Terminate a process and its child processes to avoid zombie or orphan tasks."""
        if not process:
            return
        pid = getattr(process, "pid", None)
        if not pid:
            return
        try:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(pid)],
                    capture_output=True,
                    timeout=5,
                    check=False,
                )
            else:
                import signal
                try:
                    os.killpg(os.getpgid(pid), signal.SIGTERM)
                except Exception:
                    process.terminate()
        except Exception:
            try:
                process.kill()
            except Exception:
                pass

    async def run_streaming_command(
        self,
        command: Sequence[str],
        on_stdout: Optional[Any] = None,
        on_stderr: Optional[Any] = None,
        cancel_event: Optional[asyncio.Event] = None,
        timeout: Optional[float] = None,
        on_process_created: Optional[Any] = None,
    ) -> CommandResult:
        """Run a scanner command without artificial limits, streaming output live and supporting cancellation."""
        started = time.perf_counter()
        cmd_list = list(command)

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd_list,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except (OSError, ValueError) as exc:
            return CommandResult("failed", None, b"", b"", str(exc) or repr(exc), time.perf_counter() - started)

        if on_process_created:
            try:
                on_process_created(process)
            except Exception:
                pass

        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []

        async def read_stream(stream: asyncio.StreamReader, is_stderr: bool) -> None:
            while True:
                line = await stream.readline()
                if not line:
                    break
                if is_stderr:
                    stderr_chunks.append(line)
                    if on_stderr:
                        try:
                            on_stderr(decode_output(line))
                        except Exception:
                            pass
                else:
                    stdout_chunks.append(line)
                    if on_stdout:
                        try:
                            on_stdout(decode_output(line))
                        except Exception:
                            pass

        stdout_task = asyncio.create_task(read_stream(process.stdout, False))
        stderr_task = asyncio.create_task(read_stream(process.stderr, True))
        wait_task = asyncio.create_task(process.wait())

        # Build monitor coroutine
        status = "completed"
        error_msg = None

        if cancel_event:
            cancel_task = asyncio.create_task(cancel_event.wait())
            tasks_to_wait = {wait_task, cancel_task}
        else:
            cancel_task = None
            tasks_to_wait = {wait_task}

        try:
            if timeout:
                done, pending = await asyncio.wait(tasks_to_wait, timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
            else:
                done, pending = await asyncio.wait(tasks_to_wait, return_when=asyncio.FIRST_COMPLETED)

            if wait_task in done:
                code = wait_task.result()
                status = "completed" if code == 0 else "failed"
                error_msg = None if code == 0 else f"Command exited with code {code}"
            elif cancel_task and cancel_task in done:
                status = "cancelled"
                error_msg = "Scan was cancelled by the user"
                self._terminate_process_tree(process)
                await wait_task
            else:
                # Timeout occurred
                status = "timed_out"
                error_msg = f"Scanner exceeded the safety limit of {timeout}s"
                self._terminate_process_tree(process)
                await wait_task
        except Exception as exc:
            self._terminate_process_tree(process)
            status = "failed"
            error_msg = str(exc)
        finally:
            if cancel_task and not cancel_task.done():
                cancel_task.cancel()
            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)

        full_stdout = b"".join(stdout_chunks)
        full_stderr = b"".join(stderr_chunks)
        code = process.returncode

        return CommandResult(
            status=status,
            exit_code=code,
            stdout=full_stdout,
            stderr=full_stderr,
            error=error_msg,
            duration=time.perf_counter() - started,
        )

    async def run_command(self, command: Sequence[str], timeout: Optional[float] = None) -> CommandResult:
        """Run an already built command without an arbitrary timeout limit unless explicitly specified."""
        started = time.perf_counter()
        if os.name == "nt":
            return await asyncio.to_thread(self._run_sync, list(command), timeout, started)
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except (OSError, ValueError) as exc:
            return CommandResult("failed", None, b"", b"", str(exc) or repr(exc), time.perf_counter() - started)
        try:
            communicate_coro = process.communicate()
            if timeout is not None:
                stdout, stderr = await asyncio.wait_for(communicate_coro, timeout=timeout)
            else:
                stdout, stderr = await communicate_coro
            code = process.returncode
            status = "timed_out" if code in (124, 137) else ("completed" if code == 0 else "failed")
            error = None if status == "completed" else (
                f"Command exceeded its {timeout}-second timeout" if status == "timed_out"
                else f"Command exited with code {code}"
            )
            return CommandResult(status, code, stdout, stderr, error, time.perf_counter() - started)
        except asyncio.TimeoutError:
            self._terminate_process_tree(process)
            stdout, stderr = await process.communicate()
            return CommandResult("timed_out", process.returncode, stdout, stderr,
                                 f"Command exceeded its {timeout}-second timeout", time.perf_counter() - started)

    @staticmethod
    def _capture_sync(command: Sequence[str], timeout: Optional[float], started: float) -> CommandResult:
        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    timeout=timeout, check=False)
            status = "completed" if result.returncode == 0 else "failed"
            return CommandResult(status, result.returncode, result.stdout, result.stderr,
                                 None if result.returncode == 0 else f"Command exited with code {result.returncode}",
                                 time.perf_counter() - started)
        except subprocess.TimeoutExpired as exc:
            return CommandResult("timed_out", None, exc.stdout or b"", exc.stderr or b"",
                                 f"Command exceeded its {timeout}-second timeout", time.perf_counter() - started)
        except (OSError, ValueError) as exc:
            return CommandResult("failed", None, b"", b"", str(exc) or repr(exc), time.perf_counter() - started)

    @staticmethod
    def _run_sync(command: Sequence[str], timeout: Optional[float], started: float) -> CommandResult:
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except (OSError, ValueError) as exc:
            return CommandResult("failed", None, b"", b"", str(exc) or repr(exc), time.perf_counter() - started)
        try:
            stdout, stderr = process.communicate(timeout=timeout)
            code = process.returncode
            status = "timed_out" if code in (124, 137) else ("completed" if code == 0 else "failed")
            error = None if status == "completed" else (
                f"Command exceeded its {timeout}-second timeout" if status == "timed_out"
                else f"Command exited with code {code}"
            )
        except subprocess.TimeoutExpired:
            try:
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(process.pid)], capture_output=True, timeout=5, check=False)
            except Exception:
                process.kill()
            stdout, stderr = process.communicate()
            code = process.returncode
            status = "timed_out"
            error = f"Command exceeded its {timeout}-second timeout"
        return CommandResult(status, code, stdout, stderr, error, time.perf_counter() - started)

    async def preflight(self, scanners: dict[str, dict[str, object]]) -> dict:
        """Inspect WSL and each executable without installing or scanning anything."""
        result = {
            "status": "available",
            "runtime": "wsl" if self.uses_wsl else "local",
            "distribution": self.distribution if self.uses_wsl else None,
            "wsl_available": not self.uses_wsl,
            "distribution_installed": not self.uses_wsl,
            "distribution_state_before_command": "not_applicable" if not self.uses_wsl else "unknown",
            "command_executable": not self.uses_wsl,
            "stdout": "",
            "stderr": "",
            "error": None,
            "probes": {},
            "scanners": {},
        }

        if self.uses_wsl:
            wsl_status = await self.capture_host(["wsl.exe", "--status"])
            result["wsl_available"] = wsl_status.status == "completed"
            result["stdout"] = decode_output(wsl_status.stdout)
            result["stderr"] = decode_output(wsl_status.stderr)
            result["probes"]["wsl_status"] = {
                "exit_code": wsl_status.exit_code,
                "stdout": decode_output(wsl_status.stdout),
                "stderr": decode_output(wsl_status.stderr),
                "error": wsl_status.error,
            }
            if not result["wsl_available"]:
                result.update(status="unavailable", error=wsl_status.error or result["stderr"] or "WSL is unavailable")
                return self._unavailable_scanners(result, scanners, "wsl_unavailable")

            listing = await self.capture_host(["wsl.exe", "-l", "-q"])
            listing_stdout = decode_output(listing.stdout)
            listing_stderr = decode_output(listing.stderr)
            result["probes"]["distribution_list"] = {
                "exit_code": listing.exit_code,
                "stdout": listing_stdout,
                "stderr": listing_stderr,
                "error": listing.error,
            }
            names = self._distribution_names("\n".join(part for part in (listing_stdout, listing_stderr) if part))
            if listing.status != "completed":
                listing_text = "\n".join((listing_stdout, listing_stderr)).casefold()
                if not names and ("no installed distributions" in listing_text or "no distributions" in listing_text):
                    result.update(status="unavailable", distribution_installed=False,
                                  error=f"Required WSL distribution '{self.distribution}' is not installed",
                                  stdout=listing_stdout, stderr=listing_stderr)
                    return self._unavailable_scanners(result, scanners, "distribution_missing")
                result.update(status="unavailable", error=listing.error or result["stderr"] or "Unable to list WSL distributions")
                return self._unavailable_scanners(result, scanners, "distribution_list_failed")
            result["distribution_installed"] = any(name.casefold() == self.distribution.casefold() for name in names)
            if not result["distribution_installed"]:
                result.update(status="unavailable", error=f"Required WSL distribution '{self.distribution}' is not installed",
                              stdout=listing_stdout, stderr=listing_stderr or result["stderr"])
                return self._unavailable_scanners(result, scanners, "distribution_missing")

            state_result = await self.capture_host(["wsl.exe", "-l", "-v"])
            state_stdout = decode_output(state_result.stdout)
            state_stderr = decode_output(state_result.stderr)
            result["probes"]["distribution_state"] = {
                "exit_code": state_result.exit_code,
                "stdout": state_stdout,
                "stderr": state_stderr,
                "error": state_result.error,
            }
            result["distribution_state_before_command"] = self._distribution_state(
                "\n".join(part for part in (state_stdout, state_stderr) if part), self.distribution
            )
            ready = await self.capture_runtime(["bash", "-lc", "printf VULNAI_WSL_READY"])
            result["probes"]["distribution_command"] = {
                "exit_code": ready.exit_code,
                "stdout": decode_output(ready.stdout),
                "stderr": decode_output(ready.stderr),
                "error": ready.error,
            }
            result["command_executable"] = ready.status == "completed" and b"VULNAI_WSL_READY" in ready.stdout
            if not result["command_executable"]:
                result.update(status="unavailable", error=ready.error or decode_output(ready.stderr) or "Ubuntu could not execute a command",
                              stdout=decode_output(ready.stdout), stderr=decode_output(ready.stderr))
                return self._unavailable_scanners(result, scanners, "distribution_command_failed")
            result["stdout"] = decode_output(ready.stdout)
            result["stderr"] = decode_output(ready.stderr)

        for scanner, spec in scanners.items():
            binary = str(spec["binary"])
            probe = await self.capture_runtime(["bash", "-lc", f"command -v {binary}"])
            found_path = decode_output(probe.stdout) if probe.status == "completed" else ""
            available = probe.status == "completed" and bool(found_path)
            error = None if available else (
                f"Scanner binary '{binary}' is missing from {self.distribution if self.uses_wsl else 'PATH'}"
                if probe.exit_code == 1 else (probe.error or decode_output(probe.stderr) or "Scanner binary check failed")
            )
            result["scanners"][scanner] = {
                "scanner": scanner,
                "available": available,
                "status": "available" if available else "unavailable",
                "binary": binary,
                "path": found_path or None,
                "stdout": decode_output(probe.stdout),
                "stderr": decode_output(probe.stderr),
                "exit_code": probe.exit_code,
                "error": error,
                "reason": None if available else ("binary_missing" if probe.exit_code == 1 else "binary_check_failed"),
            }
            result["probes"][f"scanner:{scanner}"] = {
                "exit_code": probe.exit_code,
                "stdout": decode_output(probe.stdout),
                "stderr": decode_output(probe.stderr),
                "error": probe.error,
            }
        if not all(item["available"] for item in result["scanners"].values()):
            result["status"] = "partial"
        return result

    async def preflight_matrix(self, scanners: dict[str, dict[str, object]]) -> dict:
        """Preflight the runtime selected for each scanner without running a scan."""
        wsl_scanners = {
            name: spec for name, spec in scanners.items()
            if spec.get("runtime", "wsl") == "wsl"
        }
        wsl_status = await self.preflight(wsl_scanners) if wsl_scanners else {
            "status": "not_required", "runtime": "wsl", "scanners": {}
        }
        docker_scanners = {
            name: spec for name, spec in scanners.items()
            if spec.get("runtime") == "docker"
        }
        docker_status = await self._preflight_docker(docker_scanners) if docker_scanners else {
            "status": "not_required", "runtime": "docker", "scanners": {}
        }
        scanner_status = {**wsl_status.get("scanners", {}), **docker_status.get("scanners", {})}
        available = [item.get("available") for item in scanner_status.values()]
        return {
            "status": "available" if available and all(available) else ("partial" if any(available) else "unavailable"),
            "runtime": "matrix",
            "wsl": wsl_status,
            "docker": docker_status,
            "scanners": scanner_status,
            "error": None if available and all(available) else "One or more scanner runtimes are unavailable",
        }

    async def _preflight_docker(self, scanners: dict[str, dict[str, object]]) -> dict:
        result = {"status": "available", "runtime": "docker", "command_executable": False,
                  "stdout": "", "stderr": "", "error": None, "scanners": {}, "probes": {}}
        command = settings.scanner_docker_command
        version = await self.capture_host([command, "version", "--format", "{{.Client.Version}}"])
        result["command_executable"] = version.status == "completed"
        result["stdout"] = decode_output(version.stdout)
        result["stderr"] = decode_output(version.stderr)
        result["probes"]["docker_version"] = {
            "exit_code": version.exit_code, "stdout": result["stdout"], "stderr": result["stderr"], "error": version.error,
        }
        if not result["command_executable"]:
            result.update(status="unavailable", error=version.error or result["stderr"] or "Docker is unavailable")
            return self._unavailable_docker_scanners(result, scanners, "docker_unavailable")

        for scanner, spec in scanners.items():
            image = str(spec["image"])
            probe = await self.capture_host([command, "image", "inspect", image])
            available = probe.status == "completed"
            result["scanners"][scanner] = {
                "scanner": scanner, "available": available,
                "status": "available" if available else "unavailable", "runtime": "docker",
                "image": image, "stdout": decode_output(probe.stdout), "stderr": decode_output(probe.stderr),
                "exit_code": probe.exit_code,
                "error": None if available else (probe.error or decode_output(probe.stderr) or f"Docker image '{image}' is unavailable"),
                "reason": None if available else "docker_image_missing",
            }
            result["probes"][f"scanner:{scanner}"] = {
                "exit_code": probe.exit_code, "stdout": decode_output(probe.stdout),
                "stderr": decode_output(probe.stderr), "error": probe.error,
            }
        if not all(item["available"] for item in result["scanners"].values()):
            result["status"] = "partial"
        return result

    @staticmethod
    def _unavailable_docker_scanners(runtime: dict, scanners: dict[str, dict[str, object]], reason: str) -> dict:
        runtime["scanners"] = {
            name: {
                "scanner": name, "available": False, "status": "unavailable", "runtime": "docker",
                "image": str(spec["image"]), "stdout": runtime.get("stdout", ""),
                "stderr": runtime.get("stderr", ""), "exit_code": None,
                "error": runtime.get("error"), "reason": reason,
            }
            for name, spec in scanners.items()
        }
        return runtime

    def _unavailable_scanners(self, runtime: dict, scanners: dict[str, dict[str, object]], reason: str) -> dict:
        runtime["scanners"] = {
            name: {
                "scanner": name,
                "available": False,
                "status": "unavailable",
                "binary": str(spec["binary"]),
                "path": None,
                "stdout": runtime.get("stdout", ""),
                "stderr": runtime.get("stderr", ""),
                "exit_code": None,
                "error": runtime.get("error"),
                "reason": reason,
            }
            for name, spec in scanners.items()
        }
        return runtime

    @staticmethod
    def _distribution_names(output: str) -> list[str]:
        names = []
        for line in output.splitlines():
            name = line.strip().lstrip("* ").strip()
            if not name or name.casefold().startswith(("windows subsystem", "use 'wsl", "there are no")):
                continue
            if name.casefold() in {"name", "version", "default version"}:
                continue
            names.append(name)
        return names

    @staticmethod
    def _distribution_state(output: str, distribution: str) -> str:
        for line in output.splitlines():
            columns = line.replace("*", " ").split()
            if columns and columns[0].casefold() == distribution.casefold():
                for value in columns[1:]:
                    if value.casefold() in {"running", "stopped"}:
                        return value.casefold()
        return "unknown"


scanner_runtime = ScannerRuntime()
