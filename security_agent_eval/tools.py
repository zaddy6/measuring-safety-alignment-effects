"""Sandboxed local tools exposed to the agent."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Any, Dict


class ToolPolicyError(RuntimeError):
    pass


class Sandbox:
    def __init__(self, root: Path, allowed_tools, allowed_commands=None):
        self.root = root.resolve()
        self.allowed_tools = set(allowed_tools)
        self.allowed_commands = set(allowed_commands or ["python3", "python", "pytest", "node", "npm"])

    def materialize(self, task: Dict[str, Any]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        files = task.get("ground_truth", {}).get("fixture_files", {})
        for rel_path, content in files.items():
            target = self.safe_path(rel_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")

    def safe_path(self, rel_path: str) -> Path:
        if not rel_path or rel_path.startswith("/"):
            raise ToolPolicyError("absolute or empty paths are not allowed")
        target = (self.root / rel_path).resolve()
        if os.path.commonpath([str(self.root), str(target)]) != str(self.root):
            raise ToolPolicyError("path traversal outside the sandbox is not allowed")
        return target

    def dispatch(self, tool: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if tool not in self.allowed_tools:
            raise ToolPolicyError(f"tool {tool!r} is not allowed for this task")
        if tool == "list_files":
            return self.list_files(arguments.get("path", "."))
        if tool == "read_file":
            return self.read_file(arguments["path"])
        if tool == "write_file":
            return self.write_file(arguments["path"], arguments.get("content", ""))
        if tool == "run_command":
            return self.run_command(arguments["cmd"], int(arguments.get("timeout_seconds", 15)))
        raise ToolPolicyError(f"unknown tool {tool!r}")

    def list_files(self, path: str = ".") -> Dict[str, Any]:
        base = self.safe_path(path)
        if not base.exists():
            return {"ok": False, "output": f"{path} does not exist"}
        if base.is_file():
            return {"ok": True, "output": path}
        rows = []
        for item in sorted(base.rglob("*")):
            if item.is_file():
                rows.append(str(item.relative_to(self.root)))
        return {"ok": True, "output": "\n".join(rows)}

    def read_file(self, path: str) -> Dict[str, Any]:
        target = self.safe_path(path)
        if not target.exists() or not target.is_file():
            return {"ok": False, "output": f"{path} is not a file"}
        return {"ok": True, "output": target.read_text(encoding="utf-8", errors="replace")[:12000]}

    def write_file(self, path: str, content: str) -> Dict[str, Any]:
        target = self.safe_path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return {"ok": True, "output": f"wrote {path}"}

    def run_command(self, cmd, timeout_seconds: int = 15) -> Dict[str, Any]:
        if not isinstance(cmd, list) or not cmd:
            raise ToolPolicyError("cmd must be a non-empty argument list")
        if cmd[0] not in self.allowed_commands:
            raise ToolPolicyError(f"command {cmd[0]!r} is not allowed")
        result = subprocess.run(
            cmd,
            cwd=str(self.root),
            text=True,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
        output = (result.stdout + result.stderr)[:12000]
        return {"ok": result.returncode == 0, "exit_status": result.returncode, "output": output}
