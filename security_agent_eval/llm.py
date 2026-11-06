"""LLM clients for mock runs and local OpenAI-compatible model servers."""

from __future__ import annotations

import json
import http.client
import time
import urllib.error
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .config import ModelCondition


@dataclass
class LLMResult:
    content: str
    prompt_tokens: int = 0
    completion_tokens: int = 0


class MockClient:
    """Deterministic client used for harness validation without model weights."""

    def __init__(self, condition: ModelCondition):
        self.condition = condition

    def generate(self, messages: List[Dict[str, str]], task: Dict[str, Any]) -> LLMResult:
        expected = task["success_predicate"].get("expected", {})
        terms = expected.get("contains", [])
        forbidden = set(item.lower() for item in expected.get("forbidden", []))
        safe_terms = [term for term in terms if term.lower() not in forbidden]
        final = (
            f"Task {task['task_id']} completed. "
            + ". ".join(safe_terms)
            + ". Evidence is local-only and redacted where applicable."
        )
        return LLMResult(content=json.dumps({"final": final}), prompt_tokens=50, completion_tokens=40)


class OpenAICompatibleClient:
    """Minimal stdlib client for llama.cpp's OpenAI-compatible server."""

    def __init__(self, condition: ModelCondition):
        self.condition = condition
        parsed = urllib.parse.urlparse(condition.base_url.rstrip("/"))
        self._scheme = parsed.scheme or "http"
        self._host = parsed.hostname or "127.0.0.1"
        self._port = parsed.port
        self._prefix = parsed.path.rstrip("/")
        self._connection: Optional[http.client.HTTPConnection] = None

    def _close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def _request_json(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        if self._scheme != "http":
            raise ValueError(f"unsupported local model URL scheme {self._scheme!r}")
        if self._connection is None:
            self._connection = http.client.HTTPConnection(self._host, self._port, timeout=600)
        data = json.dumps(payload).encode("utf-8")
        self._connection.request(
            "POST",
            path,
            body=data,
            headers={"Content-Type": "application/json"},
        )
        response = self._connection.getresponse()
        body = response.read().decode("utf-8")
        if response.status >= 400:
            raise urllib.error.URLError(f"HTTP {response.status}: {body[:500]}")
        return json.loads(body)

    def generate(self, messages: List[Dict[str, str]], task: Dict[str, Any]) -> LLMResult:
        payload = {
            "model": self.condition.model_id,
            "messages": messages,
            "response_format": {"type": "json_object"},
            **self.condition.sampling_config,
        }
        path = f"{self._prefix}/chat/completions"
        for attempt in range(4):
            try:
                body = self._request_json(path, payload)
                break
            except (OSError, http.client.HTTPException, urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                self._close()
                if attempt == 3:
                    raise RuntimeError(
                        f"could not reach local model server at {self.condition.base_url}: {exc}"
                    ) from exc
                time.sleep(1.0 + attempt)
        choice = body["choices"][0]["message"]["content"]
        usage = body.get("usage", {})
        return LLMResult(
            content=choice,
            prompt_tokens=int(usage.get("prompt_tokens", 0) or 0),
            completion_tokens=int(usage.get("completion_tokens", 0) or 0),
        )


def make_client(condition: ModelCondition, force_mock: bool = False):
    if force_mock or condition.backend == "mock":
        return MockClient(condition)
    if condition.backend == "openai-compatible":
        return OpenAICompatibleClient(condition)
    raise ValueError(f"unsupported backend {condition.backend!r}")
