# Author: Tim Rice <tim.j.rice@hackrange.com>
# Part of nextgen-dast. See README.md for license and overall architecture.
"""
LLM client for security analysis of HTTP request/response pairs.

Two backends, selected per-endpoint:
  - 'anthropic'      — native Anthropic Messages API
  - 'openai_compat'  — OpenAI /v1/chat/completions; covers OpenAI itself,
                       open-webui, LibreChat, Ollama, LiteLLM, etc.

Returns a structured analysis: a list of findings with severity, category,
evidence, description, and recommendation.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from typing import Any, Optional

ANTHROPIC_VERSION = "2023-06-01"

SYSTEM_PROMPT = """You are a security auditor reviewing an HTTP request/response pair captured from a target web application during authorized DAST testing. Your goal is to identify security issues that a static regex scanner would miss: business-logic flaws, authentication / authorization issues, sensitive data exposure, IDOR, injection (SQLi / XSS / SSRF / SSTI / cmd / NoSQL / LDAP / XXE), broken access control, insecure deserialization, mass assignment, race conditions, OWASP Top 10 patterns, and unusual implementation details.

Respond ONLY with a JSON array of findings. Each element matches this schema:
  {
    "severity": "critical|high|medium|low|info",
    "category": "short label (e.g. IDOR, SSRF, info_disclosure, auth_bypass)",
    "title": "one-line summary",
    "evidence": "exact quote or value from the request or response",
    "location": "request|response|headers|body|url|cookie",
    "description": "what the issue is and why it matters",
    "recommendation": "how to remediate"
  }

If you find nothing notable, return [].
Do not output anything outside the JSON array. Do not wrap it in markdown fences."""

USER_TEMPLATE = """Existing automated regex findings (may be partial or noisy):
{automated}

REQUEST
=======
{request}

RESPONSE
========
{response}"""


def _truncate(text: str, n: int = 20000) -> str:
    return text if len(text) <= n else text[:n] + f"\n...[truncated {len(text)-n} chars]"


def build_prompt(request_text: str, response_text: str,
                 automated_findings: Optional[list]) -> str:
    return USER_TEMPLATE.format(
        automated=(json.dumps(automated_findings, indent=2)
                   if automated_findings else "(none)"),
        request=_truncate(request_text),
        response=_truncate(response_text),
    )


def _http_post(url: str, headers: dict, body: dict, timeout: int = 180):
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except urllib.error.URLError as e:
        return 0, f"network error: {e}"


def call_anthropic(api_key: str, model: str, system: str,
                   user_prompt: str, max_tokens: int = 4096) -> dict:
    headers = {
        "x-api-key": api_key,
        "anthropic-version": ANTHROPIC_VERSION,
        "content-type": "application/json",
    }
    body = {
        "model": model,
        "max_tokens": max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": user_prompt}],
    }
    status, text = _http_post("https://api.anthropic.com/v1/messages", headers, body)
    if status != 200:
        return {"ok": False, "raw": text, "error": f"HTTP {status}"}
    parsed = json.loads(text)
    content = "".join(b.get("text", "") for b in parsed.get("content", [])
                      if b.get("type") == "text")
    usage = parsed.get("usage", {})
    return {
        "ok": True,
        "raw": text,
        "content": content,
        "in_tokens": usage.get("input_tokens"),
        "out_tokens": usage.get("output_tokens"),
    }


def call_openai_compat(base_url: str, api_key: str, model: str, system: str,
                       user_prompt: str, max_tokens: int = 4096,
                       extra_headers: Optional[dict] = None) -> dict:
    url = base_url.rstrip("/") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    if extra_headers:
        headers.update(extra_headers)
    body = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_prompt},
        ],
    }
    status, text = _http_post(url, headers, body)
    if status != 200:
        return {"ok": False, "raw": text, "error": f"HTTP {status}"}
    parsed = json.loads(text)
    try:
        choice = parsed["choices"][0]
        content = choice["message"]["content"]
    except (KeyError, IndexError):
        return {"ok": False, "raw": text, "error": "unexpected response shape"}
    usage = parsed.get("usage", {})
    return {
        "ok": True,
        "raw": text,
        "content": content,
        "in_tokens": usage.get("prompt_tokens"),
        "out_tokens": usage.get("completion_tokens"),
    }


def parse_findings(content: str) -> Optional[list]:
    if not content:
        return None
    s = content.strip()
    # strip markdown fences if the model added them despite instructions
    s = re.sub(r"^```(?:json)?\s*", "", s)
    s = re.sub(r"\s*```$", "", s)
    try:
        v = json.loads(s)
        return v if isinstance(v, list) else None
    except json.JSONDecodeError:
        pass
    m = re.search(r"\[\s*(?:\{.*?\}\s*,?\s*)*\]", s, re.S)
    if m:
        try:
            v = json.loads(m.group(0))
            return v if isinstance(v, list) else None
        except json.JSONDecodeError:
            return None
    return None


def analyze(endpoint: dict, request_text: str, response_text: str,
            automated_findings: Optional[list]) -> dict:
    """
    endpoint: {backend, base_url, api_key, model, extra_headers}
    Returns {ok, content, findings, in_tokens, out_tokens, raw, error?}.
    """
    user_prompt = build_prompt(request_text, response_text, automated_findings)
    backend = endpoint["backend"]
    if backend == "anthropic":
        result = call_anthropic(endpoint["api_key"], endpoint["model"],
                                SYSTEM_PROMPT, user_prompt)
    elif backend == "openai_compat":
        extra: Any = {}
        if endpoint.get("extra_headers"):
            try:
                extra = json.loads(endpoint["extra_headers"])
            except Exception:
                extra = {}
        result = call_openai_compat(
            endpoint["base_url"], endpoint["api_key"], endpoint["model"],
            SYSTEM_PROMPT, user_prompt, extra_headers=extra,
        )
    else:
        return {"ok": False, "error": f"unknown backend: {backend}"}
    if result.get("ok"):
        result["findings"] = parse_findings(result.get("content", ""))
    return result
