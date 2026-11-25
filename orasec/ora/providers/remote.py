"""Remote AI providers over httpx (no vendor SDKs). Synchronous adapters.

* Anthropic Messages API (``x-api-key``).
* OpenAI-compatible chat completions (OpenRouter, OpenAI, Azure OpenAI, a local Ollama):
  ``{base_url}/chat/completions`` with ``Authorization: Bearer``. JSON mode is
  requested; the system prompt also says "one JSON object".
* Vertex AI ``generateContent``: a service-account JWT (RS256) is exchanged at
  the hard-coded Google token endpoint (never a ``token_uri`` from the key
  file -- SSRF guard) for an access token, cached until shortly before expiry.

One automatic retry for short-lived errors (429 / 5xx / network / timeout).
"""
from __future__ import annotations

import hashlib
import time
from typing import Any

import httpx
import jwt

from orasec.ora.providers.base import (
    PROVIDER_TIMEOUT_SECONDS,
    ProviderError,
    ProviderRequest,
    ProviderResult,
    parse_json_text,
)

_RETRY_STATUSES = {408, 409, 429, 500, 502, 503, 504, 529}


def _err(msg: str, *, transient: bool = False) -> ProviderError:
    e = ProviderError(msg)
    e.transient = transient
    return e


def _reason(resp) -> str:
    """The provider's own short error message (never the request), so admins can see why a call failed."""
    try:
        body = resp.json()
        err = body.get("error") if isinstance(body, dict) else None
        msg = err.get("message") if isinstance(err, dict) else (err if isinstance(err, str) else "")
    except ValueError:
        msg = ""
    msg = " ".join(str(msg or "").split())[:200]
    return f": {msg}" if msg else ""


def _post(url: str, *, json_body: dict[str, Any], headers: dict[str, str], timeout: float) -> dict[str, Any]:
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(url, json=json_body, headers=headers)
    except httpx.TimeoutException as exc:
        raise _err("timeout", transient=True) from exc
    except httpx.HTTPError as exc:
        raise _err(f"network error: {type(exc).__name__}", transient=True) from exc
    if resp.status_code != 200:
        raise _err(f"HTTP {resp.status_code}{_reason(resp)}", transient=resp.status_code in _RETRY_STATUSES)
    try:
        return resp.json()
    except ValueError as exc:
        raise _err("response was not JSON", transient=True) from exc


def _with_retry(fn, req: ProviderRequest) -> ProviderResult:
    started = time.monotonic()
    try:
        return fn(req, PROVIDER_TIMEOUT_SECONDS)
    except ProviderError as exc:
        left = PROVIDER_TIMEOUT_SECONDS + 10 - (time.monotonic() - started)
        if not exc.transient or left < 5:
            raise
        time.sleep(0.8)
        return fn(req, left)


class AnthropicProvider:
    name = "anthropic"
    URL = "https://api.anthropic.com/v1/messages"

    def __init__(self, *, api_key: str, model: str):
        if not (api_key and model):
            raise ProviderError("anthropic provider is not fully configured")
        self._key, self.model = api_key, model

    def _once(self, req: ProviderRequest, timeout: float) -> ProviderResult:
        started = time.monotonic()
        body = {
            "model": self.model,
            "max_tokens": req.max_tokens,
            "system": req.system + "\n\nRespond with a single JSON object only.",
            "messages": [{"role": "assistant" if t.role == "assistant" else "user",
                          "content": [{"type": "text", "text": t.text}]} for t in req.turns],
        }  # no temperature: newer Anthropic models reject it, and the JSON-only prompt keeps answers steady
        data = _post(self.URL, json_body=body, timeout=timeout,
                     headers={"x-api-key": self._key, "anthropic-version": "2023-06-01",
                              "content-type": "application/json"})
        text = "".join(b.get("text", "") for b in data.get("content") or [] if b.get("type") == "text")
        usage = data.get("usage") or {}
        return ProviderResult(data=parse_json_text(text), input_tokens=int(usage.get("input_tokens") or 0),
                              output_tokens=int(usage.get("output_tokens") or 0), model=self.model,
                              provider=self.name, latency_ms=int((time.monotonic() - started) * 1000), raw_text=text)

    def generate_json(self, req: ProviderRequest) -> ProviderResult:
        return _with_retry(self._once, req)


class OpenAICompatProvider:
    name = "openai"

    def __init__(self, *, base_url: str, api_key: str, model: str):
        if not (base_url and model):
            raise ProviderError("openai-compatible provider is not fully configured")
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._key, self.model = api_key, model

    def _once(self, req: ProviderRequest, timeout: float) -> ProviderResult:
        started = time.monotonic()
        messages = [{"role": "system", "content": req.system + "\n\nRespond with a single JSON object only."}]
        messages += [{"role": "assistant" if t.role == "assistant" else "user", "content": t.text} for t in req.turns]
        body = {"model": self.model, "messages": messages, "max_tokens": req.max_tokens, "temperature": 0.2,
                "response_format": {"type": "json_object"}}
        headers = {"content-type": "application/json", "X-Title": "OraSec"}
        if self._key:
            headers["Authorization"] = f"Bearer {self._key}"
        try:
            data = _post(self._url, json_body=body, headers=headers, timeout=timeout)
        except ProviderError as exc:
            # Some servers reject response_format: retry once without it.
            if str(exc) != "HTTP 400":
                raise
            body.pop("response_format", None)
            data = _post(self._url, json_body=body, headers=headers, timeout=timeout)
        choices = data.get("choices") or []
        text = ((choices[0] if choices else {}).get("message") or {}).get("content") or ""
        if isinstance(text, list):
            text = "".join(p.get("text", "") for p in text if isinstance(p, dict))
        usage = data.get("usage") or {}
        return ProviderResult(data=parse_json_text(text), input_tokens=int(usage.get("prompt_tokens") or 0),
                              output_tokens=int(usage.get("completion_tokens") or 0), model=self.model,
                              provider=self.name, latency_ms=int((time.monotonic() - started) * 1000), raw_text=text)

    def generate_json(self, req: ProviderRequest) -> ProviderResult:
        return _with_retry(self._once, req)


GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"
_SCOPE = "https://www.googleapis.com/auth/cloud-platform"
_token_cache: dict[str, tuple[str, float]] = {}


def _mint_token(sa: dict[str, str]) -> str:
    ident = hashlib.sha256((sa["client_email"] + "|" + hashlib.sha256(sa["private_key"].encode()).hexdigest())
                           .encode()).hexdigest()[:32]
    now = time.time()
    hit = _token_cache.get(ident)
    if hit and now < hit[1] - 60:
        return hit[0]
    assertion = jwt.encode({"iss": sa["client_email"], "scope": _SCOPE, "aud": GOOGLE_TOKEN_URI,
                            "iat": int(now), "exp": int(now) + 3600}, sa["private_key"], algorithm="RS256")
    try:
        with httpx.Client(timeout=15) as client:
            resp = client.post(GOOGLE_TOKEN_URI, data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                                                       "assertion": assertion})
    except httpx.HTTPError as exc:
        raise _err("token exchange network error", transient=True) from exc
    if resp.status_code != 200:
        raise _err(f"token exchange failed: HTTP {resp.status_code}")
    body = resp.json()
    token = body.get("access_token")
    if not token:
        raise _err("token exchange returned no access_token")
    _token_cache[ident] = (token, now + float(body.get("expires_in", 3600)))
    return token


class VertexProvider:
    name = "vertex"

    def __init__(self, *, project_id: str, region: str, model: str, service_account: dict[str, str]):
        if not (project_id and region and model and service_account):
            raise ProviderError("vertex provider is not fully configured")
        self.project_id, self.region, self.model, self._sa = project_id, region, model, service_account

    def _url(self) -> str:
        host = "aiplatform.googleapis.com" if self.region == "global" else f"{self.region}-aiplatform.googleapis.com"
        return (f"https://{host}/v1/projects/{self.project_id}/locations/{self.region}"
                f"/publishers/google/models/{self.model}:generateContent")

    def _once(self, req: ProviderRequest, timeout: float) -> ProviderResult:
        started = time.monotonic()
        body = {
            "systemInstruction": {"parts": [{"text": req.system}]},
            "contents": [{"role": "model" if t.role == "assistant" else "user", "parts": [{"text": t.text}]}
                         for t in req.turns],
            "generationConfig": {"responseMimeType": "application/json", "maxOutputTokens": req.max_tokens,
                                 "temperature": 0.2},
        }
        data = _post(self._url(), json_body=body, timeout=timeout,
                     headers={"Authorization": f"Bearer {_mint_token(self._sa)}"})
        cands = data.get("candidates") or []
        parts = ((cands[0] if cands else {}).get("content") or {}).get("parts") or []
        text = "".join(p.get("text", "") for p in parts if not p.get("thought"))
        usage = data.get("usageMetadata") or {}
        return ProviderResult(data=parse_json_text(text), input_tokens=int(usage.get("promptTokenCount") or 0),
                              output_tokens=int(usage.get("candidatesTokenCount") or 0)
                              + int(usage.get("thoughtsTokenCount") or 0), model=self.model, provider=self.name,
                              latency_ms=int((time.monotonic() - started) * 1000), raw_text=text)

    def generate_json(self, req: ProviderRequest) -> ProviderResult:
        return _with_retry(self._once, req)

