"""Stdlib HTTP client for Coralogix Alert Definitions v3 (`pyyaml`-only dependency tree)."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

_PAGE_SIZE = 1000
_IDEMPOTENT_RETRIES = 3

TransportFn = Callable[[str, str, dict[str, str], bytes | None], tuple[int, bytes]]


class CoralogixHttpError(RuntimeError):
    """HTTP status failure returned by Coralogix AlertDefs v3."""

    def __init__(self, method: str, url: str, status_code: int, body_text: str):
        super().__init__(f"Coralogix {method} {url} failed with HTTP {status_code}: {body_text}")
        self.status_code = status_code
        self.body_text = body_text


@dataclass
class CoralogixAlertDef:
    """Stored Coralogix alert definition and its user-authored properties."""

    id: str
    properties: dict[str, Any]
    status: str = ""
    updated_time: str = ""


def _urllib_transport(
    method: str, url: str, headers: dict[str, str], body: bytes | None
) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


class CoralogixAlertsClient:
    """List, create, and replace Coralogix v3 alert definitions."""

    def __init__(
        self,
        api_key: str,
        domain: str,
        *,
        transport: TransportFn | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
    ):
        self._base_url = f"https://api.{domain}/mgmt/openapi/5/alerts/alerts/v3"
        self._transport = transport or _urllib_transport
        self._sleep = sleep_fn
        self._headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": "montu-coralogix/0.7",
        }

    def list_alerts(self, page_size: int = _PAGE_SIZE) -> list[CoralogixAlertDef]:
        """Return every accessible alert definition in the team, failing on pagination cycles."""
        results: list[CoralogixAlertDef] = []
        seen_tokens: set[str] = set()
        page_token = ""
        while True:
            params: dict[str, Any] = {"pagination.page_size": page_size}
            if page_token:
                params["pagination.page_token"] = page_token
            query_string = urllib.parse.urlencode(params)
            body = self._request("GET", f"?{query_string}") or {}
            for entry in body.get("alertDefs") or []:
                results.append(self._parse(entry))
            next_token = str((body.get("pagination") or {}).get("nextPageToken") or "")
            if not next_token:
                break
            if next_token in seen_tokens:
                raise RuntimeError(
                    f"Coralogix list_alerts pagination cycle detected on token {next_token!r}"
                )
            seen_tokens.add(next_token)
            page_token = next_token
        return results

    def create_alert(self, properties: dict[str, Any]) -> CoralogixAlertDef:
        """Create a new alert definition (never retried on 5xx to prevent duplicate alerts)."""
        body = self._request("POST", "", {"alertDefProperties": properties}) or {}
        return self._parse(body.get("alertDef") or body)

    def replace_alert(self, alert_id: str, properties: dict[str, Any]) -> CoralogixAlertDef:
        """Replace an existing alert definition in full by persistent ID."""
        body = self._request("PUT", "", {"id": alert_id, "alertDefProperties": properties}) or {}
        return self._parse(body.get("alertDef") or body)

    @staticmethod
    def _parse(entry: dict[str, Any]) -> CoralogixAlertDef:
        return CoralogixAlertDef(
            id=entry.get("id", ""),
            properties=entry.get("alertDefProperties") or {},
            status=entry.get("status", ""),
            updated_time=entry.get("updatedTime", ""),
        )

    def _request(
        self, method: str, path: str, payload: dict[str, Any] | None = None
    ) -> Any:
        max_attempts = 1 if method == "POST" else _IDEMPOTENT_RETRIES
        url = f"{self._base_url}{path}"
        encoded = json.dumps(payload).encode() if payload is not None else None
        for attempt in range(max_attempts):
            try:
                status, raw = self._transport(method, url, self._headers, encoded)
            except urllib.error.URLError:
                if attempt < max_attempts - 1:
                    self._sleep(2**attempt)
                    continue
                raise
            if 200 <= status < 300:
                return json.loads(raw.decode()) if raw else None
            if (status >= 500 or status == 429) and attempt < max_attempts - 1:
                self._sleep(2**attempt)
                continue
            raise CoralogixHttpError(method, url, status, raw.decode(errors="replace"))
