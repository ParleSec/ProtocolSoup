"""Small standard-library client for the OIDF conformance-suite API."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


class OIDFAPIError(RuntimeError):
    pass


class OIDFClient:
    def __init__(self, base_url: str, token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token.strip()
        if not self.token:
            raise ValueError("OIDF API bearer token is required")

    def request(
        self,
        method: str,
        path: str,
        body: Any | None = None,
    ) -> Any:
        data = None if body is None else json.dumps(body).encode("utf-8")
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                raw = response.read().decode("utf-8")
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise OIDFAPIError(
                f"{method} {path} returned HTTP {exc.code}: {detail}"
            ) from exc

    def create_plan(
        self,
        plan_name: str,
        alias: str,
        variant: dict[str, Any],
        config: dict[str, Any],
        description: str,
    ) -> str:
        query = urllib.parse.urlencode({"planName": plan_name, "alias": alias})
        created = self.request(
            "POST",
            f"/api/plan?{query}",
            {
                "planName": plan_name,
                "variant": variant,
                "config": config,
                "description": description,
            },
        )
        plan_id = (
            created.get("id") or created.get("planId")
            if isinstance(created, dict)
            else None
        )
        if not plan_id:
            raise OIDFAPIError(f"unexpected create-plan response: {created!r}")
        return str(plan_id)

    def plans(self) -> list[dict[str, Any]]:
        payload = self.request("GET", "/api/plan?length=500")
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            raise OIDFAPIError(f"unexpected plan-list response: {payload!r}")
        return [item for item in payload["data"] if isinstance(item, dict)]

    def plan(self, plan_id: str) -> dict[str, Any]:
        for plan in self.plans():
            if plan.get("_id") == plan_id:
                return plan
        raise OIDFAPIError(f"plan {plan_id!r} was not found")

    def start_module(self, plan_id: str, module: dict[str, Any]) -> str:
        query: dict[str, str] = {
            "test": str(module["testModule"]),
            "plan": plan_id,
        }
        if module.get("variant") is not None:
            query["variant"] = json.dumps(
                module["variant"], separators=(",", ":"), sort_keys=True
            )
        created = self.request(
            "POST",
            "/api/runner?" + urllib.parse.urlencode(query),
        )
        module_id = (
            created.get("id") if isinstance(created, dict) else created
        )
        if not module_id:
            raise OIDFAPIError(f"unexpected start-module response: {created!r}")
        return str(module_id)

    def module_info(self, module_id: str) -> dict[str, Any]:
        payload = self.request("GET", f"/api/info/{module_id}")
        if not isinstance(payload, dict):
            raise OIDFAPIError(f"unexpected module-info response: {payload!r}")
        return payload

    def module_log(self, module_id: str) -> list[dict[str, Any]]:
        payload = self.request("GET", f"/api/log/{module_id}")
        if not isinstance(payload, list):
            raise OIDFAPIError(f"unexpected module-log response: {payload!r}")
        return [entry for entry in payload if isinstance(entry, dict)]
