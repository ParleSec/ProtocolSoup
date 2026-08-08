#!/usr/bin/env python3
"""Create, start, and export pinned OIDF VC conformance plans.

The runner deliberately has no sample credentials. Creation requires a real
operator-supplied manifest matching the suite form for release-v5.2.2.
Official certification submission remains a manual OIDF operation.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import sys
import time
from typing import Any

from oidf_api import OIDFClient


SUITE_RELEASE = "release-v5.2.2"
SUITE_COMMIT = "321bc5bc53601b9690b54c023c0cbfac0f0230f2"
PLAN_NAMES = {
    "oid4vp-verifier": {
        "final": "oid4vp-1final-verifier-test-plan",
        "haip": "oid4vp-1final-verifier-haip-test-plan",
    },
    "oid4vp-wallet": {
        "final": "oid4vp-1final-wallet-test-plan",
        "haip": "oid4vp-1final-wallet-haip-test-plan",
    },
    "oid4vci-issuer": {
        "final": "oid4vci-1_0-issuer-test-plan",
        "haip": "oid4vci-1_0-issuer-haip-test-plan",
    },
    "oid4vci-wallet": {
        "final": "oid4vci-1_0-wallet-test-plan",
        "haip": "oid4vci-1_0-wallet-haip-test-plan",
    },
}
ALLOWED_PLANS = {
    plan_name for profiles in PLAN_NAMES.values() for plan_name in profiles.values()
}
SENSITIVE_KEYS = {
    "access_token",
    "client_secret",
    "d",
    "password",
    "private_key",
    "privatekey",
    "secret",
    "token",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("create", "start", "snapshot"))
    parser.add_argument(
        "--manifest",
        type=pathlib.Path,
        help="real suite plan manifest; required for create",
    )
    parser.add_argument(
        "--plan-id",
        action="append",
        default=[],
        help="existing OIDF plan ID; repeat for multiple roles",
    )
    parser.add_argument(
        "--artifact-dir",
        type=pathlib.Path,
        default=pathlib.Path("artifacts/oidf-vc"),
    )
    parser.add_argument(
        "--module",
        action="append",
        default=[],
        help="start only this exact module name; repeat as needed",
    )
    parser.add_argument(
        "--wait",
        action="store_true",
        help="wait for started modules and fail unless every result passes",
    )
    parser.add_argument(
        "--wait-timeout",
        type=int,
        default=1800,
        help="maximum seconds to wait for started modules",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=10,
        help="seconds between module status checks",
    )
    parser.add_argument(
        "--target-commit",
        default=os.environ.get("TARGET_COMMIT") or os.environ.get("GITHUB_SHA", ""),
        help="candidate commit recorded in exported evidence",
    )
    parser.add_argument(
        "--deployment-url",
        action="append",
        default=[],
        help="role=url deployment provenance; repeat for each tested role",
    )
    return parser.parse_args()


def load_manifest(path: pathlib.Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("suite_release") != SUITE_RELEASE:
        raise ValueError(
            f"manifest suite_release must be {SUITE_RELEASE}, "
            f"got {payload.get('suite_release')!r}"
        )
    if payload.get("suite_commit") != SUITE_COMMIT:
        raise ValueError(
            f"manifest suite_commit must be {SUITE_COMMIT}, "
            f"got {payload.get('suite_commit')!r}"
        )
    plans = payload.get("plans")
    if not isinstance(plans, list) or not plans:
        raise ValueError("manifest plans must be a non-empty array")
    aliases: set[str] = set()
    for index, plan in enumerate(plans):
        if not isinstance(plan, dict):
            raise ValueError(f"plans[{index}] must be an object")
        plan_name = plan.get("plan_name")
        if plan_name not in ALLOWED_PLANS:
            raise ValueError(f"plans[{index}] uses unpinned plan {plan_name!r}")
        alias = str(plan.get("alias") or "").strip()
        if not alias or alias in aliases:
            raise ValueError(f"plans[{index}] alias must be non-empty and unique")
        aliases.add(alias)
        if not isinstance(plan.get("variant"), dict):
            raise ValueError(f"plans[{index}].variant must be an object")
        if not isinstance(plan.get("config"), dict):
            raise ValueError(f"plans[{index}].config must be an object")
    return payload


def redact(value: Any, key: str = "") -> Any:
    normalized_key = key.lower().replace("-", "_")
    if normalized_key in SENSITIVE_KEYS or normalized_key.endswith("_secret"):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {item_key: redact(item, str(item_key)) for item_key, item in value.items()}
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def write_json(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    path.write_bytes(encoded)
    path.with_suffix(path.suffix + ".sha256").write_text(
        hashlib.sha256(encoded).hexdigest() + "\n",
        encoding="ascii",
    )


def parse_deployment_urls(values: list[str]) -> dict[str, str]:
    deployments: dict[str, str] = {}
    for value in values:
        role, separator, url = value.partition("=")
        role = role.strip()
        url = url.strip()
        if not separator or not role or not url.startswith(("https://", "http://")):
            raise ValueError(
                f"deployment URL must use role=https://host form, got {value!r}"
            )
        if role in deployments:
            raise ValueError(f"deployment role {role!r} is repeated")
        deployments[role] = url
    return deployments


def parse_target_commit(value: str) -> str:
    commit = value.strip()
    if commit and re.fullmatch(r"[0-9a-fA-F]{40}", commit) is None:
        raise ValueError("target commit must be a full 40-character hexadecimal SHA")
    return commit.lower()


def condition_failures(log: list[dict[str, Any]]) -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    for entry in log:
        result = str(entry.get("result") or entry.get("status") or "").upper()
        entry_type = str(entry.get("type") or "").upper()
        if result in {"FAIL", "FAILED", "FAILURE"} or (
            entry_type == "CONDITION" and entry.get("result") is False
        ):
            failures.append(redact(entry))
    return failures


def wait_for_modules(
    client: OIDFClient,
    module_ids: list[str],
    timeout_seconds: int,
    poll_interval_seconds: int,
) -> dict[str, dict[str, Any]]:
    if timeout_seconds <= 0 or poll_interval_seconds <= 0:
        raise ValueError("wait timeout and poll interval must be positive")
    deadline = time.monotonic() + timeout_seconds
    pending = set(module_ids)
    completed: dict[str, dict[str, Any]] = {}
    while pending:
        for module_id in list(pending):
            info = client.module_info(module_id)
            status = str(info.get("status") or "").upper()
            if status in {"FINISHED", "INTERRUPTED"}:
                completed[module_id] = info
                pending.remove(module_id)
        if not pending:
            break
        if time.monotonic() >= deadline:
            raise TimeoutError(
                "OIDF modules did not finish before timeout: "
                + ", ".join(sorted(pending))
            )
        time.sleep(min(poll_interval_seconds, max(0, deadline - time.monotonic())))
    failed = {
        module_id: info
        for module_id, info in completed.items()
        if str(info.get("result") or "").upper() not in {"PASS", "PASSED", "SUCCESS"}
    }
    if failed:
        summary = ", ".join(
            f"{module_id}={info.get('result') or info.get('status')}"
            for module_id, info in sorted(failed.items())
        )
        raise RuntimeError(f"OIDF modules did not all pass: {summary}")
    return completed


def create_plans(
    client: OIDFClient,
    manifest: dict[str, Any],
) -> list[str]:
    plan_ids: list[str] = []
    for plan in manifest["plans"]:
        plan_id = client.create_plan(
            plan["plan_name"],
            plan["alias"],
            plan["variant"],
            plan["config"],
            plan.get("description")
            or f"ProtocolSoup {plan['plan_name']} ({plan['alias']})",
        )
        plan_ids.append(plan_id)
        print(f"created {plan['plan_name']}: {client.base_url}/plan-detail.html?plan={plan_id}")
    return plan_ids


def start_modules(
    client: OIDFClient,
    plan_ids: list[str],
    module_filter: set[str],
) -> list[str]:
    module_ids: list[str] = []
    for plan_id in plan_ids:
        plan = client.plan(plan_id)
        for module in plan.get("modules") or []:
            if not isinstance(module, dict) or not module.get("testModule"):
                continue
            module_name = str(module["testModule"])
            if module_filter and module_name not in module_filter:
                continue
            module_id = client.start_module(plan_id, module)
            module_ids.append(module_id)
            print(f"started {module_name}: {client.base_url}/log-detail.html?log={module_id}")
    return module_ids


def snapshot(
    client: OIDFClient,
    plan_ids: list[str],
    artifact_dir: pathlib.Path,
    target_commit: str,
    deployment_urls: dict[str, str],
) -> None:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    index: dict[str, Any] = {
        "captured_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "suite_base": client.base_url,
        "suite_release": SUITE_RELEASE,
        "suite_commit": SUITE_COMMIT,
        "target_commit": target_commit or None,
        "deployment_urls": deployment_urls,
        "plans": [],
    }
    for plan_id in plan_ids:
        plan = client.plan(plan_id)
        plan_record: dict[str, Any] = {
            "id": plan_id,
            "plan_name": plan.get("planName"),
            "description": plan.get("description"),
            "modules": [],
        }
        write_json(artifact_dir / f"plan-{plan_id}.json", redact(plan))
        for module in plan.get("modules") or []:
            if not isinstance(module, dict):
                continue
            for module_id in module.get("instances") or []:
                module_id = str(module_id)
                info = client.module_info(module_id)
                log = client.module_log(module_id)
                failures = condition_failures(log)
                write_json(artifact_dir / f"module-{module_id}-info.json", redact(info))
                write_json(artifact_dir / f"module-{module_id}-log.json", redact(log))
                write_json(
                    artifact_dir / f"module-{module_id}-condition-failures.json",
                    failures,
                )
                plan_record["modules"].append(
                    {
                        "test_module": module.get("testModule"),
                        "id": module_id,
                        "status": info.get("status"),
                        "result": info.get("result"),
                        "condition_failure_count": len(failures),
                    }
                )
        index["plans"].append(plan_record)
    write_json(artifact_dir / "index.json", index)


def main() -> int:
    args = parse_args()
    try:
        deployment_urls = parse_deployment_urls(args.deployment_url)
        target_commit = parse_target_commit(args.target_commit)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    token = os.environ.get("CONFORMANCE_TOKEN", "").strip()
    if not token:
        print("CONFORMANCE_TOKEN is required", file=sys.stderr)
        return 2
    client = OIDFClient(
        os.environ.get("CONFORMANCE_BASE", "https://www.certification.openid.net"),
        token,
    )
    plan_ids = list(args.plan_id)
    if args.action == "create":
        if args.manifest is None:
            print("--manifest is required for create", file=sys.stderr)
            return 2
        plan_ids.extend(create_plans(client, load_manifest(args.manifest)))
    elif not plan_ids:
        print("at least one --plan-id is required", file=sys.stderr)
        return 2

    wait_error: Exception | None = None
    if args.action == "start":
        module_ids = start_modules(client, plan_ids, set(args.module))
        if not module_ids:
            print("no OIDF modules matched the selected plans", file=sys.stderr)
            return 2
        if args.wait:
            if not target_commit or not deployment_urls:
                print(
                    "--wait requires --target-commit and at least one --deployment-url",
                    file=sys.stderr,
                )
                return 2
            try:
                wait_for_modules(
                    client,
                    module_ids,
                    args.wait_timeout,
                    args.poll_interval,
                )
            except (RuntimeError, TimeoutError) as exc:
                wait_error = exc
    snapshot(
        client,
        plan_ids,
        args.artifact_dir,
        target_commit,
        deployment_urls,
    )
    if wait_error is not None:
        print(str(wait_error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
