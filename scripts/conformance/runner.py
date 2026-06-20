#!/usr/bin/env python3
"""Drive the OpenID Foundation conformance suite against the ProtocolSoup OP.

This talks to the suite's automation REST API only (no UI), so it is suitable
for CI. It creates a test plan, runs every module, polls each to completion,
retains the per-module logs as artefacts, and exits non-zero on any real
failure. It never modifies, skips, or reinterprets a suite result; the suite is
the fixed reference.

Standard library only, so CI needs no extra installs.

REST API (see https://gitlab.com/openid/conformance-suite):
  GET  /api/runner/available            readiness
  POST /api/plan?planName=&variant=     create a plan from a config body
  POST /api/runner?test=&plan=&variant= start a module
  GET  /api/info/{id}                   status and result of a running module
  GET  /api/log/{id}                    full event log for a module
"""

import argparse
import fnmatch
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# The suite terminates TLS with a self-signed cert on its own nginx. We only
# disable verification for the SUITE control channel; the OP under test is
# validated by the suite itself over real TLS.
_SUITE_TLS = ssl.create_default_context()
_SUITE_TLS.check_hostname = False
_SUITE_TLS.verify_mode = ssl.CERT_NONE

TERMINAL_STATUSES = {"FINISHED", "INTERRUPTED"}
PASS_RESULTS = {"PASSED", "WARNING", "REVIEW", "SKIPPED"}
FAIL_RESULTS = {"FAILED"}


def _request(method, url, body=None):
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, context=_SUITE_TLS, timeout=60) as resp:
        raw = resp.read().decode("utf-8")
    if not raw:
        return None
    return json.loads(raw)


def wait_for_suite(suite_url, attempts=40, delay=5):
    url = f"{suite_url}/api/runner/available"
    for i in range(attempts):
        try:
            _request("GET", url)
            return True
        except (urllib.error.URLError, ConnectionError, ssl.SSLError):
            time.sleep(delay)
    return False


def create_plan(suite_url, plan_name, variant, config):
    query = {"planName": plan_name}
    if variant:
        query["variant"] = json.dumps(variant, separators=(",", ":"))
    url = f"{suite_url}/api/plan?{urllib.parse.urlencode(query)}"
    return _request("POST", url, body=config)


def start_module(suite_url, plan_id, module_name, variant):
    query = {"test": module_name, "plan": plan_id}
    if variant:
        query["variant"] = json.dumps(variant, separators=(",", ":"))
    url = f"{suite_url}/api/runner?{urllib.parse.urlencode(query)}"
    return _request("POST", url)


def poll_module(suite_url, test_id, timeout, interval=3):
    deadline = time.time() + timeout
    last = {}
    while time.time() < deadline:
        try:
            last = _request("GET", f"{suite_url}/api/info/{test_id}") or {}
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                time.sleep(interval)
                continue
            raise
        if last.get("status") in TERMINAL_STATUSES:
            return last
        time.sleep(interval)
    last["status"] = last.get("status", "TIMEOUT")
    last.setdefault("result", "TIMEOUT")
    return last


def fetch_log(suite_url, test_id):
    try:
        return _request("GET", f"{suite_url}/api/log/{test_id}")
    except urllib.error.HTTPError:
        return None


def module_names(plan):
    names = []
    for module in plan.get("modules", []):
        name = module.get("testModule") or module.get("testName") or module.get("name")
        if name:
            names.append(name)
    return names


def selected(names, include, exclude):
    out = []
    for name in names:
        if include and not any(fnmatch.fnmatch(name, pat) for pat in include):
            continue
        if exclude and any(fnmatch.fnmatch(name, pat) for pat in exclude):
            continue
        out.append(name)
    return out


def load_config(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def load_expected_failures(path):
    if not path or not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def main():
    parser = argparse.ArgumentParser(description="Run an OIDF OP conformance plan.")
    parser.add_argument("--suite-url", default=os.environ.get("CONFORMANCE_SUITE_URL", "https://localhost.emobix.co.uk:8443"))
    parser.add_argument("--plan", required=True, help="OIDF plan name, e.g. oidcc-basic-certification-test-plan")
    parser.add_argument("--variant", default=os.environ.get("OIDC_VARIANT", ""), help="JSON object of variant axes")
    parser.add_argument("--config", required=True, help="Rendered suite config JSON")
    parser.add_argument("--results-dir", default=os.environ.get("CONFORMANCE_RESULTS_DIR", ".artifacts/conformance"))
    parser.add_argument("--include", nargs="*", default=None, help="fnmatch globs to include")
    parser.add_argument("--exclude", nargs="*", default=None, help="fnmatch globs to exclude")
    parser.add_argument("--expected-failures", default=os.environ.get("CONFORMANCE_EXPECTED_FAILURES", ""))
    parser.add_argument("--strict-warnings", action="store_true", help="Treat WARNING as failure")
    parser.add_argument("--module-timeout", type=int, default=int(os.environ.get("CONFORMANCE_MODULE_TIMEOUT", "300")))
    parser.add_argument("--list-modules", action="store_true")
    args = parser.parse_args()

    variant = json.loads(args.variant) if args.variant else None
    config = load_config(args.config)
    expected_failures = load_expected_failures(args.expected_failures)

    if not wait_for_suite(args.suite_url):
        print(f"FATAL: conformance suite not reachable at {args.suite_url}", file=sys.stderr)
        return 2

    plan = create_plan(args.suite_url, args.plan, variant, config)
    plan_id = plan.get("id")
    if not plan_id:
        print(f"FATAL: plan creation returned no id: {plan}", file=sys.stderr)
        return 2

    names = module_names(plan)
    if args.list_modules:
        for name in names:
            print(name)
        return 0

    run_names = selected(names, args.include, args.exclude)
    os.makedirs(args.results_dir, exist_ok=True)

    print(f"Plan {args.plan} ({plan_id}) variant={variant or '{}'}: {len(run_names)} modules")

    results = []
    for name in run_names:
        started = start_module(args.suite_url, plan_id, name, variant)
        test_id = started.get("id") if started else None
        if not test_id:
            results.append({"module": name, "status": "ERROR", "result": "ERROR", "reason": "no test id"})
            print(f"  ERROR  {name}: could not start")
            continue
        info = poll_module(args.suite_url, test_id, args.module_timeout)
        result = info.get("result") or info.get("status")
        status = info.get("status")
        log = fetch_log(args.suite_url, test_id)
        if log is not None:
            log_path = os.path.join(args.results_dir, f"{name}.{test_id}.log.json")
            with open(log_path, "w", encoding="utf-8") as handle:
                json.dump(log, handle, indent=2)
        results.append({"module": name, "test_id": test_id, "status": status, "result": result})
        print(f"  {result:<8} {name}")

    summary = summarise(args.plan, variant, plan_id, results, expected_failures, args.strict_warnings)
    summary_path = os.path.join(args.results_dir, f"summary.{sanitise(args.plan)}.json")
    with open(summary_path, "w", encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)

    print(json.dumps(summary["counts"], indent=2))
    if summary["xpass"]:
        print(f"XPASS (stale expected-failure entries): {summary['xpass']}", file=sys.stderr)
    return 0 if summary["passed"] else 1


def sanitise(name):
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in name)


def summarise(plan, variant, plan_id, results, expected_failures, strict_warnings):
    counts = {}
    real_failures = []
    xfail = []
    xpass = []
    for entry in results:
        result = entry.get("result") or "UNKNOWN"
        counts[result] = counts.get(result, 0) + 1
        is_fail = result in FAIL_RESULTS or result in {"TIMEOUT", "ERROR", "INTERRUPTED"}
        if strict_warnings and result == "WARNING":
            is_fail = True
        module = entry["module"]
        if module in expected_failures:
            if is_fail:
                xfail.append(module)
            elif result == "PASSED":
                xpass.append(module)
            continue
        if is_fail:
            real_failures.append({"module": module, "result": result})
    return {
        "plan": plan,
        "plan_id": plan_id,
        "variant": variant or {},
        "counts": counts,
        "results": results,
        "real_failures": real_failures,
        "xfail": xfail,
        "xpass": xpass,
        "passed": len(real_failures) == 0,
    }


if __name__ == "__main__":
    sys.exit(main())
