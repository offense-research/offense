#!/usr/bin/env python3
"""Bounded Schemathesis runner. Intended only for the no-network API test image."""
import base64
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

VERSION = "4.32.4"
MAX_INPUT = 48 * 1024 * 1024
MAX_SCHEMA = 256 * 1024
METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
CHECKS = "not_a_server_error,negative_data_rejection,ignored_auth"
RULES = {
    "ignored_auth": ("security_candidate", "HIGH", "Authentication may not be enforced", "Verify the operation requires authentication; add an authentication regression and enforce it in the handler."),
    "not_a_server_error": ("robustness_candidate", "MEDIUM", "Generated input caused a server error", "Reproduce the failing input locally and determine whether it has a security impact before treating it as a vulnerability."),
    "negative_data_rejection": ("validation_candidate", "MEDIUM", "Schema-invalid input was accepted", "Review the API contract and validate rejected input at the boundary; add a focused regression."),
}
FAILURE_RULES = {"ST401": "ignored_auth", "ST101": "not_a_server_error", "ST102": "not_a_server_error", "ST201": "negative_data_rejection"}


class InvalidInput(Exception):
    pass


def bounded_int(value, default, low, high):
    if value is None:
        return default
    if type(value) is not int or not low <= value <= high:
        raise InvalidInput()
    return value


def clean_schema(raw):
    if not isinstance(raw, str) or len(raw.encode()) > MAX_SCHEMA:
        raise InvalidInput()
    import yaml
    try:
        document = yaml.safe_load(raw)
    except Exception:
        raise InvalidInput() from None
    if not isinstance(document, dict) or not str(document.get("openapi", "")).startswith(("3.0.", "3.1.")):
        raise InvalidInput()
    nodes = 0
    seen = set()

    def visit(value, depth=0):
        nonlocal nodes
        nodes += 1
        if nodes > 12000 or depth > 40:
            raise InvalidInput()
        if isinstance(value, (list, dict)):
            identity = id(value)
            if identity in seen:
                raise InvalidInput()
            seen.add(identity)
        if isinstance(value, dict):
            result = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise InvalidInput()
                if key == "$ref" and (not isinstance(item, str) or not item.startswith("#/")):
                    raise InvalidInput()
                if key in {"callbacks", "webhooks"}:
                    raise InvalidInput()
                if key in {"servers", "externalDocs"} or key.startswith("x-"):
                    continue
                result[key] = visit(item, depth + 1)
            return result
        if isinstance(value, list):
            return [visit(item, depth + 1) for item in value]
        if value is None or type(value) in {str, int, float, bool}:
            return value
        raise InvalidInput()

    document = visit(document)
    paths = document.get("paths")
    if not isinstance(paths, dict):
        raise InvalidInput()
    operations = []
    for path, item in paths.items():
        if not re.fullmatch(r"/[A-Za-z0-9_./{}~-]*", path) or path.startswith("//") or "/../" in path or not isinstance(item, dict):
            raise InvalidInput()
        for method in item:
            if method.lower() in METHODS:
                operations.append((method.upper(), path))
            elif method.lower() in {"trace", "connect"}:
                raise InvalidInput()
    if not 1 <= len(operations) <= 25:
        raise InvalidInput()
    document["servers"] = [{"url": "/"}]
    return document, operations


def base_report(seed):
    return {"schemaVersion": "purple.api-test.v1", "tool": "schemathesis", "version": VERSION,
            "status": "failed", "error": None, "findings": [], "confirmedVulnerabilities": 0,
            "reproduction": {"seed": seed, "method": "rerun_same_snapshot_schema_command_and_seed"},
            "coverage": {"scope": "isolated_loopback_app", "remoteTargets": False,
                         "checks": CHECKS.split(","), "authorization": "missing_or_invalid_auth_only",
                         "objectLevelAuthorization": "not_assessed", "crossOperationState": "not_assessed"},
            "privacy": {"automaticUpload": False, "rawRequestsSaved": False, "rawResponsesSaved": False,
                        "rawAppOutputSaved": False}}


def write_guard(folder, port, budget):
    # Each test request is checked even when HTTP keep-alive reuses a socket.
    # Network-none is the primary boundary; this additionally confines the
    # scanner to the chosen local test service and enforces a request budget.
    source = '''import http.client, socket, urllib.parse
PORT = %d
REMAINING = %d
_connect = socket.socket.connect
def connect(self, address):
    if not isinstance(address, tuple) or address[0] != "127.0.0.1" or address[1] != PORT:
        raise OSError("purple_scope_denied")
    return _connect(self, address)
socket.socket.connect = connect
_request = http.client.HTTPConnection.putrequest
def putrequest(self, method, url, *args, **kwargs):
    global REMAINING
    if self.host != "127.0.0.1" or self.port != PORT:
        raise OSError("purple_scope_denied")
    if REMAINING <= 0:
        raise OSError("purple_request_budget")
    REMAINING -= 1
    return _request(self, method, url, *args, **kwargs)
http.client.HTTPConnection.putrequest = putrequest
''' % (port, budget)
    (folder / "sitecustomize.py").write_text(source)


def normalize_raw(raw, operations, report):
    """Read the pinned CLI report without copying request data or free text."""
    # Fail closed on unknown report shapes. The adapter is tested against the
    # actual pinned report, not the human-readable terminal format.
    if not isinstance(raw, dict) or raw.get("schemathesis_version") != VERSION or not isinstance(raw.get("operations"), dict) or not isinstance(raw.get("test_cases"), dict) or not isinstance(raw.get("failures"), list) or not isinstance(raw.get("errors"), list):
        raise InvalidInput()
    counters = raw["operations"]
    cases = raw["test_cases"]
    for name in ["total", "selected", "tested", "errored", "skipped"]:
        if type(counters.get(name)) is not int or not 0 <= counters[name] <= 1000:
            raise InvalidInput()
    for name in ["generated", "with_failures", "without_checks", "errored"]:
        if type(cases.get(name)) is not int or not 0 <= cases[name] <= 100000:
            raise InvalidInput()
    report["coverage"]["declaredOperations"] = len(operations)
    report["coverage"]["testedOperations"] = counters["tested"]
    report["coverage"]["generatedCases"] = cases["generated"]
    report["coverage"]["casesWithoutChecks"] = cases["without_checks"]
    report["coverage"]["boundedRun"] = True
    report["coverage"]["budgetReached"] = raw.get("stop_reason") in {"max_time", "max_failures"}
    known = {method + " " + path: (index, method) for index, (method, path) in enumerate(operations)}
    findings = []
    unknown = False
    for failure in raw["failures"][:100]:
        if not isinstance(failure, dict) or not isinstance(failure.get("operations"), list):
            raise InvalidInput()
        code = failure.get("code")
        rule = FAILURE_RULES.get(code)
        if not rule:
            unknown = True
            continue
        kind, severity, title, remediation = RULES[rule]
        for operation in failure["operations"]:
            if operation not in known:
                unknown = True
                continue
            index, method = known[operation]
            findings.append({"id": hashlib.sha256((str(index) + ":" + code).encode()).hexdigest()[:32],
                             "tool": "schemathesis", "ruleId": rule, "code": code,
                             "operationIndex": index, "method": method, "severity": severity,
                             "kind": kind, "title": title, "remediation": remediation,
                             "verification": "requires_review_and_focused_regression", "confirmed": False})
    report["findings"] = list({item["id"]: item for item in findings}.values())
    warnings = raw.get("warnings", {})
    rates = raw.get("valid_rates", {})
    if not isinstance(warnings, dict) or not isinstance(rates, dict):
        raise InvalidInput()
    # Keep setup, reachability and generation failures separate from findings.
    incomplete = (raw.get("complete") is not True or counters["tested"] != len(operations) or counters["selected"] != len(operations)
                  or counters["errored"] > 0 or counters["skipped"] > 0 or cases["errored"] > 0 or cases["generated"] <= cases["without_checks"]
                  or len(raw["errors"]) > 0 or len(raw["failures"]) > 100 or unknown)
    meaningful_warnings = any(bool(value) for key, value in warnings.items() if key not in {"unused_openapi_auth"})
    accepted_operations = 0
    for operation in known:
        data = rates.get(operation, {})
        if isinstance(data, dict) and any(isinstance(phase, dict) and type(phase.get("accepted")) is int and phase["accepted"] > 0 for phase in data.values()):
            accepted_operations += 1
    report["coverage"]["operationsAcceptingValidInputs"] = accepted_operations
    # A server that only returns errors or rejects our synthetic test identity
    # cannot establish normal behavior or a complete authentication assessment.
    incomplete = incomplete or accepted_operations != len(operations) or meaningful_warnings
    report["status"] = "partial" if incomplete else "complete"
    report["error"] = "test_coverage_incomplete" if incomplete else None


def test_token(payload):
    token = payload.get("testToken")
    if not isinstance(token, str) or not re.fullmatch("[a-f0-9]{64}", token):
        raise InvalidInput()
    return token


def environment(directory, port, token):
    return {"PATH": "/opt/purple/api-venv/bin:/usr/local/bin:/usr/bin:/bin", "HOME": str(directory), "TMPDIR": str(directory),
            "LANG": "C.UTF-8", "PORT": str(port), "HOST": "127.0.0.1", "NODE_ENV": "test", "PYTHONDONTWRITEBYTECODE": "1",
            "PURPLE_TEST_TOKEN": token}


def run_app(payload):
    """Executes only in the separate app container; sees no scanner files."""
    directory = Path(tempfile.mkdtemp(prefix="purple-app-"))
    process = None
    try:
        port = bounded_int(payload.get("port"), 8765, 1024, 65535)
        seconds = bounded_int(payload.get("seconds"), 20, 5, 120)
        token = test_token(payload)
        command = payload.get("command")
        if not isinstance(command, list) or not 1 <= len(command) <= 32 or any(not isinstance(v, str) or not 1 <= len(v) <= 1000 or "\x00" in v for v in command):
            raise InvalidInput()
        if command[0] not in {"node", "python3"}:
            raise InvalidInput()
        app = directory / "app"
        app.mkdir()
        total, names = 0, set()
        files = payload.get("files")
        if not isinstance(files, list) or not 1 <= len(files) <= 5000:
            raise InvalidInput()
        for file in files:
            name = file.get("path") if isinstance(file, dict) else None
            if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_@+./-]{1,500}", name) or name.startswith("/") or any(p in {"", ".", ".."} or p.startswith(".") for p in name.split("/")) or name in names:
                raise InvalidInput()
            names.add(name)
            try:
                content = base64.b64decode(file.get("contentBase64", ""), validate=True)
            except Exception:
                raise InvalidInput() from None
            total += len(content)
            if len(content) > 8 * 1024 * 1024 or total > 32 * 1024 * 1024:
                raise InvalidInput()
            target = app / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        process = subprocess.Popen(command, cwd=app, env=environment(directory, port, token), stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        try:
            process.wait(timeout=seconds + 30)
        except subprocess.TimeoutExpired:
            pass
    finally:
        if process and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
            except Exception:
                pass
        shutil.rmtree(directory, ignore_errors=True)


def run(payload):
    seed = bounded_int(payload.get("seed"), 1729, 0, 4294967295)
    report = base_report(seed)
    directory = Path(tempfile.mkdtemp(prefix="purple-api-"))
    try:
        if importlib.metadata.version("schemathesis") != VERSION:
            report["error"] = "scanner_version_mismatch"
            return report
        port = bounded_int(payload.get("port"), 8765, 1024, 65535)
        examples = bounded_int(payload.get("examples"), 10, 1, 50)
        seconds = bounded_int(payload.get("seconds"), 20, 5, 120)
        requests = bounded_int(payload.get("maxRequests"), 200, 10, 1000)
        document, operations = clean_schema(payload.get("schema"))
        token = test_token(payload)
        schema = directory / "schema.json"
        schema.write_text(json.dumps(document))
        config = directory / "operator.toml"
        config.write_text("")
        guard = directory / "guard"
        guard.mkdir()
        write_guard(guard, port, requests)
        env = environment(directory, port, token)
        ready_deadline = time.monotonic() + 10
        ready = False
        while time.monotonic() < ready_deadline:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    ready = True
                    break
            except OSError:
                time.sleep(0.05)
        if not ready:
            report["error"] = "app_start_failed"
            return report
        raw_report = directory / "raw.json"
        argv = ["/opt/purple/api-venv/bin/schemathesis", "--config-file", str(config), "--no-color", "run", str(schema),
                "--url", "http://127.0.0.1:%d" % port, "--workers", "1", "--phases", "examples,fuzzing", "--mode", "all",
                "--checks", CHECKS, "--max-examples", str(examples), "--max-time", str(seconds), "--seed", str(seed),
                "--max-failures", "20", "--request-timeout", "1", "--request-retries", "0", "--max-redirects", "0",
                "--rate-limit", "10/s", "--generation-database", "none", "--header", "Authorization: Bearer " + token,
                "--report", "json", "--report-json-path", str(raw_report), "--output-sanitize", "true"]
        scanner_env = {**env, "PYTHONPATH": str(guard)}
        try:
            result = subprocess.run(argv, cwd=directory, env=scanner_env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, timeout=seconds + 15)
        except subprocess.TimeoutExpired:
            report["status"], report["error"] = "partial", "test_budget_exhausted"
            return report
        if not raw_report.is_file() or raw_report.stat().st_size > 8 * 1024 * 1024:
            report["error"] = "scanner_report_unavailable"
            return report
        raw = json.loads(raw_report.read_text())
        if result.returncode not in {0, 1}:
            report["error"] = "scanner_execution_failed"
            return report
        normalize_raw(raw, operations, report)
        return report
    except InvalidInput:
        report["error"] = "invalid_test_input"
        return report
    except Exception:
        report["error"] = "sandbox_setup_failed"
        return report
    finally:
        shutil.rmtree(directory, ignore_errors=True)


if __name__ == "__main__":
    try:
        encoded = sys.stdin.buffer.read(MAX_INPUT + 1)
        if len(encoded) > MAX_INPUT:
            raise InvalidInput()
        payload = json.loads(encoded)
        if not isinstance(payload, dict):
            raise InvalidInput()
        if sys.argv[1:] == ["--app"]:
            run_app(payload)
            sys.exit(0)
        output = run(payload)
    except Exception:
        output = {**base_report(1729), "error": "invalid_test_input"}
    print(json.dumps(output, separators=(",", ":")))
