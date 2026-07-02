#!/usr/bin/env python3

"""Execute an approved SQL bug-reproduction plan in disposable MySQL containers."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import platform
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from bug_verification_triage import (
    AFFECTED_LABELS,
    SECURITY_LABELS,
    TRIAGE_MARKER,
    TRIAGE_BOT,
    AssessmentError,
    github_request,
    issue_declares_security,
    list_issue_comments,
    parse_model_output,
)


RUN_LABEL = "verification:run"
RUN_MARKER = "<!-- mysql-bug-verification-run:v1 -->"
MYSQL_IMAGE_TAGS = {
    "8.4": {"amd64": "8.4", "arm64": "8.4-aarch64"},
    "9.7": {"amd64": "9.7", "arm64": "9.7-aarch64"},
}
COMMAND_TIMEOUT_SECONDS = 30
STARTUP_TIMEOUT_SECONDS = 120
PULL_TIMEOUT_SECONDS = 300
MAX_CAPTURE_BYTES = 64_000
MAX_COMMENT_OUTPUT_BYTES = 4_000
ERROR_CODE = re.compile(r"(?im)\bERROR\s+(\d+)\b")
ASSESSMENT_JSON = re.compile(r"<pre>(.*?)</pre>", re.DOTALL)
IMAGE_DIGEST = re.compile(
    r"^container-registry\.oracle\.com/mysql/community-server@sha256:[0-9a-f]{64}$"
)


@dataclass
class CommandResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    stdout_truncated: bool = False
    stderr_truncated: bool = False


@dataclass
class StepResult:
    step_id: str
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


class CappedCapture:
    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.data = bytearray()
        self.truncated = False

    def drain(self, stream: Any) -> None:
        while True:
            chunk = stream.read(8192)
            if not chunk:
                return
            remaining = self.limit - len(self.data)
            if remaining > 0:
                self.data.extend(chunk[:remaining])
            if len(chunk) > remaining:
                self.truncated = True

    def text(self) -> str:
        return self.data.decode("utf-8", errors="replace")


def run_command(
    command: list[str],
    *,
    input_text: str | None = None,
    timeout: int = COMMAND_TIMEOUT_SECONDS,
) -> CommandResult:
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    assert process.stdout is not None
    assert process.stderr is not None
    stdout = CappedCapture(MAX_CAPTURE_BYTES)
    stderr = CappedCapture(MAX_CAPTURE_BYTES)
    readers = [
        threading.Thread(target=stdout.drain, args=(process.stdout,), daemon=True),
        threading.Thread(target=stderr.drain, args=(process.stderr,), daemon=True),
    ]
    for reader in readers:
        reader.start()

    if input_text is not None:
        assert process.stdin is not None
        try:
            process.stdin.write(input_text.encode("utf-8"))
            process.stdin.close()
        except BrokenPipeError:
            pass

    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
    except KeyboardInterrupt:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()
        raise
    for reader in readers:
        reader.join(timeout=5)

    return CommandResult(
        returncode=process.returncode,
        stdout=stdout.text(),
        stderr=stderr.text(),
        timed_out=timed_out,
        stdout_truncated=stdout.truncated,
        stderr_truncated=stderr.truncated,
    )


def affected_lines(labels: set[str]) -> set[str]:
    return {line for label, line in AFFECTED_LABELS.items() if label in labels}


def mysql_image(line: str, machine: str | None = None) -> str:
    architecture = machine or platform.machine()
    normalized = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(architecture.lower())
    if normalized is None:
        raise AssessmentError(f"unsupported runner architecture {architecture!r}")
    tag = MYSQL_IMAGE_TAGS[line][normalized]
    return f"container-registry.oracle.com/mysql/community-server:{tag}"


def find_bot_triage_comment(comments: list[dict[str, Any]]) -> dict[str, Any] | None:
    matches = [
        comment
        for comment in comments
        if TRIAGE_MARKER in (comment.get("body") or "")
        and comment.get("user", {}).get("login") == TRIAGE_BOT
    ]
    return max(matches, key=lambda comment: int(comment.get("id", 0)), default=None)


def assessment_from_comment(
    comment: dict[str, Any], allowed_lines: set[str]
) -> dict[str, Any]:
    body = comment.get("body") or ""
    match = ASSESSMENT_JSON.search(body)
    if not match:
        raise AssessmentError("the triage comment does not contain a structured assessment")
    raw = html.unescape(match.group(1))
    assessment = parse_model_output(raw, allowed_lines)
    classification = assessment["classification"]
    if classification["security_sensitive"]:
        raise AssessmentError("security-sensitive assessments cannot be executed")
    if classification["automation_readiness"] != "ready":
        raise AssessmentError("the assessment is not marked ready for automation")
    if assessment["recommended_harness"] != "sql-single-server":
        raise AssessmentError("only the sql-single-server harness is currently supported")
    if not assessment["recommended_targets"]:
        raise AssessmentError("the assessment does not recommend an execution target")
    return assessment


def github_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str):
        raise AssessmentError(f"{field} is missing")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise AssessmentError(f"{field} is invalid") from error


def ensure_assessment_predates_run(
    triage_comment: dict[str, Any], issue_snapshot: dict[str, Any]
) -> None:
    assessed_at = github_timestamp(triage_comment.get("updated_at"), "triage updated_at")
    run_requested_at = github_timestamp(issue_snapshot.get("updated_at"), "issue updated_at")
    if assessed_at > run_requested_at:
        raise AssessmentError(
            "the triage assessment changed after verification:run was requested; "
            "remove and reapply the label after reviewing the new assessment"
        )


def assessment_digest(assessment: dict[str, Any]) -> str:
    canonical = json.dumps(assessment, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def mysql_client_command(container: str, user: str, *, database: bool = True) -> list[str]:
    command = [
        "docker",
        "exec",
        "-i",
        container,
        "mysql",
        "--protocol=socket",
        f"--user={user}",
        "--batch",
        "--raw",
        "--skip-column-names",
        "--local-infile=0",
    ]
    if database:
        command.append("--database=verification")
    return command


def run_sql(
    container: str, sql: str, *, user: str = "verifier", database: bool = True
) -> CommandResult:
    return run_command(
        mysql_client_command(container, user, database=database), input_text=sql
    )


def image_mysql_identity(digest: str) -> tuple[int, int]:
    values: list[int] = []
    for flag in ("-u", "-g"):
        inspected = run_command(
            [
                "docker",
                "run",
                "--rm",
                "--network=none",
                "--entrypoint=id",
                digest,
                flag,
                "mysql",
            ],
            timeout=15,
        )
        value = inspected.stdout.strip()
        if inspected.returncode != 0 or not value.isdecimal():
            raise AssessmentError(
                f"could not determine the mysql account identity in {digest}"
            )
        values.append(int(value))
    return values[0], values[1]


def start_mysql_container(image: str, container: str) -> str:
    print(f"Pulling {image} from Oracle Container Registry...", flush=True)
    pulled = run_command(["docker", "pull", image], timeout=PULL_TIMEOUT_SECONDS)
    if pulled.timed_out or pulled.returncode != 0:
        raise AssessmentError(f"could not pull {image}: {pulled.stderr.strip()[:1000]}")
    print("Image pull completed; resolving immutable digest...", flush=True)

    inspected = run_command(
        ["docker", "image", "inspect", "--format={{index .RepoDigests 0}}", image],
        timeout=15,
    )
    digest = inspected.stdout.strip()
    if inspected.returncode != 0 or not IMAGE_DIGEST.fullmatch(digest):
        raise AssessmentError(f"could not resolve an immutable digest for {image}")
    mysql_uid, mysql_gid = image_mysql_identity(digest)

    print(
        f"Starting isolated MySQL container from {digest} "
        f"as mysql UID {mysql_uid}, GID {mysql_gid}...",
        flush=True,
    )
    started = run_command(
        [
            "docker",
            "run",
            "--detach",
            "--name",
            container,
            "--pull=never",
            "--network=none",
            "--read-only",
            "--cap-drop=ALL",
            "--cap-add=CHOWN",
            "--cap-add=DAC_OVERRIDE",
            "--cap-add=FOWNER",
            "--cap-add=SETGID",
            "--cap-add=SETUID",
            "--security-opt=no-new-privileges:true",
            "--pids-limit=256",
            "--memory=1536m",
            "--cpus=2",
            "--ulimit=nofile=4096:4096",
            f"--tmpfs=/var/lib/mysql:rw,nosuid,nodev,uid={mysql_uid},gid={mysql_gid},mode=0750,size=1g",
            f"--tmpfs=/var/lib/mysql-files:rw,nosuid,nodev,uid={mysql_uid},gid={mysql_gid},mode=0750,size=64m",
            f"--tmpfs=/var/run/mysqld:rw,nosuid,nodev,uid={mysql_uid},gid={mysql_gid},mode=0750,size=16m",
            "--tmpfs=/tmp:rw,nosuid,nodev,noexec,mode=1777,size=256m",
            "--env=MYSQL_ALLOW_EMPTY_PASSWORD=yes",
            digest,
            "--skip-log-bin",
            "--local-infile=OFF",
            "--max-connections=20",
            "--innodb-buffer-pool-size=256M",
        ],
        timeout=COMMAND_TIMEOUT_SECONDS,
    )
    if started.timed_out or started.returncode != 0:
        raise AssessmentError(f"could not start {image}: {started.stderr.strip()[:1000]}")

    print("Waiting for MySQL initialization...", flush=True)
    deadline = time.monotonic() + STARTUP_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        ping = run_command(
            ["docker", "exec", container, "mysqladmin", "--protocol=socket", "-uroot", "ping", "--silent"],
            timeout=5,
        )
        if ping.returncode == 0:
            break
        state = run_command(
            ["docker", "inspect", "--format={{.State.Running}}", container],
            timeout=5,
        )
        if state.returncode == 0 and state.stdout.strip() == "false":
            logs = run_command(["docker", "logs", container], timeout=10)
            raise AssessmentError(f"{image} exited during startup: {logs.stderr[-1000:]}")
        time.sleep(2)
    else:
        logs = run_command(["docker", "logs", container], timeout=10)
        raise AssessmentError(f"{image} did not become ready: {logs.stderr[-1000:]}")

    bootstrap = run_sql(
        container,
        "CREATE DATABASE verification;"
        "CREATE USER 'verifier'@'localhost';"
        "GRANT ALL PRIVILEGES ON verification.* TO 'verifier'@'localhost';",
        user="root",
        database=False,
    )
    if bootstrap.timed_out or bootstrap.returncode != 0:
        raise AssessmentError(f"could not create the verification database: {bootstrap.stderr[:1000]}")
    print("MySQL is ready.", flush=True)
    return digest


def stop_container(container: str) -> None:
    run_command(["docker", "rm", "--force", container], timeout=15)


def normalize_cell(value: Any) -> str:
    if value is None:
        return "NULL"
    if value is True:
        return "1"
    if value is False:
        return "0"
    return str(value)


def output_rows(output: str) -> list[list[str]]:
    if not output:
        return []
    return [line.split("\t") for line in output.splitlines()]


def evaluate_assertion(assertion: dict[str, Any], result: StepResult) -> tuple[bool, str]:
    assertion_type = assertion["type"]
    if result.timed_out:
        return False, "step timed out"
    if assertion_type == "statement_succeeds":
        return result.returncode == 0, f"exit code was {result.returncode}"
    if assertion_type == "statement_fails":
        return result.returncode != 0, f"exit code was {result.returncode}"
    if assertion_type == "error_code":
        found = [int(value) for value in ERROR_CODE.findall(result.stderr)]
        expected = assertion["value"]
        return expected in found, f"expected error {expected}; observed {found or 'none'}"
    if assertion_type == "row_count":
        observed = len(output_rows(result.stdout))
        expected = assertion["value"]
        return observed == expected, f"expected {expected} rows; observed {observed}"
    if assertion_type == "rows_equal":
        observed = output_rows(result.stdout)
        expected = [[normalize_cell(cell) for cell in row] for row in assertion["value"]]
        return observed == expected, f"expected {expected!r}; observed {observed!r}"
    if assertion_type == "output_contains":
        expected = assertion["value"]
        combined = result.stdout + "\n" + result.stderr
        return expected in combined, f"expected output to contain {expected!r}"
    raise AssessmentError(f"unsupported assertion type {assertion_type!r}")


def execute_target(line: str, assessment: dict[str, Any], issue_number: int) -> dict[str, Any]:
    image = mysql_image(line)
    container = f"mysql-bug-{issue_number}-{line.replace('.', '-')}-{secrets.token_hex(4)}"
    started_at = datetime.now(timezone.utc)
    timer = time.monotonic()
    result: dict[str, Any] = {
        "line": line,
        "requested_image": image,
        "repetition": 1,
        "started_at": started_at.isoformat(),
        "isolation": {
            "network": "none",
            "read_only_root": True,
            "database_user": "verifier@localhost",
            "memory_limit": "1536m",
            "cpu_limit": 2,
            "process_limit": 256,
            "command_timeout_seconds": COMMAND_TIMEOUT_SECONDS,
        },
        "status": "infrastructure_error",
        "steps": [],
        "assertions": [],
        "cleanup": None,
    }
    try:
        result["image_digest"] = start_mysql_container(image, container)
        server = run_sql(
            container,
            "SELECT VERSION(), @@version_comment, @@version_compile_machine;",
        )
        if server.timed_out or server.returncode != 0:
            raise AssessmentError(f"could not identify the MySQL server: {server.stderr[:1000]}")
        rows = output_rows(server.stdout)
        if len(rows) != 1 or len(rows[0]) != 3:
            raise AssessmentError("MySQL server identity returned an unexpected result")
        result["server"] = {
            "version": rows[0][0],
            "version_comment": rows[0][1],
            "compile_machine": rows[0][2],
        }
        reproduction = assessment["reproduction"]
        setup = reproduction["setup_sql"]
        if setup is not None:
            setup_result = run_sql(container, setup["content"])
            result["setup"] = command_summary(setup_result)
            if setup_result.timed_out or setup_result.returncode != 0:
                result["status"] = "setup_failed"
                return result

        step_results: dict[str, StepResult] = {}
        for step in reproduction["steps"]:
            command = run_sql(container, step["sql"])
            step_result = StepResult(
                step_id=step["id"],
                returncode=command.returncode,
                stdout=command.stdout,
                stderr=command.stderr,
                timed_out=command.timed_out,
            )
            step_results[step["id"]] = step_result
            result["steps"].append(
                {"id": step["id"], **command_summary(command)}
            )
            if command.timed_out:
                result["status"] = "step_timed_out"
                return result

        control = reproduction["control_sql"]
        if control is not None:
            result["control"] = command_summary(run_sql(container, control["content"]))

        passed = True
        for assertion in assessment["reproduction_assertions"]:
            assertion_passed, detail = evaluate_assertion(
                assertion, step_results[assertion["step_id"]]
            )
            passed = passed and assertion_passed
            result["assertions"].append(
                {
                    "step_id": assertion["step_id"],
                    "type": assertion["type"],
                    "passed": assertion_passed,
                    "detail": detail[:2_000],
                }
            )
        result["status"] = "reproduced" if passed else "not_reproduced"
        return result
    except (AssessmentError, OSError) as error:
        result["error"] = str(error)
        return result
    finally:
        cleanup = assessment["reproduction"]["cleanup_sql"]
        if cleanup is not None:
            try:
                result["cleanup"] = command_summary(run_sql(container, cleanup["content"]))
            except OSError as error:
                result["cleanup"] = {"error": str(error)}
        stop_container(container)
        result["finished_at"] = datetime.now(timezone.utc).isoformat()
        result["duration_seconds"] = round(time.monotonic() - timer, 3)


def command_summary(result: CommandResult) -> dict[str, Any]:
    return {
        "returncode": result.returncode,
        "timed_out": result.timed_out,
        "stdout": result.stdout[:MAX_COMMENT_OUTPUT_BYTES],
        "stderr": result.stderr[:MAX_COMMENT_OUTPUT_BYTES],
        "output_truncated": result.stdout_truncated or result.stderr_truncated,
    }


def render_results(digest: str, results: list[dict[str, Any]]) -> str:
    lines = [
        RUN_MARKER,
        "",
        "### Automated reproduction results",
        "",
        f"- Approved assessment: `{digest}`",
    ]
    server_url = os.environ.get("GITHUB_SERVER_URL")
    repository = os.environ.get("GITHUB_REPOSITORY")
    run_id = os.environ.get("GITHUB_RUN_ID")
    if server_url and repository and run_id:
        lines.append(f"- Workflow run: {server_url}/{repository}/actions/runs/{run_id}")
    for target in results:
        lines.append(f"- MySQL {target['line']}: `{target['status']}`")
    lines.extend(
        [
            "",
            "`reproduced` means the approved assertions matched in the disposable test environment. It does not assign the official `Verified` status.",
            "",
        ]
    )
    for target in results:
        safe = html.escape(json.dumps(target, indent=2, ensure_ascii=False))
        if len(safe) > 50_000:
            safe = safe[:50_000] + "\n… execution details truncated …"
        lines.extend(
            [
                f"<details><summary>MySQL {target['line']} execution details</summary>",
                "",
                f"<pre>{safe}</pre>",
                "",
                "</details>",
                "",
            ]
        )
    return "\n".join(lines)


def find_run_comment(comments: list[dict[str, Any]]) -> dict[str, Any] | None:
    return next(
        (
            comment
            for comment in comments
            if RUN_MARKER in (comment.get("body") or "")
            and comment.get("user", {}).get("login") == TRIAGE_BOT
        ),
        None,
    )


def upsert_run_comment(
    repository: str, issue_number: int, body: str, comments: list[dict[str, Any]]
) -> None:
    existing = find_run_comment(comments)
    if existing:
        github_request(
            "PATCH", f"/repos/{repository}/issues/comments/{existing['id']}", {"body": body}
        )
    else:
        github_request("POST", f"/repos/{repository}/issues/{issue_number}/comments", {"body": body})


def run_github_event(event_path: Path) -> None:
    payload = json.loads(event_path.read_text(encoding="utf-8"))
    issue = payload.get("issue")
    repository = payload.get("repository", {}).get("full_name")
    event_label = payload.get("label", {}).get("name")
    if not isinstance(issue, dict) or not repository:
        raise AssessmentError("GitHub event does not contain an issue and repository")
    if event_label != RUN_LABEL:
        raise AssessmentError(f"GitHub event label must be {RUN_LABEL!r}")
    issue_number = issue.get("number")
    if not isinstance(issue_number, int):
        raise AssessmentError("GitHub issue number is missing")
    if issue.get("state") != "open":
        raise AssessmentError("only open issues can be executed")

    labels = {
        label.get("name") for label in issue.get("labels", []) if isinstance(label, dict)
    }
    body = issue.get("body") or ""
    if labels & SECURITY_LABELS or issue_declares_security(body):
        raise AssessmentError("security-sensitive reports cannot be executed")
    lines = affected_lines(labels)
    if not lines:
        raise AssessmentError("an affected:8.4 or affected:9.7 label is required")

    comments = list_issue_comments(repository, issue_number)
    triage_comment = find_bot_triage_comment(comments)
    if triage_comment is None:
        raise AssessmentError("no GitHub Actions triage assessment was found")
    ensure_assessment_predates_run(triage_comment, issue)
    assessment = assessment_from_comment(triage_comment, lines)
    targets = sorted({target["line"] for target in assessment["recommended_targets"]})
    results = [execute_target(line, assessment, issue_number) for line in targets]
    upsert_run_comment(
        repository,
        issue_number,
        render_results(assessment_digest(assessment), results),
        comments,
    )
    if any(result["status"] not in {"reproduced", "not_reproduced"} for result in results):
        raise AssessmentError("one or more execution targets had an infrastructure failure")


def self_test() -> None:
    if not mysql_image("8.4", "x86_64").endswith(":8.4"):
        raise AssertionError("x86_64 image selection failed")
    if not mysql_image("8.4", "aarch64").endswith(":8.4-aarch64"):
        raise AssertionError("ARM64 image selection failed")
    command = run_command([sys.executable, "-c", "print('capture-ok')"], timeout=5)
    if command.returncode != 0 or command.stdout != "capture-ok\n":
        raise AssertionError("capped command capture failed")
    timeout = run_command(
        [sys.executable, "-c", "import time; time.sleep(5)"], timeout=1
    )
    if not timeout.timed_out:
        raise AssertionError("command timeout failed")
    if output_rows("\n") != [[""]]:
        raise AssertionError("an empty SQL value must still count as one row")
    sample = StepResult("select_rows", 0, "10\n20\n", "")
    passed, _ = evaluate_assertion(
        {"step_id": "select_rows", "type": "rows_equal", "value": [[10], [20]]}, sample
    )
    if not passed:
        raise AssertionError("numeric row normalization failed")
    passed, _ = evaluate_assertion(
        {"step_id": "select_rows", "type": "row_count", "value": 2}, sample
    )
    if not passed:
        raise AssertionError("row count assertion failed")
    failure = StepResult("bad_insert", 1, "", "ERROR 3819 (HY000): constraint violated")
    for assertion in (
        {"step_id": "bad_insert", "type": "statement_fails"},
        {"step_id": "bad_insert", "type": "error_code", "value": 3819},
    ):
        passed, _ = evaluate_assertion(assertion, failure)
        if not passed:
            raise AssertionError(f"assertion failed: {assertion['type']}")

    assessment = {
        "schema_version": 2,
        "classification": {
            "bug_class": "ddl-dml",
            "security_sensitive": False,
            "automation_readiness": "ready",
            "confidence": 0.9,
        },
        "reported_environment": {},
        "missing_information": [],
        "reproduction": {
            "setup_sql": {"source": "reported", "content": "CREATE TABLE t(a INT);"},
            "steps": [{"id": "select_rows", "source": "reported", "sql": "SELECT a FROM t;"}],
            "control_sql": None,
            "cleanup_sql": {"source": "reported", "content": "DROP TABLE t;"},
        },
        "expected_behavior": {"source": "reported", "description": "No rows."},
        "actual_behavior": {"source": "reported", "description": "Two rows."},
        "reproduction_assertions": [
            {"step_id": "select_rows", "type": "row_count", "value": 2}
        ],
        "recommended_harness": "sql-single-server",
        "recommended_targets": [{"line": "8.4", "basis": "authorized"}],
        "review_notes": [],
    }
    body = "\n".join(
        [TRIAGE_MARKER, "<pre>", html.escape(json.dumps(assessment)), "</pre>"]
    )
    parsed = assessment_from_comment({"body": body}, {"8.4"})
    if assessment_digest(parsed) != assessment_digest(assessment):
        raise AssertionError("assessment comment round trip failed")
    ensure_assessment_predates_run(
        {"updated_at": "2026-07-02T10:00:00Z"},
        {"updated_at": "2026-07-02T10:01:00Z"},
    )
    try:
        ensure_assessment_predates_run(
            {"updated_at": "2026-07-02T10:02:00Z"},
            {"updated_at": "2026-07-02T10:01:00Z"},
        )
    except AssessmentError as error:
        if "changed after" not in str(error):
            raise
    else:
        raise AssertionError("a post-approval assessment change should be rejected")
    print("self-test passed")


def container_smoke_test(line: str) -> None:
    image = mysql_image(line)
    container = f"mysql-bug-smoke-{line.replace('.', '-')}-{secrets.token_hex(4)}"
    try:
        digest = start_mysql_container(image, container)
        query = run_sql(
            container,
            "SELECT VERSION(), @@version_comment, @@version_compile_machine;",
        )
        if query.timed_out or query.returncode != 0:
            raise AssessmentError(f"smoke-test query failed: {query.stderr[:1000]}")
        print(
            json.dumps(
                {
                    "requested_image": image,
                    "image_digest": digest,
                    "server": output_rows(query.stdout),
                },
                indent=2,
            )
        )
    finally:
        stop_container(container)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--github-event", type=Path, help="process an issues:labeled event")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument(
        "--container-smoke-test",
        choices=sorted(MYSQL_IMAGE_TAGS),
        metavar="VERSION_LINE",
        help="start an Oracle Registry MySQL image and run a server identity query",
    )
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    if args.container_smoke_test:
        container_smoke_test(args.container_smoke_test)
        return 0
    if args.github_event is None:
        parser.error(
            "--github-event is required unless --self-test or --container-smoke-test is used"
        )
    run_github_event(args.github_event)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssessmentError, OSError, UnicodeError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
