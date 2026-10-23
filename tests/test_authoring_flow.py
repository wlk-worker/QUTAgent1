"""Contract tests for the authoring controller and the participation flow.

No real platform is contacted: every request goes to a loopback mock server or
to an injected opener that records that it was never called.
"""
from __future__ import annotations

import io
import json
import os
import re
import sys
import tarfile
import tempfile
import threading
import unittest
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# The DSH Windows sandbox maps POSIX mode 0o700 directories to a Windows ACL
# the sandboxed process itself cannot write, so tempfile.mkdtemp() would create
# unusable directories. Widen only that exact mode inside this test process;
# this is a test-environment compatibility shim (a no-op outside that sandbox),
# not product behaviour. unittest discovery imports this module first, so the
# same process-wide shim also keeps the pre-existing tempfile-based tests
# runnable in the sandbox.
if os.name == "nt":  # pragma: no cover - environment-specific
    _REAL_OS_MKDIR = os.mkdir

    def _sandbox_safe_mkdir(path, mode=0o777, **kwargs):
        if mode == 0o700:
            mode = 0o750
        return _REAL_OS_MKDIR(path, mode, **kwargs)

    os.mkdir = _sandbox_safe_mkdir

from author import controller  # noqa: E402
from author.controller import (  # noqa: E402
    BlockedError,
    MultipartFile,
    PlatformHttp,
    RefusedError,
    Tooling,
    build_archive,
    discover_tooling,
    encode_multipart,
    plan_checks,
    poll_authored_status,
    run_authoring_flow,
    validate_slug,
)
from author.generate import generate  # noqa: E402

sys.path.insert(0, str(ROOT / "scripts"))
import platform_flow  # noqa: E402

TOKEN = "fixture-secret-platform-token-0123456789"
FLAG_PATTERN = re.compile(r"(?:ctfy|flag)\{[^}]*\}")


# ---------------------------------------------------------------------------
# Injected transports
# ---------------------------------------------------------------------------


class OpenerSpy:
    """An opener that fails the test if any request is attempted."""

    def __init__(self) -> None:
        self.calls = 0

    def open(self, request, timeout=None):  # noqa: ARG002
        self.calls += 1
        raise AssertionError(f"unexpected network request: {request.full_url}")


class MockPlatform:
    """Loopback HTTP server whose response is supplied by ``responder``."""

    def __init__(self, responder):
        self.requests: list[dict] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _handle(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                outer.requests.append({
                    "method": self.command,
                    "path": self.path,
                    "headers": {key.lower(): value for key, value in self.headers.items()},
                    "body": body,
                })
                status, payload, content_type = responder(
                    self.command, self.path, dict(self.headers), body)
                if isinstance(payload, (dict, list)):
                    raw = json.dumps(payload).encode("utf-8")
                    content_type = content_type or "application/json"
                elif isinstance(payload, bytes):
                    raw = payload
                else:
                    raw = str(payload or "").encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", content_type or "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            do_GET = _handle
            do_POST = _handle

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()

    def of(self, method: str) -> list[dict]:
        return [item for item in self.requests if item["method"] == method]


def _fake_run(responses):
    """A subprocess.run stand-in driven by ``(exit_code, stdout)`` tuples."""
    calls: list[list[str]] = []

    def run(command, **kwargs):  # noqa: ARG001
        calls.append(list(command))
        if responses:
            code, output = responses.pop(0)
        else:
            code, output = 0, ""
        return SimpleNamespace(returncode=code, stdout=output, stderr="")

    run.calls = calls
    return run


def _package(root: Path, seed: int = 46) -> Path:
    return generate(Path(root) / f"document-desk-{seed}", seed)


def _report_json(report) -> str:
    return json.dumps(report, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Packaging / slug unit tests
# ---------------------------------------------------------------------------


class PackagingTests(unittest.TestCase):
    def test_archive_is_deterministic_lf_and_excludes_build_junk(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            package = _package(root / "generated", 46)
            # Build junk and a CRLF script that must be normalised.
            (package / "__pycache__").mkdir()
            (package / "__pycache__" / "junk.pyc").write_bytes(b"junk")
            (package / "node_modules").mkdir()
            (package / "node_modules" / "dep.js").write_text("x")
            (package / "services" / "flag-rotator" / "rotate.sh").write_bytes(
                b"#!/bin/sh\r\necho hi\r\n")
            first = build_archive(package, root / "first.tar.gz")
            second = build_archive(package, root / "second.tar.gz")
            self.assertEqual(first["sha256"], second["sha256"])
            self.assertIn("services/flag-rotator/rotate.sh", first["members"])
            self.assertTrue(any(item.startswith("__pycache__/") for item in first["skipped"]))
            self.assertTrue(any(item.startswith("node_modules/") for item in first["skipped"]))
            self.assertEqual(first["crlf_normalised"], ["services/flag-rotator/rotate.sh"])
            with tarfile.open(first["path"], "r:gz") as archive:
                names = archive.getnames()
            self.assertTrue(all(name.startswith("document-desk-46/") for name in names))
            with tarfile.open(first["path"], "r:gz") as archive:
                body = archive.extractfile(
                    "document-desk-46/services/flag-rotator/rotate.sh").read()
            self.assertNotIn(b"\r\n", body)

    def test_slug_validation_matches_server_label_rules(self):
        self.assertEqual(validate_slug("Document--Desk-46"), "document-desk-46")
        for bad in ("../evil", "a/b", "", "under_score", "a b"):
            with self.assertRaises(BlockedError):
                validate_slug(bad)


# ---------------------------------------------------------------------------
# Authoring controller tests
# ---------------------------------------------------------------------------


class AuthoringDryRunTests(unittest.TestCase):
    def test_dry_run_makes_zero_requests_and_reports_unsubmitted(self):
        spy = OpenerSpy()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            report = run_authoring_flow(
                seed=46, output_root=root / "generated",
                archive_path=root / "pkg.tar.gz",
                report_path=root / "report.json",
                competition_id="competition-fixture",
                authorized=False, tooling=Tooling(), opener=spy,
                environ={"CTFY_TOKEN": TOKEN},
            )
            self.assertEqual(spy.calls, 0)
            self.assertEqual(report["mode"], "dry_run")
            self.assertEqual(report["status"], "dry_run")
            self.assertEqual(report["exit_code"], 0)
            self.assertEqual(report["evidence_level"], "local_packaged_unsubmitted")
            self.assertFalse(report["network_sent"])
            self.assertFalse(report["upload"]["uploaded"])
            self.assertFalse(report["upload"]["platform_reviewed"])
            self.assertIsNone(report["upload"]["review_status"])
            self.assertEqual(report["local_checks"]["evidence"],
                             "local_checks_unavailable")
            self.assertTrue(Path(report["archive"]["path"]).is_file())
            self.assertTrue(Path(report["report_path"]).is_file())
            serialised = _report_json(report)
            self.assertNotIn(TOKEN, serialised)
            self.assertIsNone(FLAG_PATTERN.search(serialised))
            self.assertEqual(report["upload"]["request"]["multipart_fields"],
                             ["slug", "file"])

    def test_authorized_without_token_or_competition_is_blocked_before_network(self):
        spy = OpenerSpy()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            missing_token = run_authoring_flow(
                seed=46, output_root=root / "generated",
                archive_path=root / "a.tar.gz", report_path=root / "a.json",
                competition_id="competition-fixture", authorized=True,
                platform_url="http://127.0.0.1:9", token="",
                tooling=Tooling(), opener=spy, environ={})
            self.assertEqual(missing_token["exit_code"], 2)
            self.assertEqual(missing_token["status"], "blocked")
            self.assertEqual(missing_token["blocked"]["reason"], "missing_token")
            missing_competition = run_authoring_flow(
                seed=46, output_root=root / "generated",
                archive_path=root / "b.tar.gz", report_path=root / "b.json",
                competition_id="", authorized=True,
                platform_url="http://127.0.0.1:9", token=TOKEN,
                tooling=Tooling(), opener=spy, environ={})
            self.assertEqual(missing_competition["blocked"]["reason"],
                             "missing_competition_id")
            self.assertEqual(spy.calls, 0)


class AuthoringUploadTests(unittest.TestCase):
    def test_upload_multipart_shape_and_token_redaction(self):
        def responder(method, path, headers, body):
            if method == "POST":
                return 201, {
                    "id": "AUTHORED-ABC123",
                    "slug": "document-desk-46",
                    "review_status": "pending",
                    "file_count": 8,
                    "total_bytes": 2048,
                    "auto_smoke": {"outcome": "queued", "budget": 3, "remaining": 2},
                    # Deliberately echo the credential to prove redaction.
                    "review_note": "debug echo " + TOKEN,
                }, None
            return 404, {"code": "not_found"}, None

        with tempfile.TemporaryDirectory() as temp, MockPlatform(responder) as mock:
            root = Path(temp)
            report = run_authoring_flow(
                seed=46, output_root=root / "generated",
                archive_path=root / "pkg.tar.gz", report_path=root / "report.json",
                competition_id="competition-fixture", authorized=True,
                tooling=Tooling(), opener=None,
                environ={"CTFY_TOKEN": TOKEN, "CTFY_PLATFORM_URL": mock.url},
            )
            posts = mock.of("POST")
            self.assertEqual(len(posts), 1)
            request = posts[0]
            self.assertEqual(request["path"],
                             "/api/v1/competitions/competition-fixture/authored-challenges")
            self.assertEqual(request["headers"]["authorization"], "Bearer " + TOKEN)
            content_type = request["headers"]["content-type"]
            self.assertTrue(content_type.startswith("multipart/form-data; boundary="))
            boundary = content_type.split("boundary=", 1)[1].encode()
            raw = request["body"]
            self.assertIn(b'name="slug"', raw)
            self.assertIn(b"\r\ndocument-desk-46\r\n", raw)
            self.assertIn(b'name="file"; filename="document-desk-46.tar.gz"', raw)
            self.assertIn(b"Content-Type: application/gzip", raw)
            self.assertIn(b"--" + boundary, raw)
            archive_bytes = Path(report["archive"]["path"]).read_bytes()
            self.assertIn(archive_bytes, raw)
            self.assertEqual(report["status"], "uploaded_pending_review")
            self.assertTrue(report["upload"]["uploaded"])
            self.assertTrue(report["network_sent"])
            self.assertEqual(report["upload"]["review_status"], "pending")
            self.assertFalse(report["upload"]["platform_reviewed"])
            self.assertEqual(report["evidence_level"],
                             "uploaded_pending_operator_review")
            serialised = _report_json(report)
            self.assertNotIn(TOKEN, serialised)
            self.assertIn("[REDACTED]", serialised)
            self.assertIsNone(FLAG_PATTERN.search(serialised))

    def test_refusal_code_is_recorded_without_raising(self):
        def responder(method, path, headers, body):
            return 403, {"code": "authoring_not_open_yet",
                         "detail": "Authoring has not opened for this competition yet."}, None

        with tempfile.TemporaryDirectory() as temp, MockPlatform(responder) as mock:
            root = Path(temp)
            report = run_authoring_flow(
                seed=46, output_root=root / "generated",
                archive_path=root / "pkg.tar.gz", report_path=root / "report.json",
                competition_id="competition-fixture", authorized=True,
                tooling=Tooling(), environ={"CTFY_TOKEN": TOKEN,
                                             "CTFY_PLATFORM_URL": mock.url},
            )
            self.assertEqual(report["status"], "refused")
            self.assertEqual(report["exit_code"], 3)
            self.assertEqual(report["evidence_level"], "upload_refused")
            refusal = report["upload"]["refusal"]
            self.assertEqual(refusal["status"], 403)
            self.assertEqual(refusal["code"], "authoring_not_open_yet")
            self.assertFalse(report["upload"]["uploaded"])
            self.assertEqual(len(mock.of("POST")), 1)
            self.assertNotIn(TOKEN, _report_json(report))

    def test_poll_is_get_only_and_reads_review_status(self):
        state = {"posted": False, "gets": 0}

        def responder(method, path, headers, body):
            if method == "POST":
                state["posted"] = True
                return 201, {"id": "AUTHORED-ABC123", "slug": "document-desk-46",
                             "review_status": "pending"}, None
            state["gets"] += 1
            if path.endswith("/audit"):
                return 200, {"outcome": "ok", "errors": 0, "warnings": 0,
                             "findings": []}, None
            review = "pending" if state["gets"] == 1 else "approved"
            return 200, [{"id": "AUTHORED-ABC123", "slug": "document-desk-46",
                          "review_status": review, "smoke_verdict": "solved"}], None

        with tempfile.TemporaryDirectory() as temp, MockPlatform(responder) as mock:
            root = Path(temp)
            report = run_authoring_flow(
                seed=46, output_root=root / "generated",
                archive_path=root / "pkg.tar.gz", report_path=root / "report.json",
                competition_id="competition-fixture", authorized=True,
                poll=True, wait_seconds=2.0, interval=0.01,
                sleep=lambda _: None, tooling=Tooling(),
                environ={"CTFY_TOKEN": TOKEN, "CTFY_PLATFORM_URL": mock.url},
            )
            self.assertEqual(len(mock.of("POST")), 1)
            self.assertGreaterEqual(len(mock.of("GET")), 2)
            self.assertTrue(report["poll"]["read_only"])
            self.assertFalse(report["poll"]["uploaded_again"])
            self.assertEqual(report["poll"]["final"]["review_status"], "approved")
            self.assertEqual(report["upload"]["review_status"], "approved")
            self.assertTrue(report["upload"]["platform_reviewed"])
            self.assertEqual(report["evidence_level"], "uploaded_operator_reviewed")


class AuthoringLocalCheckTests(unittest.TestCase):
    def test_preferred_ctfy_authoring_commands_are_used_when_available(self):
        tooling = Tooling(ctfy="C:/tools/ctfy", ctfy_admin="C:/tools/ctfy-admin",
                          ctfy_version="ctfy 0.8.0",
                          authoring_check=True, authoring_smoke_local=False)
        package = Path("generated") / "document-desk-46"
        specs = plan_checks(tooling, package, Path("generated"), smoke_runs=2)
        self.assertEqual(len(specs), 1)
        self.assertEqual(specs[0]["command"][:3], ["C:/tools/ctfy", "authoring", "check"])
        self.assertIn("preferred", specs[0]["source"])

    def test_fallback_admin_audit_and_smoke_commands(self):
        tooling = Tooling(ctfy_admin="C:/tools/ctfy-admin",
                          ctfy_admin_version="ctfy-admin 0.7.0")
        specs = plan_checks(tooling, Path("generated") / "document-desk-46",
                            Path("generated"), smoke_runs=2)
        self.assertEqual([spec["kind"] for spec in specs],
                         ["admin_audit", "admin_smoke", "admin_smoke"])
        self.assertEqual(specs[0]["command"][:3],
                         ["C:/tools/ctfy-admin", "challenge", "audit"])

    def test_local_check_failure_blocks_upload_but_keeps_archive(self):
        runner = _fake_run([(1, "AUDIT: one error")])
        spy = OpenerSpy()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            report = run_authoring_flow(
                seed=46, output_root=root / "generated",
                archive_path=root / "pkg.tar.gz", report_path=root / "report.json",
                competition_id="competition-fixture", authorized=False,
                tooling=Tooling(ctfy_admin="C:/tools/ctfy-admin"),
                run=runner, opener=spy,
            )
            self.assertEqual(report["exit_code"], 1)
            self.assertEqual(report["status"], "local_validation_failed")
            self.assertEqual(report["local_checks"]["evidence"],
                             "local_checks_failed")
            self.assertFalse(report["upload"]["attempted"])
            self.assertTrue(Path(report["archive"]["path"]).is_file())
            self.assertEqual(spy.calls, 0)
            self.assertEqual(runner.calls[0][:3],
                             ["C:/tools/ctfy-admin", "challenge", "audit"])

    def test_tooling_detection_reads_live_help_and_version(self):
        from subprocess import CompletedProcess

        def fake_which(name):
            return f"C:/tools/{name}"

        outputs = {
            ("--version",): CompletedProcess([], 0, "ctfy 0.7.0", ""),
            ("authoring", "--help"): CompletedProcess(
                [], 0, "commands:\n  check\n  smoke --local\n  list\n", ""),
        }

        def fake_run(command, **kwargs):  # noqa: ARG001
            return outputs[tuple(command[1:])]

        tooling = discover_tooling(run=fake_run, which=fake_which)
        self.assertEqual(tooling.ctfy, "C:/tools/ctfy")
        self.assertEqual(tooling.ctfy_version, "ctfy 0.7.0")
        self.assertTrue(tooling.authoring_check)
        self.assertTrue(tooling.authoring_smoke_local)
        self.assertIn("check", tooling.authoring_subcommands)


# ---------------------------------------------------------------------------
# Participation flow tests
# ---------------------------------------------------------------------------


class ParticipationDryRunTests(unittest.TestCase):
    def test_register_harness_dry_run_sends_nothing(self):
        spy = OpenerSpy()
        with tempfile.TemporaryDirectory() as temp:
            report = platform_flow.register_harness_flow(
                harness_id="qutagent", image="registry.example/qutagent:dev",
                display_name="QUTAgent", version="dev",
                report_dir=Path(temp), opener=spy,
                environ={"CTFY_TOKEN": TOKEN})
            self.assertEqual(spy.calls, 0)
            self.assertEqual(report["mode"], "dry_run")
            self.assertFalse(report["network_sent"])
            self.assertEqual(report["request"]["method"], "POST")
            self.assertEqual(report["request"]["path"], "/api/v1/eval/harnesses")
            self.assertEqual(report["request"]["json"],
                             {"id": "qutagent", "image": "registry.example/qutagent:dev",
                              "display_name": "QUTAgent", "version": "dev", "notes": ""})
            self.assertNotIn(TOKEN, _report_json(report))

    def test_enter_dry_run_payload_matches_server_body(self):
        with tempfile.TemporaryDirectory() as temp:
            default = platform_flow.enter_flow(
                harness_id="qutagent", model_id="model-1",
                competition_id="competition-fixture", report_dir=Path(temp),
                environ={"CTFY_TOKEN": TOKEN})
            self.assertEqual(default["request"]["json"],
                             {"harness_id": "qutagent", "model_id": "model-1",
                              "competition_id": "competition-fixture",
                              "num_samples": 1})
            clamped = platform_flow.enter_flow(
                harness_id="qutagent", model_id="model-1",
                competition_id="competition-fixture", num_samples=99,
                timeout_s=600, max_turns=32, report_dir=Path(temp))
            payload = clamped["request"]["json"]
            self.assertEqual(payload["num_samples"], 5)
            self.assertEqual(payload["timeout_s"], 600)
            self.assertEqual(payload["max_turns"], 32)
            self.assertIn("clamped", " ".join(clamped["notes"]))
            self.assertFalse(clamped["network_sent"])

    def test_status_dry_run_makes_zero_requests(self):
        spy = OpenerSpy()
        with tempfile.TemporaryDirectory() as temp:
            report = platform_flow.status_flow(
                competition_id="competition-fixture", report_dir=Path(temp),
                opener=spy)
            self.assertEqual(spy.calls, 0)
            self.assertEqual(report["status"], "dry_run")
            self.assertEqual([item["method"] for item in report["requests"]],
                             ["GET", "GET", "GET"])


class ParticipationAuthorizedTests(unittest.TestCase):
    def _harness(self, review_status="pending", digest=""):
        return {
            "id": "owner-user-id/qutagent",
            "display_name": "QUTAgent",
            "image": "registry.example/qutagent:dev",
            "version": "dev",
            "active": True,
            "review_status": review_status,
            "approved_digest": digest,
            "conformance_status": "",
            "conformance_checked_at_ts": 0,
        }

    def test_register_harness_authorized_request_shape(self):
        def responder(method, path, headers, body):
            payload = json.loads(body)
            return 200, {**self._harness("pending"), "notes": payload.get("notes", "")}, None

        with tempfile.TemporaryDirectory() as temp, MockPlatform(responder) as mock:
            report = platform_flow.register_harness_flow(
                harness_id="qutagent", image="registry.example/qutagent:dev",
                display_name="QUTAgent", version="dev", authorized=True,
                report_dir=Path(temp),
                environ={"CTFY_TOKEN": TOKEN, "CTFY_PLATFORM_URL": mock.url})
            post = mock.of("POST")[0]
            self.assertEqual(post["path"], "/api/v1/eval/harnesses")
            self.assertEqual(post["headers"]["authorization"], "Bearer " + TOKEN)
            self.assertEqual(sorted(json.loads(post["body"]).keys()),
                             ["display_name", "id", "image", "notes", "version"])
            self.assertEqual(report["status"], "registered_pending_review")
            self.assertEqual(report["evidence_level"], "registered_not_reviewed")
            self.assertFalse(report["response"]["digest_pinned"])
            self.assertNotIn(TOKEN, _report_json(report))

    def test_missing_token_blocks_authorized_flow_without_request(self):
        spy = OpenerSpy()
        with tempfile.TemporaryDirectory() as temp:
            report = platform_flow.register_harness_flow(
                harness_id="qutagent", image="registry.example/qutagent:dev",
                authorized=True, platform_url="http://127.0.0.1:9",
                report_dir=Path(temp), opener=spy, environ={})
            self.assertEqual(report["exit_code"], 2)
            self.assertEqual(report["status"], "blocked")
            self.assertEqual(report["blocked"]["reason"], "missing_token")
            self.assertEqual(spy.calls, 0)
            self.assertTrue((Path(temp) / "qutagent.register-harness.json").is_file())

    def test_probe_resolves_bare_name_and_reads_conformance(self):
        state = {"posted": False}

        def responder(method, path, headers, body):
            if method == "GET":
                row = self._harness("approved", "sha256:abc")
                if state["posted"]:
                    row["conformance_status"] = "passed"
                    row["conformance_checked_at_ts"] = 123.0
                    row["conformance_findings"] = [
                        {"code": "HARNESS001", "severity": "info", "detail": "ok"}]
                return 200, [row], None
            state["posted"] = True
            return 200, {"id": "task-1", "kind": "harness_probe",
                         "status": "pending"}, None

        with tempfile.TemporaryDirectory() as temp, MockPlatform(responder) as mock:
            report = platform_flow.probe_flow(
                harness_id="qutagent", authorized=True, wait_seconds=2.0,
                interval=0.01, sleep=lambda _: None,
                report_dir=Path(temp),
                environ={"CTFY_TOKEN": TOKEN, "CTFY_PLATFORM_URL": mock.url})
            self.assertEqual(len(mock.of("POST")), 1)
            self.assertEqual(mock.of("POST")[0]["path"],
                             "/api/v1/eval/harnesses/owner-user-id/qutagent/probe")
            self.assertGreaterEqual(len(mock.of("GET")), 2)
            self.assertEqual(report["response"]["task_id"], "task-1")
            self.assertEqual(report["harness"]["conformance_status"], "passed")
            self.assertEqual(report["status"], "probe_submitted")
            self.assertNotIn(TOKEN, _report_json(report))

    def test_probe_unknown_harness_is_blocked_before_post(self):
        def responder(method, path, headers, body):
            return 200, [], None

        with tempfile.TemporaryDirectory() as temp, MockPlatform(responder) as mock:
            report = platform_flow.probe_flow(
                harness_id="qutagent", authorized=True, report_dir=Path(temp),
                environ={"CTFY_TOKEN": TOKEN, "CTFY_PLATFORM_URL": mock.url})
            self.assertEqual(report["status"], "blocked")
            self.assertEqual(report["blocked"]["reason"], "harness_not_found")
            self.assertEqual(mock.of("POST"), [])

    def test_status_reads_harnesses_entries_and_models(self):
        def responder(method, path, headers, body):
            parsed = urllib.parse.urlparse(path)
            if parsed.path == "/api/v1/eval/harnesses":
                return 200, [self._harness("approved", "sha256:abc")], None
            if parsed.path == "/api/v1/eval/entries":
                return 200, {"items": [{"id": "campaign-1",
                                        "model_id": "model-1",
                                        "harness_id": "owner-user-id/qutagent",
                                        "tier": "self_reported",
                                        "trigger": "user",
                                        "status": "pending"}], "total": 1}, None
            if parsed.path == "/api/v1/eval/models":
                return 200, [{"id": "model-1", "display_name": "Model",
                              "flavor": "openai", "vendor": "fixture"}], None
            return 404, {"code": "not_found"}, None

        with tempfile.TemporaryDirectory() as temp, MockPlatform(responder) as mock:
            report = platform_flow.status_flow(
                competition_id="competition-fixture", authorized=True,
                report_dir=Path(temp),
                environ={"CTFY_TOKEN": TOKEN, "CTFY_PLATFORM_URL": mock.url})
            self.assertEqual(report["status"], "ok")
            self.assertEqual(report["entries"]["total"], 1)
            self.assertEqual(report["entries"]["items"][0]["tier"], "self_reported")
            self.assertEqual(report["models"][0]["id"], "model-1")
            entry_request = mock.of("GET")[1]
            self.assertIn("competition_id=competition-fixture", entry_request["path"])
            self.assertNotIn(TOKEN, _report_json(report))

    def test_enter_blocks_pending_harness_before_post(self):
        def responder(method, path, headers, body):
            return 200, [self._harness("pending")], None

        with tempfile.TemporaryDirectory() as temp, MockPlatform(responder) as mock:
            report = platform_flow.enter_flow(
                harness_id="qutagent", model_id="model-1",
                competition_id="competition-fixture", authorized=True,
                report_dir=Path(temp),
                environ={"CTFY_TOKEN": TOKEN, "CTFY_PLATFORM_URL": mock.url})
            self.assertEqual(report["status"], "blocked")
            self.assertEqual(report["blocked"]["reason"], "agent_not_dispatchable")
            self.assertEqual(mock.of("POST"), [])

    def test_enter_blocks_unapproved_model_before_post(self):
        def responder(method, path, headers, body):
            if urllib.parse.urlparse(path).path == "/api/v1/eval/harnesses":
                return 200, [self._harness("approved", "sha256:abc")], None
            return 200, [{"id": "other-model", "display_name": "Other"}], None

        with tempfile.TemporaryDirectory() as temp, MockPlatform(responder) as mock:
            report = platform_flow.enter_flow(
                harness_id="qutagent", model_id="model-1",
                competition_id="competition-fixture", authorized=True,
                report_dir=Path(temp),
                environ={"CTFY_TOKEN": TOKEN, "CTFY_PLATFORM_URL": mock.url})
            self.assertEqual(report["blocked"]["reason"], "model_not_approved")
            self.assertEqual(mock.of("POST"), [])

    def test_enter_accepted_is_self_reported_and_not_official(self):
        def responder(method, path, headers, body):
            parsed = urllib.parse.urlparse(path)
            if method == "GET" and parsed.path == "/api/v1/eval/harnesses":
                return 200, [self._harness("approved", "sha256:abc")], None
            if method == "GET" and parsed.path == "/api/v1/eval/models":
                return 200, [{"id": "model-1", "display_name": "Model"}], None
            return 200, {"id": "campaign-1", "status": "pending",
                         "tier": "self_reported", "trigger": "user",
                         "model_id": "model-1",
                         "harness_id": "owner-user-id/qutagent",
                         "standard_set_id": "competition-fixture"}, None

        with tempfile.TemporaryDirectory() as temp, MockPlatform(responder) as mock:
            report = platform_flow.enter_flow(
                harness_id="qutagent", model_id="model-1",
                competition_id="competition-fixture", authorized=True,
                report_dir=Path(temp),
                environ={"CTFY_TOKEN": TOKEN, "CTFY_PLATFORM_URL": mock.url})
            post = mock.of("POST")[0]
            self.assertEqual(post["path"], "/api/v1/eval/entries")
            sent = json.loads(post["body"])
            self.assertEqual(sent["harness_id"], "owner-user-id/qutagent")
            self.assertEqual(sent["num_samples"], 1)
            self.assertNotIn("tier", sent)  # server stamps self_reported
            self.assertEqual(report["status"], "entered")
            self.assertEqual(report["evidence_level"],
                             "entry_accepted_self_reported")
            self.assertEqual(report["response"]["tier"], "self_reported")
            self.assertNotIn(TOKEN, _report_json(report))

    def test_enter_refusal_code_is_preserved_and_redacted(self):
        def responder(method, path, headers, body):
            parsed = urllib.parse.urlparse(path)
            if method == "GET" and parsed.path == "/api/v1/eval/harnesses":
                return 200, [self._harness("approved", "sha256:abc")], None
            if method == "GET" and parsed.path == "/api/v1/eval/models":
                return 200, [{"id": "model-1", "display_name": "Model"}], None
            return 409, {"code": "unfunded",
                         "detail": "this agent cannot enter: unfunded; echo " + TOKEN}, None

        with tempfile.TemporaryDirectory() as temp, MockPlatform(responder) as mock:
            report = platform_flow.enter_flow(
                harness_id="qutagent", model_id="model-1",
                competition_id="competition-fixture", authorized=True,
                report_dir=Path(temp),
                environ={"CTFY_TOKEN": TOKEN, "CTFY_PLATFORM_URL": mock.url})
            self.assertEqual(report["status"], "refused")
            self.assertEqual(report["exit_code"], 3)
            self.assertEqual(report["refusal"]["code"], "unfunded")
            serialised = _report_json(report)
            self.assertNotIn(TOKEN, serialised)
            self.assertIn("[REDACTED]", serialised)


# ---------------------------------------------------------------------------
# Low-level transport tests
# ---------------------------------------------------------------------------


class TransportTests(unittest.TestCase):
    def test_multipart_encoder_shape(self):
        body, content_type = encode_multipart(
            {"slug": "document-desk-46"},
            MultipartFile("file", "document-desk-46.tar.gz", b"\x1f\x8bgzip"),
            boundary="BOUNDARY")
        self.assertEqual(content_type, "multipart/form-data; boundary=BOUNDARY")
        self.assertIn(b'Content-Disposition: form-data; name="slug"\r\n\r\n'
                      b'document-desk-46', body)
        self.assertIn(b'name="file"; filename="document-desk-46.tar.gz"', body)
        self.assertIn(b"Content-Type: application/gzip\r\n\r\n\x1f\x8bgzip", body)
        self.assertTrue(body.endswith(b"--BOUNDARY--\r\n"))

    def test_redirect_is_not_followed(self):
        def responder(method, path, headers, body):
            return 302, {}, "text/plain"

        with MockPlatform(responder) as mock:
            client = PlatformHttp(mock.url, TOKEN, secrets=[TOKEN])
            with self.assertRaises(RefusedError) as raised:
                client.request("GET", "/eval/harnesses")
            self.assertEqual(raised.exception.status, 302)
            # One request only: the redirect target was never contacted.
            self.assertEqual(len(mock.requests), 1)
            self.assertNotIn(TOKEN, str(raised.exception))

    def test_poll_helper_never_posts(self):
        def responder(method, path, headers, body):
            if path.endswith("/audit"):
                return 200, {"outcome": "ok", "errors": 0, "warnings": 0}, None
            return 200, [{"id": "AUTHORED-1", "slug": "document-desk-46",
                          "review_status": "pending"}], None

        with MockPlatform(responder) as mock:
            client = PlatformHttp(mock.url, TOKEN, secrets=[TOKEN])
            result = poll_authored_status(
                client, "competition-fixture", slug="document-desk-46",
                wait_seconds=0, sleep=lambda _: None)
            self.assertTrue(result["read_only"])
            self.assertFalse(result["uploaded_again"])
            self.assertEqual(mock.of("POST"), [])
            self.assertGreaterEqual(len(mock.of("GET")), 2)
            self.assertEqual(result["final"]["review_status"], "pending")


if __name__ == "__main__":
    unittest.main()
