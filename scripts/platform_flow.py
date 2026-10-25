"""Platform participation flow for the CTFY model-evaluation track.

Subcommands, all based on the CTFy 0.7.0 source snapshot in
``_research/ctfy/pypi/extracted``:

``register-harness``
    ``POST /api/v1/eval/harnesses`` with
    ``{id, image, display_name, version, notes}``. ``id`` is the bare name the
    caller chooses; the server stores ``<owner_user_id>/<name>`` and stamps
    ``review_status="pending"``. Registration is not approval: it is not
    dispatchable until an operator approves it and pins a digest.

``probe``
    ``POST /api/v1/eval/harnesses/{harness_id}/probe`` (a background task that
    runs the image once), then read-only ``GET /api/v1/eval/harnesses`` until
    the row's ``conformance_*`` fields move. Probe output is evidence, never a
    review gate and never a credential-carrying run.

``status``
    Read-only: ``GET /api/v1/eval/harnesses``,
    ``GET /api/v1/eval/entries?competition_id=...`` and
    ``GET /api/v1/eval/models``.

``enter``
    ``POST /api/v1/eval/entries`` with
    ``{harness_id, model_id, competition_id, num_samples}`` (plus
    ``timeout_s`` / ``max_turns`` only when the caller sets them; both can only
    shorten a run). The entry is stamped ``tier="self_reported"`` and
    ``trigger="user"`` server-side and runs the agent as an independent
    entrant. Server refusals arrive as 409 codes: ``not_your_agent``,
    ``agent_not_dispatchable``, ``model_not_approved``, ``agents_not_allowed``,
    ``no_challenges``, ``already_running``, ``unfunded``.

Safety defaults: every subcommand is dry-run (zero HTTP requests) unless
``--authorized`` is given. The platform URL and token come from the environment
(``CTFY_PLATFORM_URL`` / ``CTFY_TOKEN``); a token is never accepted on the
command line and never written to a report. Mutations are not retried after a
transport failure because their outcome is unknown.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Iterable, Mapping

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from author.controller import (  # noqa: E402
    API_PREFIX,
    SCHEMA_VERSION,
    BlockedError,
    PlatformHttp,
    RefusedError,
    TransportError,
    environment_secrets,
    redact,
    write_json_report,
)
from author.controller import _iso_now  # noqa: E402  (shared timestamp helper)

PLATFORM_URL_ENV = "CTFY_PLATFORM_URL"
TOKEN_ENV = "CTFY_TOKEN"
PLATFORM_ENV_KEYS = frozenset({PLATFORM_URL_ENV, TOKEN_ENV})
HARNESS_PATH = "/eval/harnesses"
ENTRY_PATH = "/eval/entries"
MODELS_PATH = "/eval/models"
DEFAULT_REPORT_DIR = Path("artifacts") / "participation"
#: Source: ``ctfy.server.routes.eval_public._HARNESS_ID_RE``.
HARNESS_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
#: Source: ``ctfy.server.routes.eval_public._MAX_USER_SAMPLES``.
MAX_USER_SAMPLES = 5


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _safe_stem(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "__", value).strip("._") or "platform-flow"


def _write(path: Path, report: dict[str, Any], secrets: Iterable[str]) -> Path:
    """Write the report, refusing to persist any known credential value."""
    serialised = json.dumps(report, ensure_ascii=False)
    leaked = [value for value in secrets if value and value in serialised]
    if leaked:
        report["notes"] = list(report.get("notes") or []) + [
            "redaction guard tripped; response fields were replaced"]
        for key in ("response", "harnesses", "entries", "models", "result"):
            report[key] = None
        report["secrets_in_report"] = True
    report["report_path"] = str(path)
    report.setdefault("secrets_in_report", False)
    write_json_report(report, path)
    return path


def _resolve_credentials(authorized: bool, token: str | None, platform_url: str | None,
                         environ: Mapping[str, str] | None) -> tuple[str, str, list[str]]:
    env = os.environ if environ is None else environ
    secrets_found = environment_secrets(env)
    chosen_token = token if token is not None else env.get(TOKEN_ENV, "")
    if chosen_token and chosen_token not in secrets_found and len(chosen_token) >= 4:
        secrets_found.append(chosen_token)
    chosen_url = platform_url if platform_url is not None else env.get(PLATFORM_URL_ENV, "")
    return chosen_url, chosen_token, secrets_found


def _base(command: str, *, authorized: bool) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "command": command,
        "generated_at": _iso_now(),
        "mode": "authorized" if authorized else "dry_run",
        "network_sent": False,
        "status": "unknown",
        "exit_code": 0,
        "request": None,
        "response": None,
        "refusal": None,
        "blocked": None,
        "notes": [],
        "evidence_level": "",
    }


def _blocked(report: dict[str, Any], reason: str, message: str,
             path: Path, secrets: Iterable[str]) -> dict[str, Any]:
    report["status"] = "blocked"
    report["exit_code"] = 2
    report["blocked"] = {"reason": reason, "message": message}
    report["notes"].append(message)
    report["evidence_level"] = "blocked_" + reason
    _write(path, report, secrets)
    return report


def _refusal(report: dict[str, Any], exc: RefusedError, path: Path,
             secrets: Iterable[str]) -> dict[str, Any]:
    report["status"] = "refused"
    report["exit_code"] = 3
    report["network_sent"] = True
    report["refusal"] = {
        "status": exc.status,
        "code": exc.code,
        "detail": exc.detail,
        "reasons": exc.reasons,
    }
    report["evidence_level"] = "platform_refused"
    _write(path, report, secrets)
    return report


def _transport(report: dict[str, Any], exc: TransportError, path: Path,
               secrets: Iterable[str], *, mutation: bool) -> dict[str, Any]:
    report["status"] = "transport_unknown" if mutation else "transport_failed"
    report["exit_code"] = 3
    report["network_sent"] = True
    report["transport"] = {
        "message": redact(str(exc), secrets),
        "mutation_outcome_unknown": exc.mutation_outcome_unknown and mutation,
    }
    if mutation:
        report["notes"].append(
            "mutation outcome is unknown; not retried automatically")
    report["evidence_level"] = "transport_failure"
    _write(path, report, secrets)
    return report


def _client(platform_url: str, token: str, *, opener: Any,
            secrets: Iterable[str]) -> PlatformHttp:
    return PlatformHttp(platform_url, token, opener=opener, secrets=secrets)


def _find_harness(rows: Any, wanted: str) -> dict[str, Any] | None:
    """Resolve a bare name or a full stored id against the caller's shelf."""
    if not isinstance(rows, list):
        return None
    for row in rows:
        if isinstance(row, dict) and str(row.get("id") or "") == wanted:
            return row
    for row in rows:
        if isinstance(row, dict) and str(row.get("id") or "").endswith("/" + wanted):
            return row
    return None


def _select(value: Mapping[str, Any], keys: Iterable[str]) -> dict[str, Any]:
    return {key: value.get(key) for key in keys if key in value}


_HARNESS_FIELDS = ("id", "display_name", "image", "version", "active",
                   "review_status", "conformance_status", "conformance_checked_at_ts",
                   "conformance_error", "source_url", "notes", "created_at")
_ENTRY_FIELDS = ("id", "name", "model_id", "harness_id", "standard_set_id",
                 "tier", "trigger", "status", "num_samples", "timeout_s",
                 "max_turns", "task_id", "created_at", "total_runs",
                 "finished_runs", "fully_solved_runs", "cost_usd", "error")
_MODEL_FIELDS = ("id", "display_name", "flavor", "vendor",
                 "input_price_per_mtok", "output_price_per_mtok")


def _harness_view(row: Mapping[str, Any]) -> dict[str, Any]:
    view = _select(row, _HARNESS_FIELDS)
    # Concise evidence: does the row carry the digest an approval pins?
    view["digest_pinned"] = bool(row.get("approved_digest"))
    findings = row.get("conformance_findings")
    if isinstance(findings, list):
        view["conformance_findings"] = [
            _select(item, ("code", "severity", "detail"))
            for item in findings[:20] if isinstance(item, dict)
        ]
    else:
        view["conformance_findings"] = []
    return view


# ---------------------------------------------------------------------------
# register-harness
# ---------------------------------------------------------------------------


def register_harness_flow(*, harness_id: str, image: str,
                          display_name: str = "", version: str = "",
                          notes: str = "", authorized: bool = False,
                          token: str | None = None,
                          platform_url: str | None = None,
                          opener: Any = None,
                          report_dir: Path = DEFAULT_REPORT_DIR,
                          report_path: Path | None = None,
                          environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Plan or send one harness registration."""
    platform_url, chosen_token, secrets_found = _resolve_credentials(
        authorized, token, platform_url, environ)
    report = _base("register-harness", authorized=authorized)
    path = Path(report_path) if report_path else (
        Path(report_dir) / f"{_safe_stem(harness_id)}.register-harness.json")
    body = {"id": harness_id, "image": image,
            "display_name": display_name, "version": version, "notes": notes}
    report["request"] = {"method": "POST", "path": API_PREFIX + HARNESS_PATH,
                         "json": body}
    report["platform_url_configured"] = bool(platform_url)
    report["token_configured"] = bool(chosen_token)

    if not harness_id or not image:
        return _blocked(report, "missing_fields",
                        "register-harness needs --id and --image",
                        path, secrets_found)
    if not HARNESS_NAME_RE.match(harness_id):
        return _blocked(
            report, "invalid_harness_name",
            "the server takes a bare name: lowercase letters, digits and "
            "'.', '_' or '-', at most 64 characters; the owner namespace is "
            "implied",
            path, secrets_found)

    report["notes"].append(
        "id is a bare name; the server stores <owner_user_id>/<name> and stamps "
        "review_status=pending")
    if not authorized:
        report["status"] = "dry_run"
        report["evidence_level"] = "planned_only"
        report["notes"].append("dry run: no HTTP request sent")
        _write(path, report, secrets_found)
        return report
    if not platform_url:
        return _blocked(report, "missing_platform_url",
                        f"authorized call needs {PLATFORM_URL_ENV} in the environment",
                        path, secrets_found)
    if not chosen_token:
        return _blocked(report, "missing_token",
                        f"authorized call needs {TOKEN_ENV} in the environment "
                        "(never pass a token on the command line)",
                        path, secrets_found)

    client = _client(platform_url, chosen_token, opener=opener, secrets=secrets_found)
    try:
        payload = client.request_json("POST", HARNESS_PATH, json_body=body)
    except RefusedError as exc:
        return _refusal(report, exc, path, secrets_found)
    except TransportError as exc:
        return _transport(report, exc, path, secrets_found, mutation=True)
    report["network_sent"] = True
    report["status"] = "registered_pending_review"
    report["exit_code"] = 0
    report["evidence_level"] = "registered_not_reviewed"
    report["response"] = _harness_view(payload) if isinstance(payload, dict) else None
    report["notes"].append(
        "registration is not approval: the row stays pending until an operator "
        "reviews it, and only an approved+pinned digest is dispatchable")
    _write(path, report, secrets_found)
    return report


# ---------------------------------------------------------------------------
# probe
# ---------------------------------------------------------------------------


def probe_flow(*, harness_id: str, authorized: bool = False,
               token: str | None = None, platform_url: str | None = None,
               wait_seconds: float = 0.0, interval: float = 5.0,
               opener: Any = None,
               report_dir: Path = DEFAULT_REPORT_DIR,
               report_path: Path | None = None,
               environ: Mapping[str, str] | None = None,
               sleep: Any = time.sleep, clock: Any = time.monotonic) -> dict[str, Any]:
    """Plan or submit one probe; read the outcome back with GET only."""
    platform_url, chosen_token, secrets_found = _resolve_credentials(
        authorized, token, platform_url, environ)
    report = _base("probe", authorized=authorized)
    path = Path(report_path) if report_path else (
        Path(report_dir) / f"{_safe_stem(harness_id)}.probe.json")
    report["request"] = {
        "preflight": {"method": "GET", "path": API_PREFIX + HARNESS_PATH,
                      "note": "resolve the bare name to the stored id"},
        "method": "POST",
        "path": API_PREFIX + HARNESS_PATH + "/" + (
            harness_id if "/" in harness_id else "<resolved-owner>/" + harness_id)
        + "/probe",
    }
    report["platform_url_configured"] = bool(platform_url)
    report["token_configured"] = bool(chosen_token)
    if not harness_id:
        return _blocked(report, "missing_fields", "probe needs --harness-id",
                        path, secrets_found)
    report["notes"].append(
        "probe runs the image once under the dry-run briefing with no platform "
        "credential and no model key; its verdict is evidence, not review")
    if not authorized:
        report["status"] = "dry_run"
        report["evidence_level"] = "planned_only"
        report["notes"].append("dry run: no HTTP request sent")
        _write(path, report, secrets_found)
        return report
    if not platform_url:
        return _blocked(report, "missing_platform_url",
                        f"authorized call needs {PLATFORM_URL_ENV} in the environment",
                        path, secrets_found)
    if not chosen_token:
        return _blocked(report, "missing_token",
                        f"authorized call needs {TOKEN_ENV} in the environment "
                        "(never pass a token on the command line)",
                        path, secrets_found)

    client = _client(platform_url, chosen_token, opener=opener, secrets=secrets_found)
    try:
        rows = client.request_json("GET", HARNESS_PATH)
    except RefusedError as exc:
        return _refusal(report, exc, path, secrets_found)
    except TransportError as exc:
        return _transport(report, exc, path, secrets_found, mutation=False)
    row = _find_harness(rows, harness_id)
    if row is None:
        report["network_sent"] = True
        return _blocked(report, "harness_not_found",
                        f"no harness named {harness_id!r} on this account",
                        path, secrets_found)
    stored_id = str(row.get("id") or harness_id)
    report["harness"] = _harness_view(row)
    prior_checked = row.get("conformance_checked_at_ts") or 0
    prior_status = row.get("conformance_status") or ""
    try:
        task = client.request_json("POST", HARNESS_PATH + "/" + stored_id + "/probe")
    except RefusedError as exc:
        return _refusal(report, exc, path, secrets_found)
    except TransportError as exc:
        return _transport(report, exc, path, secrets_found, mutation=True)
    report["network_sent"] = True
    report["status"] = "probe_submitted"
    report["exit_code"] = 0
    report["evidence_level"] = "probe_task_submitted"
    report["response"] = {
        "task_id": task.get("id") if isinstance(task, dict) else None,
        "task_status": task.get("status") if isinstance(task, dict) else None,
    }
    if wait_seconds <= 0:
        report["notes"].append(
            "task submitted; re-run `status` later for the conformance verdict")
        _write(path, report, secrets_found)
        return report
    deadline = clock() + wait_seconds
    rounds: list[dict[str, Any]] = []
    final_row = row
    while True:
        if clock() >= deadline:
            break
        sleep(interval)
        try:
            rows = client.request_json("GET", HARNESS_PATH)
        except (RefusedError, TransportError):
            break
        found = _find_harness(rows, stored_id)
        if found is not None:
            final_row = found
            rounds.append({
                "checked_at": _iso_now(),
                "conformance_status": found.get("conformance_status"),
                "conformance_checked_at_ts": found.get("conformance_checked_at_ts"),
            })
            checked = found.get("conformance_checked_at_ts") or 0
            if checked > (prior_checked or 0) or (
                    found.get("conformance_status") or "") != prior_status:
                break
    report["poll"] = {"request": {"method": "GET",
                                  "path": API_PREFIX + HARNESS_PATH},
                      "rounds": rounds, "read_only": True}
    report["harness"] = _harness_view(final_row)
    report["notes"].append(
        "conformance status is evidence; approving the harness remains an "
        "operator action and never happens in this flow")
    _write(path, report, secrets_found)
    return report


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


def status_flow(*, competition_id: str = "", authorized: bool = False,
                token: str | None = None, platform_url: str | None = None,
                opener: Any = None,
                report_dir: Path = DEFAULT_REPORT_DIR,
                report_path: Path | None = None,
                environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Plan or execute the read-only harness/entry/model status reads."""
    platform_url, chosen_token, secrets_found = _resolve_credentials(
        authorized, token, platform_url, environ)
    report = _base("status", authorized=authorized)
    path = Path(report_path) if report_path else Path(report_dir) / "status.json"
    entry_request_path = ENTRY_PATH + (
        "?competition_id=" + competition_id if competition_id else "")
    report["requests"] = [
        {"method": "GET", "path": API_PREFIX + HARNESS_PATH},
        {"method": "GET", "path": API_PREFIX + entry_request_path},
        {"method": "GET", "path": API_PREFIX + MODELS_PATH},
    ]
    report["platform_url_configured"] = bool(platform_url)
    report["token_configured"] = bool(chosen_token)
    if not authorized:
        report["status"] = "dry_run"
        report["evidence_level"] = "planned_only"
        report["notes"].append("dry run: no HTTP request sent")
        _write(path, report, secrets_found)
        return report
    if not platform_url:
        return _blocked(report, "missing_platform_url",
                        f"authorized call needs {PLATFORM_URL_ENV} in the environment",
                        path, secrets_found)
    if not chosen_token:
        return _blocked(report, "missing_token",
                        f"authorized call needs {TOKEN_ENV} in the environment "
                        "(never pass a token on the command line)",
                        path, secrets_found)

    client = _client(platform_url, chosen_token, opener=opener, secrets=secrets_found)
    try:
        harnesses = client.request_json("GET", HARNESS_PATH)
        entries = client.request_json("GET", entry_request_path)
        models = client.request_json("GET", MODELS_PATH)
    except RefusedError as exc:
        return _refusal(report, exc, path, secrets_found)
    except TransportError as exc:
        return _transport(report, exc, path, secrets_found, mutation=False)
    report["network_sent"] = True
    report["status"] = "ok"
    report["exit_code"] = 0
    report["evidence_level"] = "platform_read_only"
    report["harnesses"] = [
        _harness_view(row) for row in harnesses
        if isinstance(row, dict)] if isinstance(harnesses, list) else []
    if isinstance(entries, dict):
        items = entries.get("items")
        report["entries"] = {
            "total": entries.get("total"),
            "items": [_select(row, _ENTRY_FIELDS) for row in items
                      if isinstance(row, dict)] if isinstance(items, list) else [],
        }
    else:
        report["entries"] = {"total": None, "items": []}
    report["models"] = [
        _select(row, _MODEL_FIELDS) for row in models
        if isinstance(row, dict)] if isinstance(models, list) else []
    report["notes"].append(
        "read-only snapshot; it cannot create an entry, approve a harness or "
        "confirm competition results")
    _write(path, report, secrets_found)
    return report


# ---------------------------------------------------------------------------
# enter
# ---------------------------------------------------------------------------


def enter_flow(*, harness_id: str, model_id: str, competition_id: str,
               num_samples: int = 1, timeout_s: int = 0, max_turns: int = 0,
               authorized: bool = False, token: str | None = None,
               platform_url: str | None = None, opener: Any = None,
               report_dir: Path = DEFAULT_REPORT_DIR,
               report_path: Path | None = None,
               environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    """Plan or submit one independent-agent entry, after fail-closed preflight."""
    platform_url, chosen_token, secrets_found = _resolve_credentials(
        authorized, token, platform_url, environ)
    report = _base("enter", authorized=authorized)
    path = Path(report_path) if report_path else (
        Path(report_dir) / f"{_safe_stem(competition_id or 'entry')}.enter.json")
    clamped = max(1, min(num_samples, MAX_USER_SAMPLES))
    body: dict[str, Any] = {
        "harness_id": harness_id,
        "model_id": model_id,
        "competition_id": competition_id,
        "num_samples": clamped,
    }
    # The server body model also accepts these two; they can only shorten a run
    # (``0`` inherits the deployment setting), so they are sent only when set.
    if timeout_s > 0:
        body["timeout_s"] = timeout_s
    if max_turns > 0:
        body["max_turns"] = max_turns
    report["request"] = {
        "preflight": [
            {"method": "GET", "path": API_PREFIX + HARNESS_PATH,
             "note": "resolve id; require review_status=approved and a pinned digest"},
            {"method": "GET", "path": API_PREFIX + MODELS_PATH,
             "note": "require the model to be offerable (approved and active)"},
        ],
        "method": "POST",
        "path": API_PREFIX + ENTRY_PATH,
        "json": body,
    }
    report["platform_url_configured"] = bool(platform_url)
    report["token_configured"] = bool(chosen_token)
    if clamped != num_samples:
        report["notes"].append(
            f"num_samples clamped to {clamped}: the server caps an entry at "
            f"{MAX_USER_SAMPLES}")
    if not (harness_id and model_id and competition_id):
        return _blocked(report, "missing_fields",
                        "enter needs --harness-id, --model-id and --competition-id",
                        path, secrets_found)
    report["notes"].append(
        "an entry is a self-reported campaign (tier=self_reported, "
        "trigger=user) run as an independent entrant; it needs the entrant's own "
        "model key or an operator allowance, and only one entry per "
        "(harness, model, competition) may be in flight")
    if not authorized:
        report["status"] = "dry_run"
        report["evidence_level"] = "planned_only"
        report["notes"].append("dry run: no HTTP request sent")
        _write(path, report, secrets_found)
        return report
    if not platform_url:
        return _blocked(report, "missing_platform_url",
                        f"authorized call needs {PLATFORM_URL_ENV} in the environment",
                        path, secrets_found)
    if not chosen_token:
        return _blocked(report, "missing_token",
                        f"authorized call needs {TOKEN_ENV} in the environment "
                        "(never pass a token on the command line)",
                        path, secrets_found)

    client = _client(platform_url, chosen_token, opener=opener, secrets=secrets_found)
    try:
        harnesses = client.request_json("GET", HARNESS_PATH)
        models = client.request_json("GET", MODELS_PATH)
    except RefusedError as exc:
        return _refusal(report, exc, path, secrets_found)
    except TransportError as exc:
        return _transport(report, exc, path, secrets_found, mutation=False)
    row = _find_harness(harnesses, harness_id)
    if row is None:
        report["network_sent"] = True
        return _blocked(report, "harness_not_found",
                        f"no harness named {harness_id!r} on this account",
                        path, secrets_found)
    stored_id = str(row.get("id") or harness_id)
    body["harness_id"] = stored_id
    report["request"]["json"] = body
    report["harness"] = _harness_view(row)
    review_status = str(row.get("review_status") or "")
    digest_pinned = bool(row.get("approved_digest"))
    if review_status != "approved" or not digest_pinned:
        # Fail closed before the POST: an entry that fans out runs which all
        # fail at dispatch spends node time and reads as a broken agent.
        return _blocked(
            report, "agent_not_dispatchable",
            f"harness review_status={review_status or 'unknown'!r} with "
            f"pinned digest={digest_pinned}; an operator must approve the image "
            "first (this flow cannot approve it)",
            path, secrets_found)
    model_ids = {str(item.get("id")) for item in models
                 if isinstance(item, dict)} if isinstance(models, list) else set()
    if body["model_id"] not in model_ids:
        return _blocked(
            report, "model_not_approved",
            f"model {body['model_id']!r} is not in GET {API_PREFIX}{MODELS_PATH}; "
            "the entry gate refuses an unapproved or inactive model",
            path, secrets_found)
    try:
        payload = client.request_json("POST", ENTRY_PATH, json_body=body)
    except RefusedError as exc:
        # The 409 code is the actionable part (wait for review, add a key, ...).
        return _refusal(report, exc, path, secrets_found)
    except TransportError as exc:
        return _transport(report, exc, path, secrets_found, mutation=True)
    report["network_sent"] = True
    report["status"] = "entered"
    report["exit_code"] = 0
    report["evidence_level"] = "entry_accepted_self_reported"
    campaign = payload if isinstance(payload, dict) else {}
    report["response"] = _select(campaign, _ENTRY_FIELDS)
    if not report["response"].get("tier"):
        report["notes"].append(
            "entry response did not report a tier; the server stamps "
            "self_reported, so do not read this as an official board result")
    _write(path, report, secrets_found)
    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def load_platform_env_file(path: str | Path | None) -> int:
    """Load only CTFY_PLATFORM_URL/CTFY_TOKEN from a local KEY=VALUE file.

    The file is gitignored and never copied into a report. Values are not
    printed; returning the count is safe. Unknown keys are ignored.
    """
    if not path:
        return 0
    source = Path(path)
    text = source.read_text(encoding="utf-8")
    loaded = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        if key not in PLATFORM_ENV_KEYS:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if value:
            os.environ[key] = value
            loaded += 1
    return loaded


def _add_auth(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--authorized", action="store_true",
                        help="explicitly allow HTTP calls; requires CTFY_PLATFORM_URL "
                             "and CTFY_TOKEN in the environment")
    parser.add_argument("--env-file", default="",
                        help="optional local KEY=VALUE file with CTFY_PLATFORM_URL/CTFY_TOKEN; "
                             "values are not echoed")
    parser.add_argument("--json", action="store_true", help="print the full report JSON")
    parser.add_argument("--report-dir", type=Path, default=DEFAULT_REPORT_DIR)
    parser.add_argument("--report", type=Path, default=None,
                        help="exact report path (overrides --report-dir)")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="CTFY eval participation flow: register-harness, probe, "
                    "status, enter. Dry-run by default; no token on the CLI.")
    sub = parser.add_subparsers(dest="command", required=True)

    register = sub.add_parser("register-harness",
                              help="POST /api/v1/eval/harnesses")
    register.add_argument("--id", required=True,
                          help="bare harness name (owner namespace is implied)")
    register.add_argument("--image", required=True, help="platform-pullable image reference")
    register.add_argument("--display-name", default="")
    register.add_argument("--version", default="")
    register.add_argument("--notes", default="")
    _add_auth(register)

    probe = sub.add_parser("probe", help="POST /api/v1/eval/harnesses/{id}/probe")
    probe.add_argument("--harness-id", required=True)
    probe.add_argument("--wait-seconds", type=float, default=0.0,
                       help="read the conformance verdict back with GET for this long")
    probe.add_argument("--interval", type=float, default=5.0)
    _add_auth(probe)

    status = sub.add_parser("status", help="read harness/entry/model status (GET only)")
    status.add_argument("--competition-id", default="")
    _add_auth(status)

    enter = sub.add_parser("enter", help="POST /api/v1/eval/entries")
    enter.add_argument("--harness-id", required=True)
    enter.add_argument("--model-id", required=True)
    enter.add_argument("--competition-id", required=True)
    enter.add_argument("--num-samples", type=int, default=1)
    enter.add_argument("--timeout-s", type=int, default=0,
                       help="0 inherits the deployment setting; may only shorten")
    enter.add_argument("--max-turns", type=int, default=0,
                       help="0 inherits the deployment setting; may only shorten")
    _add_auth(enter)
    return parser


def _print_summary(report: Mapping[str, Any]) -> None:
    print(f"{report.get('command')} {report.get('mode')}: status={report.get('status')} "
          f"evidence={report.get('evidence_level')}")
    print(f"  network sent: {report.get('network_sent')}")
    if report.get("blocked"):
        print(f"  blocked: {report['blocked']['reason']} — {report['blocked']['message']}")
    if report.get("refusal"):
        refusal = report["refusal"]
        print(f"  refusal: HTTP {refusal.get('status')} {refusal.get('code')}")
    if report.get("response"):
        response = report["response"]
        if isinstance(response, dict):
            keys = ("id", "review_status", "tier", "status", "task_id")
            print("  response:", {key: response.get(key) for key in keys
                                  if key in response})
    print(f"  report: {report.get('report_path')}")
    if report.get("mode") == "dry_run":
        print("  dry run: nothing was sent to the platform and nothing was "
              "registered, probed or entered.")


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if getattr(args, "env_file", ""):
        try:
            count = load_platform_env_file(args.env_file)
        except OSError as exc:
            print(f"cannot read --env-file: {type(exc).__name__}", file=sys.stderr)
            return 2
        print(f"loaded {count} CTFY_* value(s) from --env-file (values not printed)",
              file=sys.stderr)
    kwargs = dict(authorized=args.authorized, report_dir=args.report_dir,
                  report_path=args.report)
    try:
        if args.command == "register-harness":
            report = register_harness_flow(
                harness_id=args.id, image=args.image,
                display_name=args.display_name, version=args.version,
                notes=args.notes, **kwargs)
        elif args.command == "probe":
            report = probe_flow(harness_id=args.harness_id,
                                wait_seconds=args.wait_seconds,
                                interval=args.interval, **kwargs)
        elif args.command == "status":
            report = status_flow(competition_id=args.competition_id, **kwargs)
        else:
            report = enter_flow(
                harness_id=args.harness_id, model_id=args.model_id,
                competition_id=args.competition_id,
                num_samples=args.num_samples, timeout_s=args.timeout_s,
                max_turns=args.max_turns, **kwargs)
    except BlockedError as exc:
        print(f"blocked: {redact(str(exc), environment_secrets())}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        _print_summary(report)
    return int(report.get("exit_code", 1))


if __name__ == "__main__":
    raise SystemExit(main())
