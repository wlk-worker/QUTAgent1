"""Deterministic gates in front of ``submit`` and ``finish``.

Three observed failure modes motivate this module:

* ``MMLU-CS-0011`` submitted an option *sentence* to a ``single_select``
  question whose ``choices`` are the letters ``A``-``D``.  The platform rejected
  it, and because the sentence was the same semantic option as an already
  rejected letter it spent an attempt on a duplicate instead of on a new
  hypothesis.
* ``SECQA-0132`` answered, got ``correct: false``, tried to look the answer up
  over the network (blocked for QA runs), then called ``finish`` while claiming
  "answer C was accepted with challenge_fully_solved=true".  The platform never
  saw that submission.
* ``SECQA-0148`` had a *confirmed* success relabelled ``internal_error`` by a
  later write failure (fixed in :mod:`agent.main`; the loop-side half of that
  fix is the sticky success state and the guarded post-submit refresh).

Everything here is pure: no I/O, no platform access, no clocks.  The loop calls
these functions, so every rule is unit-testable without a server.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

# Question modes that declare an enumerated answer set.  ``single_select`` is
# the shape used by the MMLU/SECQA/CTFy benchmark suites.
MULTI_MODES = frozenset({
    "multi_select", "multi", "multiple", "multiple_select", "checkbox",
    "multi_choice", "multiple_choice",
})

MAX_ANSWER_CHARS = 4_000
MAX_EVIDENCE_CHARS = 4_000

# Answers the flag discipline already forbids: submitting one wastes an attempt.
_PLACEHOLDER_ANSWERS = frozenset({
    "flag{...}", "flag{}", "flag{flag}", "flag", "ctf{...}", "ctf{flag}", "ctf",
    "<flag>", "<answer>", "todo", "tbd", "unknown", "n/a", "na", "none",
    "placeholder", "example", "your answer", "answer", "redacted",
})
# Evidence that carries no observation at all.
_GENERIC_EVIDENCE = frozenset({
    "", "-", "--", "?", ".", "n/a", "na", "none", "unknown", "tbd", "todo",
    "guess", "guessed", "example", "placeholder", "as above", "see above",
    "same", "see observation", "from reasoning",
})

_PREFIX = re.compile(r"^\s*(?:the\s+)?(?:final\s+)?(?:option|choice|answer)\s*(?:is)?\s*[:#=\-]?\s*", re.I)
_DECORATED = re.compile(r"^[\s(\[]*([A-Za-z0-9]{1,3})[\s)\].:\-]*$")
_OPTION_LINE = re.compile(r"(?m)^[ \t]*([A-Za-z])[\)\.\:][ \t]*(\S.*?)[ \t]*$")

# Verbs that turn a ``finish`` reason into a success claim.  Bare "solve" is
# excluded on purpose: "could not solve" is a failure report, not a claim.
_SUCCESS_CLAIM = re.compile(
    r"\b(?:solved|accepted|accept|correctly|correct|successful|success|"
    r"fully[_ -]?solved|completed|passed)\b",
    re.I,
)
# A clause containing one of these does not assert success.
_NEGATION = re.compile(
    r"\b(?:not|never|unable|unsuccessful|unsolved|cannot|can't|couldn't|didn't|"
    r"won't|isn't|wasn't|failed|rejected|incorrect)\b",
    re.I,
)
_CLAUSE_SPLIT = re.compile(r"[.;\n!?]+")


@dataclass(frozen=True)
class Decision:
    """Outcome of the submission gate.  ``ok`` means "safe to send"."""

    ok: bool
    value: Any = None
    evidence: str = ""
    code: str = ""
    detail: str = ""
    instruction: str = ""


@dataclass(frozen=True)
class Verdict:
    """Validated platform verdict; never a bare truthiness test."""

    correct: bool
    fully_solved: bool
    attempts_remaining: int | None
    basis: str
    problems: tuple[str, ...] = ()


def _key(text: Any) -> str:
    """Comparison key: case, whitespace and punctuation insensitive."""
    value = " ".join(str(text or "").split()).casefold()
    return value.strip(" .,:;!?()[]\"'")


def choice_pairs(question: Mapping[str, Any] | None) -> list[tuple[str, str]]:
    """``[(value, label), ...]`` from a platform question.

    ``choices`` is normally a list of strings (``["A", "B", ...]``); a mapping
    of value -> label is also accepted because the platform has used both.
    """
    if not isinstance(question, Mapping):
        return []
    raw = question.get("choices") or question.get("options") or []
    if isinstance(raw, Mapping):
        return [(str(value), str(label)) for value, label in raw.items()]
    if not isinstance(raw, (list, tuple)):
        return []
    pairs: list[tuple[str, str]] = []
    for item in raw:
        if isinstance(item, Mapping):
            value = item.get("value", item.get("id", item.get("key")))
            label = item.get("label", item.get("text", value))
            if value is not None:
                pairs.append((str(value), str(label)))
        elif item is not None and str(item).strip():
            pairs.append((str(item).strip(), str(item).strip()))
    return pairs


def is_multi(question: Mapping[str, Any] | None) -> bool:
    if not isinstance(question, Mapping):
        return False
    mode = str(question.get("mode") or "").strip().lower().replace(" ", "_")
    if mode in MULTI_MODES:
        return True
    if question.get("allow_multiple") is True or question.get("multiple") is True:
        return True
    return False


def answer_format(question: Mapping[str, Any] | None) -> str:
    """Model-facing description of the answer shape the platform accepts."""
    pairs = choice_pairs(question)
    if pairs:
        values = " | ".join(value for value, _label in pairs)
        if is_multi(question):
            return ('a JSON list of choice values, e.g. ["A", "C"] - each one of: ' + values)
        return ('exactly one choice value: ' + values
                + ' - submit the value itself (e.g. "A"), never the option sentence')
    return "the exact literal answer string (no quotes, no paraphrase, no placeholder)"


def option_map(*texts: Any) -> dict[str, str]:
    """Parse ``A) text ...`` / ``A. text`` option lines out of free text.

    MMLU/SECQA questions keep the option sentences in the description while
    ``choices`` only lists the letters, so this map is what lets the gate
    recognise "the sentence the model quoted" as choice ``A``.
    """
    mapping: dict[str, str] = {}
    for text in texts:
        if not isinstance(text, str) or not text.strip():
            continue
        for match in _OPTION_LINE.finditer(text):
            letter = match.group(1).upper()
            mapping.setdefault(letter, match.group(2).strip())
    return mapping


def resolve_choice(answer: Any, pairs: Iterable[tuple[str, str]],
                   options: Mapping[str, str] | None = None) -> str | None:
    """Map a model-supplied answer onto one declared choice value."""
    if not isinstance(answer, str) or not answer.strip():
        return None
    pairs = list(pairs)
    cleaned = answer.strip()
    for _ in range(2):  # "answer: A", "option A"
        stripped = _PREFIX.sub("", cleaned).strip()
        if stripped == cleaned:
            break
        cleaned = stripped
    cleaned = cleaned.strip().strip("\"'").strip()
    if not cleaned:
        return None
    # 1. the choice value itself, exactly or case-insensitively.
    for value, _label in pairs:
        if cleaned == value:
            return value
    key = _key(cleaned)
    for value, _label in pairs:
        if key and key == _key(value):
            return value
    # 2. a decorated value: "A)", "(A", "a.", "A: ...".
    match = _DECORATED.match(cleaned)
    if match:
        token = match.group(1)
        for value, _label in pairs:
            if value.casefold() == token.casefold():
                return value
    # 3. the option sentence was submitted where choices are letters.
    #    "A) sentence", "A. sentence" and the bare sentence all map to "A".
    prefix = re.match(r"^[\s(\[]*([A-Za-z0-9]{1,3})[\s)\].:\-]+(\S.*)$", cleaned)
    prefix_key = _key(prefix.group(2)) if prefix else ""
    for value, label in pairs:
        label_key = _key(label)
        if label_key and (key == label_key or (prefix_key and prefix_key == label_key)):
            return value
    options = options or {}
    declared = {value for value, _label in pairs}
    for letter, sentence in options.items():
        sentence_key = _key(sentence)
        if not sentence_key:
            continue
        if (key == sentence_key
                or (prefix_key and prefix_key == sentence_key)
                or (len(sentence_key) >= 20 and key.startswith(sentence_key))):
            # The sentence names an option; only a declared value is submittable.
            return letter if letter in declared else None
    return None


def _multi_values(answer: Any, pairs: list[tuple[str, str]],
                  options: Mapping[str, str] | None) -> list[str] | None:
    if isinstance(answer, list):
        items = answer
    else:
        items = [part for part in re.split(r"[,;\s]+", str(answer or "")) if part]
    resolved: list[str] = []
    for item in items:
        value = resolve_choice(item, pairs, options)
        if value is None:
            return None
        if value not in resolved:
            resolved.append(value)
    if not resolved:
        return None
    order = [value for value, _label in pairs]
    return [value for value in order if value in resolved]


def check_submission(question: Mapping[str, Any] | None, answer: Any, evidence: Any, *,
                     options: Mapping[str, str] | None = None) -> Decision:
    """Validate one answer before it can consume a platform attempt.

    A rejected submission never reaches the platform, so it never spends an
    attempt, and the returned ``instruction`` tells the model exactly what to
    send instead.

    Only a question that publishes ``choices`` gets the strict choice rules: a
    select mode without choices is not treated as enumerable, because blocking
    it would make the question unanswerable and grading is the platform's job.
    """
    if not isinstance(question, Mapping):
        return Decision(False, code="question_metadata_missing",
                        detail="the question payload is unavailable",
                        instruction="use `refresh` to reload platform state, then submit again")
    pairs = choice_pairs(question)
    if pairs:
        if is_multi(question):
            values = _multi_values(answer, pairs, options)
            if not values:
                return Decision(False, code="answer_not_in_choices",
                                detail="answer is not a valid set of declared choices",
                                instruction="submit " + answer_format(question)
                                            + "; no attempt was consumed")
            normalized: Any = values
        else:
            if isinstance(answer, list):
                return Decision(False, code="answer_not_single",
                                detail="this question accepts exactly one choice, not a list",
                                instruction="submit " + answer_format(question)
                                            + "; no attempt was consumed")
            value = resolve_choice(answer, pairs, options)
            if value is None:
                return Decision(False, code="answer_not_in_choices",
                                detail="answer %r is not one of the declared choices" % (str(answer)[:120],),
                                instruction="submit " + answer_format(question)
                                            + "; no attempt was consumed")
            normalized = value
    else:
        if not isinstance(answer, str) or not answer.strip():
            return Decision(False, code="answer_missing",
                            detail="answer must be a non-empty string",
                            instruction="submit the exact string you observed; no attempt was consumed")
        normalized = answer.strip()
        if len(normalized) > MAX_ANSWER_CHARS:
            return Decision(False, code="answer_too_long",
                            detail="answer is longer than %d characters" % MAX_ANSWER_CHARS,
                            instruction="submit only the answer string; no attempt was consumed")
        if _key(normalized) in _PLACEHOLDER_ANSWERS:
            return Decision(False, code="answer_placeholder",
                            detail="answer is a placeholder, not an observed value",
                            instruction="submit the real value observed in a tool response; "
                                        "no attempt was consumed")

    if not isinstance(evidence, str) or not evidence.strip():
        return Decision(False, code="evidence_missing",
                        detail="evidence is mandatory",
                        instruction="include `evidence` quoting the request/tool response "
                                    "or the cited fact that supports the answer")
    evidence_text = evidence.strip()
    if len(evidence_text) > MAX_EVIDENCE_CHARS:
        return Decision(False, code="evidence_too_long",
                        detail="evidence is longer than %d characters" % MAX_EVIDENCE_CHARS,
                        instruction="quote only the decisive fragment as evidence")
    if _key(evidence_text) in _GENERIC_EVIDENCE:
        return Decision(False, code="evidence_generic",
                        detail="evidence does not describe any observation",
                        instruction="quote the concrete observation that supports the answer")
    if _key(evidence_text) == _key(normalized if isinstance(normalized, str) else " ".join(normalized)):
        return Decision(False, code="evidence_is_answer",
                        detail="evidence repeats the answer instead of supporting it",
                        instruction="quote the observation or cited fact that supports the answer")
    return Decision(True, value=normalized, evidence=evidence_text)


def duplicate_decision(answer: Any) -> Decision:
    """Local rejection for an answer value that was already sent and graded."""
    return Decision(
        False,
        code="duplicate_submission",
        detail="answer %r was already submitted for this question"
               % (json.dumps(answer, ensure_ascii=False)[:120],),
        instruction="that value was already graded - choose a different answer or explain the "
                    "obstacle with `finish`; no attempt was consumed",
    )


def validate_verdict(verdict: Any, question_id: Any = None, *,
                     reconciled: bool = False) -> Verdict:
    """Normalise a platform verdict; only an explicit ``correct: true`` wins.

    Truthy-but-not-``True`` values (``"false"``, ``1``), a verdict for a
    different question, and non-object payloads are recorded as problems and
    never mark a question solved.
    """
    if not isinstance(verdict, Mapping):
        return Verdict(False, False, None, "invalid", ("verdict_not_an_object",))
    problems: list[str] = []
    raw = verdict.get("correct")
    if raw is None:
        correct = False
        problems.append("verdict_missing_correct")
    elif raw is True:
        correct = True
    elif raw is False:
        correct = False
    else:
        correct = False
        problems.append("verdict_correct_not_boolean")
    reported = verdict.get("question_id")
    if correct and isinstance(reported, str) and reported.strip():
        if question_id is not None and reported.strip() != str(question_id):
            correct = False
            problems.append("verdict_question_mismatch")
    attempts = verdict.get("attempts_remaining")
    if isinstance(attempts, bool) or not isinstance(attempts, int):
        attempts = None
    else:
        attempts = max(0, attempts)
    fully = verdict.get("challenge_fully_solved") is True
    if reconciled:
        basis = "reconciled_get"
    elif correct:
        basis = "platform_correct"
    else:
        basis = "platform_incorrect"
    return Verdict(correct, fully, attempts, basis, tuple(problems))


def claims_success(reason: Any) -> bool:
    """Does a ``finish`` reason assert an accepted/solved outcome?

    Negated clauses are ignored: "could not solve the challenge" is a failure
    report, while "answer C was accepted" is the SECQA-0132 style claim the
    finish gate exists for.
    """
    if not isinstance(reason, str) or not reason.strip():
        return False
    for clause in _CLAUSE_SPLIT.split(reason):
        if not clause.strip() or _NEGATION.search(clause):
            continue
        if _SUCCESS_CLAIM.search(clause):
            return True
    return False


def question_view(question: Mapping[str, Any] | None) -> dict[str, Any]:
    """Compact, model-facing question view used in the task briefing."""
    if not isinstance(question, Mapping):
        return {}
    view: dict[str, Any] = {"id": question.get("id")}
    for key in ("prompt", "mode", "requires"):
        if question.get(key):
            view[key] = question[key]
    pairs = choice_pairs(question)
    if pairs:
        view["choices"] = [value for value, _label in pairs]
    if question.get("attempts_remaining") is not None:
        view["attempts_remaining"] = question.get("attempts_remaining")
    view["answer_format"] = answer_format(question)
    return view


def finish_feedback(reason: Any, pending: Iterable[Mapping[str, Any]], solved: Iterable[str],
                    attempts_left: int | None = None) -> str:
    """Corrective message for a finish whose success claim is unconfirmed."""
    pending = [item for item in pending if isinstance(item, Mapping)]
    ids = [str(item.get("id")) for item in pending] or ["(none)"]
    solved = [str(item) for item in solved]
    lines = [
        "Finish rejected: your `reason` reports success, but the platform has not confirmed it.",
        "- open questions: " + ", ".join(ids[:8]),
        "- platform-confirmed solved: " + (", ".join(solved[:8]) if solved else "none"),
    ]
    if attempts_left is not None:
        lines.append("- attempts remaining on the open question(s): %d" % attempts_left)
    lines.extend([
        "Submitting a claim is not the same as a verdict: only `verdict.correct == true` from the",
        "platform counts. Either submit the answer you hold (with evidence) and wait for the verdict,",
        "or call `finish` again with a reason that states the obstacle instead of claiming success.",
    ])
    if isinstance(reason, str) and reason.strip():
        lines.append("Your rejected reason: " + reason.strip()[:300])
    return "\n".join(lines)


def unused_attempt_feedback(pending: Iterable[Mapping[str, Any]]) -> str:
    """Corrective message for a finish that abandons an untouched question."""
    pending = [item for item in pending if isinstance(item, Mapping)]
    rows = []
    for item in pending[:6]:
        rows.append("- %s: %s" % (item.get("id"), answer_format(item)))
    return "\n".join([
        "Finish rejected: no answer has been submitted and the open question still has attempts.",
        "Spend the remaining attempt with your best-supported answer and evidence, or state the",
        "concrete obstacle (for example a checker-mode question, or an empty question list).",
        *(rows or ["- (no question metadata)"]),
    ])
