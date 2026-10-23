"""Conservative completion from observed platform state, never empty queues."""


def assess(task_raw, challenge, instance, solved, confirmed_complete=False):
    sources = [task_raw, challenge, instance or {}]
    questions = {}
    for source in sources:
        for question in source.get("questions") or []:
            if isinstance(question, dict) and question.get("id"):
                qid = str(question["id"])
                questions[qid] = {**questions.get(qid, {}), **question}
    confirmed = set(solved)
    confirmed.update(qid for qid, q in questions.items() if q.get("answered_correctly") is True)
    states = {}
    for qid, question in questions.items():
        if qid in confirmed:
            status = "correct"
        elif question.get("unlocked") is False or any(str(r) not in confirmed for r in question.get("requires", [])):
            status = "locked"
        elif question.get("attempts_remaining") == 0:
            status = "attempts_exhausted"
        else:
            status = "available"
        states[qid] = status
    gated = next((s["gated_questions"] for s in reversed(sources) if "gated_questions" in s), None)
    explicit = confirmed_complete or any(s.get("challenge_fully_solved") is True for s in sources)
    # No declared hidden questions is necessary before inferring completeness.
    verified = bool(states) and all(s == "correct" for s in states.values()) and gated == 0
    return {"questions": states, "solved": sorted(confirmed), "fully_solved": bool(explicit or verified),
            "gated_questions": gated,
            "completion_basis": "platform_verdict" if explicit else "verified_questions" if verified else "unconfirmed"}
