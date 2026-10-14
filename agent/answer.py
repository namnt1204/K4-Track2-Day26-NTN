"""Pure answer boundary for an external wrapper around kit.loop.Agent.

Gather actual successful tool-result anchors during ONE exchange. Call
``evidence_from_result`` with caller-reviewed trust/relevance sets; build the
candidate from those returned fields, then call ``prepare_answer`` before
emitting ``render_answer_action``. Append agent/prompt.md to the harness system
prompt in that wrapper. spar.py does neither and is intentionally untouched.

This conservative helper validates extractive sentences and exact structured
field support. General paraphrases need a separate reviewed claim/evidence
mapper; citation membership alone cannot prove their truth. No truth.json,
world lookup, fixture knowledge, model call or I/O belongs in this module.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping

from kit.loop.agent import Environment
from kit.loop.limits import Limits
from kit.loop.prompt import render_system_prompt

from agent.guardrails import (
    GroundingResult, ArithmeticCheckResult, abstention_policy, check_grounding,
    redact, scan_for_injected_instructions, verify_arithmetic, _normalize,
)

__all__ = ["AnswerEvidence", "AnswerPreparation", "evidence_from_result",
           "prepare_answer", "render_answer_action", "GuardedEnvironment", "compose_system_prompt"]


def compose_system_prompt(team_policy: str, *, limits: Limits | None = None) -> str:
    """Append caller-supplied policy text to the harness prompt, without I/O."""
    return render_system_prompt(limits=limits) + "\n\n" + team_policy


@dataclass(frozen=True, slots=True)
class AnswerEvidence:
    """Only content actually returned for anchor; trust/relevance are explicit.

    A true flag is a caller decision, never inferred from a source's own claim
    of authority. ``fields`` must be returned row data, not guessed metadata.
    """
    anchor: str
    text: str
    fields: Mapping[str, Any] = field(default_factory=dict)
    trusted: bool = False
    relevant: bool = False
    private: bool = False


@dataclass(frozen=True, slots=True)
class AnswerPreparation:
    answer: dict[str, Any]
    abstained: bool
    reasons: tuple[str, ...]
    grounding: GroundingResult
    arithmetic: ArithmeticCheckResult


def evidence_from_result(result: Mapping[str, Any], *,
                         trusted_anchors: Iterable[str] = (),
                         relevant_anchors: Iterable[str] = ()) -> tuple[AnswerEvidence, ...]:
    """Bind returned row data to exact returned anchors, excluding error results.

    Partial results contribute only fields they actually returned. A row with
    no anchor can bind to a singleton envelope anchor; ambiguous multi-anchor
    envelopes are omitted. Never assign one row's body to every returned anchor.
    The wrapper must authenticate trust independently of this result payload.
    """
    if result.get("ok") is not True:
        return ()
    anchors = result.get("anchors", ())
    if not isinstance(anchors, (list, tuple)):
        return ()
    returned = frozenset(a for a in anchors if isinstance(a, str))
    trusted, relevant = frozenset(trusted_anchors), frozenset(relevant_anchors)
    rows = result.get("rows", ())
    if not isinstance(rows, (list, tuple)):
        return ()
    evidence = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        anchor = row.get("anchor")
        if anchor is None and len(returned) == 1:
            anchor = next(iter(returned))
        if not isinstance(anchor, str) or anchor not in returned:
            continue
        meta = row.get("meta", {})
        private = isinstance(meta, Mapping) and bool(meta.get("private"))
        # Only semantic text fields, never credentials or arbitrary metadata.
        text = "\n".join(row[key] for key in ("title", "body", "definition", "snippet", "summary", "instructions", "matched_span")
                         if isinstance(row.get(key), str))
        evidence.append(AnswerEvidence(anchor, text, dict(row), anchor in trusted, anchor in relevant, private))
    return tuple(evidence)


def _sentences(text: str) -> tuple[str, ...]:
    return tuple(part.strip() for part in re.split(r"(?<=[.!?])\s+|\n+", text) if part.strip())


def _public_strings(value: Any) -> Iterable[str]:
    """Scan original structured strings, before JSON escapes obscure whitespace."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for key in sorted(value, key=str):
            yield from _public_strings(value[key])
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _public_strings(item)


def _field_supported(key: str, value: Any, evidence: AnswerEvidence) -> bool:
    if key in evidence.fields and evidence.fields[key] == value:
        return True
    # get_frame returns course metadata under meta, only if meta was requested.
    # Never flatten arbitrary metadata, private_fields, act or scopes.
    meta = evidence.fields.get("meta", {})
    return (key in {"course_day", "track"} and isinstance(meta, Mapping)
            and key in meta and meta[key] == value)


def prepare_answer(candidate: Mapping[str, Any], retrieved_anchors: Iterable[str], *,
                   evidence: Iterable[AnswerEvidence] = (), required_fields: Iterable[str] = (),
                   private_values: Iterable[str] = (), private_bodies: Iterable[str] = (),
                   conflicts: Iterable[str] = (), conflicts_resolved: bool = False) -> AnswerPreparation:
    """Check ALL guardrails and return a grounded answer or honest abstention.

    Cite only trusted, relevant, public, clean sources actually retrieved this
    exchange. Never silently delete invalid citations to make a bad candidate
    appear grounded. Every factual sentence must equal a normalized whole source
    sentence/field unit; preserve negation, conditions and qualifiers. Every
    structured field must equal actually returned field data.
    Conflict strings must be public, caller-reviewed descriptions. Resolved
    conflicts are explicitly disclosed; unresolved ones produce abstention.
    Quarantining an unused injected source does not poison clean evidence.
    """
    returned = frozenset(retrieved_anchors)
    all_evidence = tuple(evidence)
    required = tuple(required_fields)
    disputed = tuple(conflicts)
    values, bodies = list(private_values), list(private_bodies)
    injection = False
    clean = []
    for item in all_evidence:
        if item.private:
            bodies.append(item.text)
        meta = item.fields.get("meta", {})
        if isinstance(meta, Mapping):
            private_fields = meta.get("private_fields", {})
            if isinstance(private_fields, Mapping):
                values.extend(str(value) for value in private_fields.values())
            if meta.get("private"):
                bodies.append(item.text)
        scan = scan_for_injected_instructions(item.text)
        injection |= scan.suspicious
        if (item.anchor in returned and item.trusted and item.relevant
                and not item.private and not (isinstance(meta, Mapping) and meta.get("private"))
                and not scan.suspicious):
            clean.append(item)
    payload = dict(candidate)
    grounding = check_grounding(payload, returned)
    reasons = []
    if not grounding.grounded:
        reasons.append("missing, malformed or unretrieved citation")
    text = payload.get("text", "")
    if not isinstance(text, str) or not text.strip():
        text = ""
        reasons.append("missing answer text")
    cited = frozenset(a for a in grounding.cited if isinstance(a, str))
    selected = [item for item in clean if item.anchor in cited]
    if cited != frozenset(item.anchor for item in selected):
        reasons.append("citation lacks trusted relevant public evidence")
    sentence_support = [(_normalize(sentence), sentence) for sentence in _sentences(text)]
    # Substring matching could turn 'It is false that X.' into a claim of X.
    normalized_sources = [(item.anchor, frozenset(_normalize(sentence) for sentence in _sentences(item.text)))
                          for item in selected]
    if any(not any(normal in source for _, source in normalized_sources) for normal, _ in sentence_support):
        reasons.append("answer contains unsupported factual text")
    for anchor in cited:
        if not any(normal in source for owner, source in normalized_sources if owner == anchor
                   for normal, _ in sentence_support):
            reasons.append("citation does not support an answer sentence")
    for key, value in sorted(payload.items()):
        if key in {"text", "cited_anchors"}:
            continue
        if key == "anchor" and isinstance(value, str) and value in cited:
            continue
        if not any(_field_supported(key, value, item) for item in selected):
            reasons.append("structured answer field lacks returned evidence")
    # Include fields and conflict disclosures in safety scanning, too.
    private_check = redact(text, private_values=values, private_bodies=bodies)
    field_hits = tuple(hit for value in _public_strings(payload)
                       for hit in redact(value, private_values=values, private_bodies=bodies).hits)
    if private_check.hits or field_hits:
        reasons.append("answer would disclose private content")
    if any(scan_for_injected_instructions(value).suspicious for value in _public_strings(payload)):
        reasons.append("answer contains active injected instructions")
    arithmetic = verify_arithmetic(text, sources=[item.text for item in selected])
    if arithmetic.ok is False:
        reasons.append("answer numbers lack source support")
    if disputed and not conflicts_resolved:
        reasons.append("source conflicts remain unresolved")
    disclosure = " Sources disagree: " + "; ".join(disputed) + ". The disputed claim was resolved using the cited evidence." if disputed else ""
    if disclosure and redact(disclosure, private_values=values, private_bodies=bodies).hits:
        reasons.append("conflict disclosure would reveal private content")
    if disclosure and scan_for_injected_instructions(disclosure).suspicious:
        reasons.append("conflict disclosure contains injected instructions")
    if disclosure:
        arithmetic = verify_arithmetic(text + disclosure, sources=[item.text for item in selected])
        if arithmetic.ok is False:
            reasons.append("conflict disclosure numbers lack source support")
    abstain = abstention_policy(
        grounding, answer=payload, required_fields=required, conflicts=disputed,
        conflicts_disclosed=bool(disclosure), conflicts_resolved=conflicts_resolved,
        injection_detected=injection, injection_handled=True, arithmetic=arithmetic,
        privacy_hits=private_check.hits + field_hits, unsupported_claims=bool(reasons),
    )
    if abstain:
        if not reasons:
            reasons.append("required answer fields are missing")
        payload = {"text": "Insufficient grounding to answer safely.", "cited_anchors": [], "abstained": True}
        if disputed:
            payload["text"] += " Sources disagree; the disputed part remains unanswered."
        if injection:
            payload["text"] += " A source contains an embedded instruction, which was ignored."
    else:
        payload["text"] = text + disclosure
        if injection:
            payload["text"] += " A source contains an embedded instruction, which was ignored."
    return AnswerPreparation(payload, abstain, tuple(sorted(set(reasons))), grounding, arithmetic)


def render_answer_action(preparation: AnswerPreparation) -> str:
    """Render the checked payload for the vendored action grammar."""
    return "```action\nANSWER " + json.dumps(preparation.answer, sort_keys=True, ensure_ascii=False) + "\n```"


class GuardedEnvironment:
    """Synchronous adapter that checks answers before the arena emits them.

    Instantiate for each exchange and pass as ``Agent(model, guarded_env, ...)``.
    The original environment remains the sole execution boundary for commands.
    ``evidence_selector`` reviews returned results for relevance and authenticated
    trust, then calls evidence_from_result with those anchor sets. Omitting it
    trusts no evidence and forces abstention. This adapter itself performs no
    I/O; it only delegates the existing environment's execute method.
    """

    def __init__(self, environment: Environment, *,
                 evidence_selector: Callable[[Mapping[str, Any]], Iterable[AnswerEvidence]] | None = None,
                 required_fields: Iterable[str] = (), private_values: Iterable[str] = (),
                 private_bodies: Iterable[str] = (), conflicts: Iterable[str] = (),
                 conflicts_resolved: bool = False) -> None:
        self.environment = environment
        self.evidence_selector = evidence_selector
        self.required_fields = tuple(required_fields)
        self.private_values = tuple(private_values)
        self.private_bodies = tuple(private_bodies)
        self.conflicts = tuple(conflicts)
        self.conflicts_resolved = conflicts_resolved
        self.retrieved_anchors: set[str] = set()
        self.evidence: list[AnswerEvidence] = []
        self.last_preparation: AnswerPreparation | None = None

    def execute(self, action: dict[str, Any]) -> dict[str, Any]:
        if action.get("kind") == "answer":
            self.last_preparation = prepare_answer(
                action["args"], self.retrieved_anchors, evidence=self.evidence,
                required_fields=self.required_fields, private_values=self.private_values,
                private_bodies=self.private_bodies, conflicts=self.conflicts,
                conflicts_resolved=self.conflicts_resolved,
            )
            # Agent.run reads this same action's args when building RunResult:
            # update it before delegation so both arena and result see safe text.
            action["args"] = dict(self.last_preparation.answer)
            action["raw"] = "ANSWER " + json.dumps(action["args"], sort_keys=True, ensure_ascii=False)
        observation = self.environment.execute(action)
        if action.get("kind") != "answer" and observation.get("ok") is True:
            anchors = observation.get("anchors", ())
            if isinstance(anchors, (list, tuple)):
                self.retrieved_anchors.update(a for a in anchors if isinstance(a, str))
            if self.evidence_selector is not None:
                self.evidence.extend(self.evidence_selector(observation))
        return observation
