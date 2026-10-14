"""agent/gateway.py — YOUR control plane. CONTRACTS.md section 4, exactly.

READ agent/README.md FIRST — it maps all five files in this directory to what
each is scored on. This file is the one CONTRACTS.md calls "the trusted
envelope's untrusted half": every single MCP / A2A / DISCOVER command your
agent's model wants to make passes through `Gateway.decide` before it is
allowed to happen.

WHY THERE IS NO `execute()` METHOD ON `GatewayContext` (read this before you
go looking for one — there isn't one, and that is not an oversight)
----------------------------------------------------------------------------
CONTRACTS.md section 4's trusted envelope, reproduced here because it is the
one diagram worth memorising:

    [ trusted ]   loop emits a raw action line
         v
    [ trusted ]   INTERCEPT + CANONICALISE -> Command        (kit/loop/agent.py)
         v
    [ UNTRUSTED ] Gateway.decide(cmd) -> Decision             <- THIS FILE
         v
    [ trusted ]   ENFORCE: honour the Decision, meter it,
                  apply the active mutation, execute the
                  ToolCall or refuse it                       (the arena)
         v
    [ trusted ]   RECORD the authoritative L1 event, then
                  RENDER the Observation                      (the arena)
         v
    [ trusted ]   the model sees the Observation

`decide()` returns a *decision*, never a *result*. You cannot reach a tool
server, a file, a socket, or a clock from in here — there is nothing to
call. Two things follow from that, and both matter more than they look:

  1. YOUR TRACE CANNOT BE FORGED. Every `command` / `decision` / `enforced`
     / `tool_call` / `tool_result` L1 event (CONTRACTS.md 5.2) is written by
     the arena, from what the arena itself actually did — never from
     anything you claimed happened. A student gateway that wanted to lie
     about having blocked an attack ("I totally denied that, trust me")
     simply has no channel to lie through: the only thing you ever hand
     back is this one small `Decision` value, and the arena is the one that
     turns it into history.
  2. NOBODY CAN ACCUSE YOU OF A CALL YOU DID NOT AUTHORISE, either. Because
     `decide()` is the ONLY door a command can walk through on its way to
     actually running, a prosecutor's `enforcement_failure` claim against
     you has exactly one thing to point at: the `Decision` you returned for
     that specific `cmd_id`. There is no ambiguity about "maybe the loop
     called the tool directly" — CONTRACTS.md 4.2 removed that path on
     purpose, and kit/loop/agent.py's own module docstring names the same
     invariant from the other side (the loop never imports this module,
     never sees a `Decision`, never executes anything itself).

The cost of that guarantee is that this file is PURE: synchronous, no I/O,
no threads, no `sleep`, 250 ms wall-clock deadline (RULES.md section 3).
Raising anything, returning something that is not a valid `Decision`, or
missing the deadline is treated by the arena as a DENIED command PLUS a 2
credit penalty PLUS an `integrity` event that hands the prosecutor a free
`enforcement_failure` — CONTRACTS.md 4.1's charging table, reproduced in
agent/README.md's own table. Getting this file to just plainly return valid
`Decision` values, every time, is worth more than getting it clever.

POLICY SHAPE (the four enforcement stages)
----------------------------------------------------------------------------
ROUTE selects headers and successors, ADMIT validates peers and leases,
AUTHORIZE binds targets and write preconditions to trusted context, and
BUDGET narrows masks and reserves credits across the duel. Changes return
rewrite; unchanged clean calls forward; unsafe or unaffordable calls deny.

ONE THING WORTH INTERNALISING BEFORE YOU WRITE YOUR FIRST REAL CHECK:
`verdict="deny"` costs the CALLER (your own team) **zero credits** —
CONTRACTS.md 4.1's charging table has exactly one $0 row, and it is this
one. Refusing to make a call you cannot justify is FREE. That makes
abstention a real strategy, not a luxury you can't afford: a `deny` you can
defend beats a `forward` you can't, every time a prosecutor is watching.

Stdlib only. No network, no randomness, no wall-clock reads, no sleeping —
none of that would even survive the kernel sandbox (CONTRACTS.md 12), but
the point is this file has no reason to want any of it in the first place.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Mapping, Protocol, runtime_checkable

# kit.mcp.types is a collaborator's file (workspace hard rule 2: import it,
# degrade gracefully). It is present as of this writing and is core, stable
# infrastructure (CONTRACTS.md 3.1) — but this module must still not fail to
# IMPORT if a concurrent edit ever breaks it transiently. When it is
# unavailable, `Decision.call` type-checking is skipped (not enforced), and
# `Gateway.decide` falls back to a minimal local dict-shaped stand-in so the
# rest of this file — everything that does not need a *real* ToolCall — still
# runs.
try:
    from kit.mcp.types import ToolCall
    _TOOLCALL_AVAILABLE = True
except ImportError:  # pragma: no cover - collaborator file
    ToolCall = Any  # type: ignore[assignment, misc]
    _TOOLCALL_AVAILABLE = False

# kit.loop.agent is also a collaborator's file, used only by this module's
# own __main__ demo (to build real Commands the same way the arena's trusted
# canonicaliser would) — never by decide() itself, which never touches the
# loop. Degraded the same way.
try:
    from kit.loop.agent import canonicalise_action as _canonicalise_action
except ImportError:  # pragma: no cover - collaborator file
    _canonicalise_action = None

from agent.telemetry import RecordingGatewayContext, Telemetry
from agent.strategy import pick_replica, cheap_mask

# Load policy dependencies before entering the synchronous, no-I/O boundary.
# A missing collaborator module fails closed, while Command/Decision still import.
try:
    from kit.mcp.specs import TOOL_SPECS, A2A_PEERS
    from kit.mcp.a2a import AGENT_CARDS, SKILL_ROUTES, verify_card, verify_delegation
    from kit.mcp.servers import _lookup_spec
except ImportError:  # pragma: no cover - transient collaborator edit
    TOOL_SPECS, AGENT_CARDS, SKILL_ROUTES = {}, {}, {}
    A2A_PEERS = frozenset()
    def _lookup_spec(server: str, tool: str) -> Any:
        return None

__all__ = [
    "COMMAND_KINDS",
    "DECISION_VERDICTS",
    "Command",
    "Decision",
    "GatewayContext",
    "Gateway",
]

# CONTRACTS.md 4.1: `Command.kind` — "mcp" | "a2a" | "discover". An "answer"
# action is NEVER a Command (kit/loop/agent.py's own module docstring: "an
# answer is not a tool call routed to a server, so it never becomes a
# Command at all") — it is handled entirely by the loop/arena and never
# reaches `Gateway.decide`.
COMMAND_KINDS: frozenset[str] = frozenset({"mcp", "a2a", "discover"})

# CONTRACTS.md 4.1: `Decision.verdict` — the closed three-member set.
DECISION_VERDICTS: frozenset[str] = frozenset({"forward", "deny", "rewrite"})


@dataclass(frozen=True, slots=True)
class Command:
    """CONTRACTS.md 4.1, field for field — "canonicalised by the arena
    BEFORE the student sees it". You never build one of these from your own
    agent's raw text; the arena's canonicaliser (kit/loop/agent.py's
    `canonicalise_action`, run inside the trusted envelope) already did that
    work and minted `cmd_id` by the time `decide()` sees it. The
    `from_action_dict` classmethod below exists only so this file's own demo
    (and your local tests, if you write any) can build a realistic `Command`
    without duplicating the arena's canonicalisation logic."""

    cmd_id: str
    kind: str  # "mcp" | "a2a" | "discover" — see COMMAND_KINDS
    raw: str
    server: str
    tool: str
    args: dict
    fields: tuple[str, ...]
    headers: dict
    lease_id: str | None
    call_index: int

    def __post_init__(self) -> None:
        if not isinstance(self.cmd_id, str) or not self.cmd_id:
            raise ValueError(f"Command.cmd_id must be a non-empty str, got {self.cmd_id!r}")
        if self.kind not in COMMAND_KINDS:
            raise ValueError(f"Command.kind must be one of {sorted(COMMAND_KINDS)}, got {self.kind!r}")
        if not isinstance(self.server, str) or not self.server:
            raise ValueError(f"Command.server must be a non-empty str, got {self.server!r}")
        if not isinstance(self.tool, str) or not self.tool:
            raise ValueError(f"Command.tool must be a non-empty str, got {self.tool!r}")
        if not isinstance(self.args, dict):
            raise ValueError(f"Command.args must be a dict, got {type(self.args).__name__}")
        if not isinstance(self.headers, dict):
            raise ValueError(f"Command.headers must be a dict, got {type(self.headers).__name__}")
        if (
            not isinstance(self.call_index, int)
            or isinstance(self.call_index, bool)
            or self.call_index < 0
        ):
            raise ValueError(f"Command.call_index must be a non-negative int, got {self.call_index!r}")

    @classmethod
    def from_action_dict(cls, action: Mapping[str, Any], *, cmd_id: str) -> "Command":
        """Build a `Command` from the dict shape `kit.loop.agent.canonicalise_action`
        returns (`kind, raw, server, tool, args, fields, headers, lease_id,
        call_index` — everything except the arena-minted `cmd_id`, supplied
        here as a keyword). Raises `ValueError` if `action["kind"] ==
        "answer"` — an answer is never a Command (see the module docstring).
        This is a convenience for tests/demos, not something the real arena
        calls: the trusted envelope mints `cmd_id` itself and constructs the
        real `Command` on its own side of the boundary."""
        kind = action.get("kind")
        if kind == "answer":
            raise ValueError(
                "an 'answer' action never becomes a Command (kit/loop/agent.py: "
                "\"an answer is not a tool call routed to a server\") — do not "
                "route it through Gateway.decide at all"
            )
        return cls(
            cmd_id=cmd_id,
            kind=kind,
            raw=action["raw"],
            server=action["server"],
            tool=action["tool"],
            args=dict(action.get("args", {})),
            fields=tuple(action.get("fields", ())),
            headers=dict(action.get("headers", {})),
            lease_id=action.get("lease_id"),
            call_index=action.get("call_index", 0),
        )

    def to_dict(self) -> dict:
        return {
            "cmd_id": self.cmd_id,
            "kind": self.kind,
            "raw": self.raw,
            "server": self.server,
            "tool": self.tool,
            "args": dict(self.args),
            "fields": list(self.fields),
            "headers": dict(self.headers),
            "lease_id": self.lease_id,
            "call_index": self.call_index,
        }


@dataclass(frozen=True, slots=True)
class Decision:
    """CONTRACTS.md 4.1, field for field.

    Validated strictly (`__post_init__`) because a *structurally* invalid
    `Decision` is charged exactly like a raised exception — CONTRACTS.md
    4.1's charging table: "malformed Decision (schema-invalid) -> 2 cr
    penalty, command denied." Failing loudly HERE, in your own process
    during development, is strictly better than discovering it live in a
    duel as an unexplained penalty.

    `verdict == "deny"` requires a non-empty `reason` (CONTRACTS.md 4.1:
    "required when verdict == 'deny'; shown in the combat log") and
    forbids `call` — a real denial has nothing left to carry out.
    `verdict` in `("forward", "rewrite")` requires `call` to be set — the
    arena executes exactly that `ToolCall`, nothing else, per the trusted
    envelope's whole point (see the module docstring)."""

    verdict: str  # "forward" | "deny" | "rewrite" — see DECISION_VERDICTS
    reason: str | None = None
    call: "ToolCall | None" = None
    quarantine: bool = False
    note: str | None = None

    def __post_init__(self) -> None:
        if self.verdict not in DECISION_VERDICTS:
            raise ValueError(
                f"Decision.verdict must be one of {sorted(DECISION_VERDICTS)}, got {self.verdict!r}"
            )
        if self.verdict == "deny":
            if not isinstance(self.reason, str) or not self.reason.strip():
                raise ValueError("Decision.verdict=='deny' requires a non-empty 'reason'")
            if self.call is not None:
                raise ValueError("Decision.verdict=='deny' must not carry a 'call' — there is nothing to run")
        else:  # forward | rewrite
            if self.call is None:
                raise ValueError(f"Decision.verdict=={self.verdict!r} requires 'call' to be set")
            if _TOOLCALL_AVAILABLE and not isinstance(self.call, ToolCall):
                raise ValueError(
                    f"Decision.call must be a kit.mcp.types.ToolCall instance, got {type(self.call).__name__}"
                )
        if not isinstance(self.quarantine, bool):
            raise ValueError(f"Decision.quarantine must be a bool, got {self.quarantine!r}")
        if self.note is not None and not isinstance(self.note, str):
            raise ValueError(f"Decision.note must be a str or None, got {self.note!r}")

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "reason": self.reason,
            "call": self.call.to_dict() if self.call is not None and hasattr(self.call, "to_dict") else self.call,
            "quarantine": self.quarantine,
            "note": self.note,
        }


@runtime_checkable
class GatewayContext(Protocol):
    """CONTRACTS.md 4.2 — "read-only, arena-provided". Note what this is
    NOT: unlike `Command`/`Decision` above, CONTRACTS.md writes this as a
    plain `class`, not a `@dataclass(frozen=True, ...)`. That is a real
    signal, not an inconsistency — a `GatewayContext` is a LIVE VIEW the
    arena owns and updates as the duel actually progresses (credits get
    spent, rounds advance, leases mint and expire), not a frozen snapshot
    you receive once. This file therefore models it as a structural
    `Protocol`: the arena hands your `Gateway.__init__` some object shaped
    like this (see `agent/telemetry.py`'s `RecordingGatewayContext` for a
    concrete example your own tests/demos can build), and you read
    `self.ctx.<field>` fresh every time `decide()` runs — NEVER cache a
    context field into a local variable across calls; if you need memory
    that persists across the duel (a cache, a budget tracker, drift notes),
    keep it on YOUR OWN `Gateway` instance attributes instead (CONTRACTS.md
    4.3: "Gateway is instantiated once per duel... persists across the 10
    rounds").

    There is deliberately no `execute` method here — see the module
    docstring's "WHY THERE IS NO execute() METHOD" section. `emit` is the
    ONE thing you can do that has any side effect at all, and it writes to
    `own_telemetry` only: your own side, never scored, never shown to the
    opponent (`agent/telemetry.py` wraps it)."""

    act: str  # "learner:sv-0417" — WHOM YOU SERVE. Authority derives from this.
    sub: str  # "agent:vlearn-tutor" — what you are. NOT authority.
    scopes: frozenset[str]  # {"wiki.read"}; writes need "wiki.write:progress" etc.
    credits: int  # remaining this duel
    round: int
    call_index: int
    leases: tuple[str, ...]  # live lease ids, arena-tracked
    history: tuple[Mapping[str, Any], ...]  # YOUR OWN prior (Command, Decision, outcome) triples this duel

    def emit(self, name: str, **payload: Any) -> None: ...


class Gateway:
    """Pure ROUTE, ADMIT, AUTHORIZE and BUDGET control plane.

    Only the arena-owned context, successful history, and trusted result
    callbacks supply authority. Outgoing arguments never vouch for themselves.
    Estimates reserve credits until the live context reflects actual charges.
    """

    def __init__(self, ctx: GatewayContext) -> None:
        self.ctx = ctx
        self._telemetry = Telemetry(ctx)
        self._denied_cmd_ids: set[str] = set()
        self._cards: dict[str, dict] = {}
        self._provenance: dict[str, dict] = {}
        self._tokens: set[str] = set()
        self._idempotency: set[str] = set()
        self._write_attempts: dict[str, tuple[int, int]] = {}
        self._conflicts: dict[str, str] = {}
        self._rates: dict[tuple[str, str], list[int]] = {}
        self._round_spend: dict[int, int] = {}
        self._credits_authorised = 0
        self._pending = 0
        self._last_credits: int | None = None
        self._history_seen: set[tuple] = set()
        self._reservations: dict[tuple[int, str], int] = {}
        self._command_rounds: dict[str, int] = {}

    @staticmethod
    def _mapping(value: Any) -> Mapping:
        if isinstance(value, Mapping):
            return value
        if hasattr(value, "to_dict"):
            result = value.to_dict()
            return result if isinstance(result, Mapping) else {}
        return {}

    @staticmethod
    def _learner(value: Any) -> str | None:
        if not isinstance(value, str) or not value.strip():
            return None
        value = value.strip()
        if ":" in value:
            ns, value = value.split(":", 1)
            if ns.lower() != "learner":
                return None
        if not value or any(c in value for c in "/# "):
            return None
        return "learner:" + value

    @staticmethod
    def _anchor_key(anchor: Any) -> str | None:
        if not isinstance(anchor, str) or not anchor:
            return None
        if anchor.lower().startswith("learner:"):
            return Gateway._learner(anchor)
        return anchor

    def _emit(self, method: str, *args: Any, **kw: Any) -> None:
        # Diagnostics must never turn a valid free denial into an exception.
        try:
            getattr(self._telemetry, method)(*args, **kw)
        except Exception:
            pass

    def note_card(self, server: str, card: Mapping) -> None:
        """Trusted harness callback, never populated from Command arguments.

        Signed kit cards are verified. The small verified/skills shape is the
        registry-vouched callback used by spar; it is not a wire credential.
        """
        try:
            if server not in AGENT_CARDS:
                return
            data = dict(self._mapping(card))
            if "signature" in data:
                admission = verify_card(data)
                if not admission.admitted or admission.peer != server:
                    self._cards.pop(server, None)
                    return
                skills = admission.declared_skills
                legacy = False
            else:
                skills = data.get("skills")
                if data.get("verified") is not True or not isinstance(skills, (list, tuple)):
                    self._cards.pop(server, None)
                    return
                if not all(isinstance(x, str) for x in skills):
                    return
                legacy = True
            self._cards[server] = {"skills": tuple(skills), "legacy": legacy,
                                   "signature": data.get("signature"),
                                   "fingerprint": data.get("fingerprint")}
        except (ImportError, TypeError, ValueError, KeyError):
            self._cards.pop(server, None)

    def note_provenance(self, anchor: str, etag: str, **metadata: Any) -> None:
        """Trusted successful registry.provenance callback (not a model claim).

        Optional round/call_index preserve the result's issuance position;
        preferred_replica is an explicit registry freshness signal. A mere
        replica label or etag comparison does not prove which copy is fresher.
        """
        key = self._anchor_key(anchor)
        if key and isinstance(etag, str) and etag:
            rnd = metadata.get("round", getattr(self.ctx, "round", 0))
            idx = metadata.get("call_index", getattr(self.ctx, "call_index", 0))
            preferred = metadata.get("preferred_replica")
            if isinstance(rnd, int) and isinstance(idx, int):
                self._provenance[key] = {"etag": etag, "round": rnd,
                                         "call_index": idx,
                                         "preferred_replica": preferred if preferred in ("w", "c") else None}

    def _refresh_history(self) -> None:
        """Read successful arena-owned (Command, Decision, outcome) triples.

        Supports mapping and positional triples; result wrappers and ToolResult
        objects are accepted. Denials and failed results cannot issue etags.
        """
        history = getattr(self.ctx, "history", ())
        if not isinstance(history, (tuple, list)):
            return
        for position, entry in enumerate(history):
            if isinstance(entry, (tuple, list)) and len(entry) == 3:
                command, decision, result = entry
                entry_round = None
            elif isinstance(entry, Mapping):
                command = entry.get("command", entry.get("cmd", {}))
                decision = entry.get("decision", {})
                result = entry.get("outcome", entry.get("result", entry.get("tool_result", {})))
                entry_round = entry.get("round")
            else:
                continue
            c, d, r = map(self._mapping, (command, decision, result))
            if "result" in r:
                r = self._mapping(r["result"])
            # A history triple need not carry round metadata. Link it to a
            # command this instance saw; never label an undated old result as
            # current just because it appeared in this round's live context.
            rnd = entry_round if entry_round is not None else c.get("round", self._command_rounds.get(c.get("cmd_id")))
            idx = c.get("call_index", position)
            marker = (position, c.get("cmd_id"), c.get("server"), c.get("tool"), rnd, idx)
            if marker in self._history_seen or d.get("verdict") == "deny":
                continue
            self._history_seen.add(marker)
            # The executed Decision.call may have normalized learner aliases
            # or changed a deprecated tool. It is the authoritative target.
            executed = self._mapping(d.get("call", {}))
            if executed:
                c = dict(c, **executed)
            reservation = (rnd, c.get("cmd_id"))
            actual = r.get("cost")
            if reservation in self._reservations and isinstance(actual, int) and not isinstance(actual, bool) and actual >= 0:
                estimated = self._reservations.pop(reservation)
                delta = actual - estimated
                self._round_spend[rnd] = max(0, self._round_spend.get(rnd, 0) + delta)
                self._pending = max(0, self._pending + delta)
            prior_spec = _lookup_spec(c.get("server"), c.get("tool"))
            prior_headers = self._mapping(c.get("headers", {}))
            prior_args = self._mapping(c.get("args", {}))
            prior_key = self._anchor_key(prior_args.get("anchor"))
            if prior_spec and prior_spec.is_write:
                idem = prior_headers.get("idempotency-key")
                if isinstance(idem, str) and idem:
                    self._idempotency.add(idem)
                if prior_key and isinstance(rnd, int) and isinstance(idx, int):
                    previous = self._write_attempts.get(prior_key, (-1, -1))
                    self._write_attempts[prior_key] = max(previous, (rnd, idx))
            if d.get("verdict") == "deny" or r.get("ok") is not True:
                # Conflict histories still invalidate unchanged write retries.
                error = self._mapping(r.get("error", {}))
                if error.get("code") == "conflict":
                    if prior_key and isinstance(prior_headers.get("if-match"), str):
                        self._conflicts[prior_key] = prior_headers["if-match"]
                continue
            if isinstance(rnd, int) and (c.get("server"), c.get("tool")) == ("registry", "provenance"):
                anchor = self._mapping(c.get("args", {})).get("anchor")
                rows = r.get("rows", ())
                row = self._mapping(rows[0]) if isinstance(rows, (list, tuple)) and rows else {}
                etag = r.get("etag") or row.get("etag")
                self.note_provenance(anchor, etag, round=rnd, call_index=idx,
                                     preferred_replica=row.get("preferred_replica"))

    def deny(self, cmd: Command, reason: str) -> Decision:
        ident = getattr(cmd, "cmd_id", None)
        if isinstance(ident, str):
            self._denied_cmd_ids.add(ident)
        decision = Decision(verdict="deny", reason=reason)
        self._emit("decision_made", cmd, decision)
        return decision

    def decide(self, cmd: Command) -> Decision:
        """Synchronous: no I/O, threads, or clock. Malformed input denies free."""
        self._emit("decision_seen", cmd)
        try:
            return self._decide(cmd)
        except Exception:
            # Arbitrary malformed nested values must never cause an arena penalty.
            return self.deny(cmd, "malformed command or trusted policy context")

    def _decide(self, cmd: Command) -> Decision:
        self._refresh_history()
        if not isinstance(cmd, Command) or not isinstance(cmd.raw, str):
            return self.deny(cmd, "invalid command")
        if not all(isinstance(k, str) for k in cmd.headers) or not all(isinstance(k, str) for k in cmd.args):
            return self.deny(cmd, "argument and header names must be strings")
        headers = {k.lower(): v for k, v in cmd.headers.items()}
        if len(headers) != len(cmd.headers):
            return self.deny(cmd, "ambiguous duplicate header names")
        if isinstance(cmd.fields, (str, bytes)) or not all(isinstance(x, str) for x in cmd.fields):
            return self.deny(cmd, "malformed field mask")
        if any(k in cmd.args for k in ("route", "_route", "replica", "mcp-replica")):
            return self.deny(cmd, "replica routing must use the header")
        args = dict(cmd.args)
        fields = tuple(sorted(set(f.lower() for f in cmd.fields)))
        server, tool = cmd.server, cmd.tool
        wire = SKILL_ROUTES.get(tool)
        if server in A2A_PEERS and wire and wire[0] == server:
            server, tool = wire
        original_spec = _lookup_spec(server, tool)
        if original_spec is None:
            return self.deny(cmd, "unknown server or tool")
        if server in A2A_PEERS and cmd.kind != "a2a":
            return self.deny(cmd, "peer calls must use A2A")
        if server not in A2A_PEERS and cmd.kind == "a2a":
            return self.deny(cmd, "A2A cannot target an MCP server")
        if fields and fields != ("*",) and not set(fields) <= set(original_spec.all_fields):
            return self.deny(cmd, "unknown response field")

        # ROUTE: deprecation and authoritative freshness, never body hints.
        if original_spec.deprecated:
            server, tool = original_spec.successor.split(".", 1)
            if fields and fields != ("*",):
                translated = {"body" if f == "snippet" else f for f in fields if f != "anchor"}
                fields = tuple(sorted(translated)) or _lookup_spec(server, tool).default_fields
        spec = _lookup_spec(server, tool)
        # The action grammar parses key=value arguments as strings, whereas
        # these real handlers require a positive integer limit.
        if "limit" in args and (server, tool) in {
            ("slides", "query"), ("slides", "list_sections"),
            ("glossary", "list_terms"), ("research", "search"), ("labs", "list_tasks"),
        }:
            limit = args["limit"]
            if isinstance(limit, str) and limit.isascii() and limit.isdecimal() and len(limit) <= 9:
                limit = int(limit)
            if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
                return self.deny(cmd, "tool limit must be a positive integer")
            args["limit"] = limit
        replica = headers.get("mcp-replica")
        if replica is not None and replica not in ("w", "c"):
            return self.deny(cmd, "invalid replica header")
        key = self._anchor_key(args.get("anchor"))
        provenance = self._provenance.get(key, {})
        rnd = getattr(self.ctx, "round", None)
        if not isinstance(rnd, int) or isinstance(rnd, bool) or not 0 <= rnd <= 10:
            return self.deny(cmd, "invalid round context")
        self._command_rounds[cmd.cmd_id] = rnd
        fresh_signal = provenance.get("preferred_replica") if provenance.get("round") == rnd else None
        if fresh_signal:
            replica = fresh_signal
        elif isinstance(args.get("anchor"), str) and "/" in args["anchor"]:
            # A revision-qualified anchor addresses a specific page. Keep its
            # route consistent rather than silently redirecting the request.
            revision = args["anchor"].split("/", 2)[1].split("#", 1)[0]
            if revision in ("w", "c"):
                replica = revision
            else:
                replica = pick_replica(path_id=args.get("anchor"), known_drifting=False).replica
        else:
            replica = pick_replica(path_id=args.get("anchor"), known_drifting=False).replica
        headers["mcp-replica"] = replica
        if "x-mcp-body-route" in headers:
            return self.deny(cmd, "untrusted body-route header")

        # ADMIT: a caller-provided verified flag never creates a registry entry.
        card = self._cards.get(server)
        signature_claim = headers.get("x-card-signature")
        if signature_claim is not None and (not card or not card.get("signature") or signature_claim != card["signature"]):
            return self.deny(cmd, "card signature is not registry-vouched")
        fingerprint = headers.get("x-server-fingerprint")
        if fingerprint is not None and (not card or not card.get("fingerprint") or fingerprint != card["fingerprint"]):
            return self.deny(cmd, "server fingerprint is not registry-vouched")
        if spec.needs_lease:
            live = getattr(self.ctx, "leases", ())
            if not isinstance(cmd.lease_id, str) or not isinstance(live, (tuple, list, set, frozenset)) or cmd.lease_id not in live:
                return self.deny(cmd, "frame read requires a live arena lease")
        token = headers.get("delegation", headers.get("delegation-token", args.get("delegation")))
        token_id = None
        if server in A2A_PEERS:
            supplied_card = headers.get("agent-card", headers.get("card", args.get("card")))
            if supplied_card is not None:
                supplied = verify_card(supplied_card)
                if not supplied.admitted or supplied.peer != server:
                    return self.deny(cmd, "wire card is not registry-vouched")
                card = {"skills": supplied.declared_skills, "legacy": False}
            if not card and token is not None:
                verified = verify_card(AGENT_CARDS[server])
                if verified.admitted:
                    card = {"skills": verified.declared_skills, "legacy": False}
            if not card:
                return self.deny(cmd, "peer card has not been vouched for by the registry")
            declared = card["skills"]
            if cmd.tool not in declared and not any(SKILL_ROUTES.get(skill) == (server, tool) for skill in declared):
                return self.deny(cmd, "peer does not declare the requested skill")
            aud = headers.get("aud")
            if aud is not None and aud not in (server, "a2a:" + server):
                return self.deny(cmd, "delegation audience differs from the called peer")
            if token is None:
                if not card.get("legacy") or aud is None:
                    return self.deny(cmd, "signed delegation is required")
            else:
                if isinstance(token, str):
                    if len(token) > 8192:
                        return self.deny(cmd, "oversized delegation")
                    token = json.loads(token)
                admitted = verify_delegation(token, aud="a2a:" + server, call_index=cmd.call_index,
                                               expected_act=getattr(self.ctx, "act", ""), seen_token_ids=self._tokens)
                if not admitted.admitted:
                    return self.deny(cmd, "delegation rejected: " + str(admitted.reason.value))
                data = self._mapping(token)
                if cmd.call_index < data.get("minted_at_call_index", 0):
                    return self.deny(cmd, "delegation issued in the future")
                token_id = data.get("token_id")
        elif "aud" in headers and headers["aud"] not in (server, "mcp:" + server):
            return self.deny(cmd, "audience differs from the called server")

        # AUTHORIZE: ctx.act owns learner targets; sub never grants authority.
        act = self._learner(getattr(self.ctx, "act", None))
        if act is None:
            return self.deny(cmd, "invalid authenticated learner identity")
        scopes = getattr(self.ctx, "scopes", ())
        if not isinstance(scopes, (tuple, list, set, frozenset)) or not all(isinstance(x, str) for x in scopes):
            return self.deny(cmd, "invalid scope context")
        required_scope = "wiki.write:" + server if spec.is_write else "wiki.read"
        if required_scope not in scopes:
            return self.deny(cmd, "missing scope: " + required_scope)
        for field in ("learner", "learner_id", "target", "subject", "act"):
            if field in args:
                target = args[field]
                # Generic target/subject can legitimately name content pages.
                if field in ("target", "subject") and isinstance(target, str) and ":" in target and not target.lower().startswith("learner:"):
                    continue
                if self._learner(target) != act:
                    return self.deny(cmd, "target learner is outside authenticated act")
        if "act" in headers and self._learner(headers["act"]) != act:
            return self.deny(cmd, "header act is outside authenticated authority")
        anchor = args.get("anchor")
        if isinstance(anchor, str) and anchor.lower().startswith("learner:") and self._learner(anchor) != act:
            return self.deny(cmd, "learner anchor is outside authenticated act")
        if server == "progress" and spec.is_write:
            owner = self._learner(anchor or args.get("learner"))
            if owner != act:
                return self.deny(cmd, "mastery write needs the authenticated learner target")
            args["anchor"] = "Learner:" + act.split(":", 1)[1]
            key = act
        if spec.is_write:
            if not key:
                return self.deny(cmd, "write requires a target anchor")
            etag, idem = headers.get("if-match"), headers.get("idempotency-key")
            if not isinstance(etag, str) or not etag or not isinstance(idem, str) or not idem.strip():
                return self.deny(cmd, "write requires If-Match and Idempotency-Key")
            p = self._provenance.get(key)
            previous = self._write_attempts.get(key, (-1, -1))
            if not p or p["round"] != rnd or p["etag"] != etag or (p["round"], p["call_index"]) <= previous:
                return self.deny(cmd, "write needs fresh successful registry provenance")
            if not 0 <= cmd.call_index - p["call_index"] <= 1:
                return self.deny(cmd, "provenance must immediately precede the write")
            if idem in self._idempotency or self._conflicts.get(key) == etag:
                return self.deny(cmd, "write replay or unchanged conflict precondition")

        # BUDGET: price real ToolSpec fields, bound rows, pace the global pool.
        if (server, tool) == ("registry", "list_servers") and fields in ((), ("*",), spec.all_fields):
            fields = ("name",)
        elif (server, tool) == ("glossary", "list_terms") and fields in ((), ("*",), spec.all_fields):
            fields = ("term",)
        elif fields == ("*",):
            fields = spec.default_fields or tuple(f for f in spec.all_fields if spec.field_weight[f] == 0)
        credits = getattr(self.ctx, "credits", None)
        if not isinstance(credits, int) or isinstance(credits, bool) or credits < 0:
            return self.deny(cmd, "invalid credit context")
        if self._last_credits is not None and credits < self._last_credits:
            self._pending = max(0, self._pending - (self._last_credits - credits))
        self._last_credits = credits
        available = max(0, credits - self._pending)
        spent = self._round_spend.get(rnd, 0)
        # Recover this round's starting pool before dividing across rounds.
        allowance = min(11, (available + spent) // max(1, 11 - max(1, rnd)))
        remaining = min(available, max(0, allowance - spent))
        if spec.rate_limit:
            cap, window = spec.rate_limit
            if sum(r >= rnd - window + 1 for r in self._rates.get((server, tool), ())) >= cap:
                return self.deny(cmd, "tool rate window exhausted")
        effective = fields or spec.default_fields
        # Before refusing an expensive call, preserve a useful subset of the
        # requested response. Zero fields means default, so never accidentally
        # return an empty narrowed mask that would restore an expensive dump.
        minimum_rows = 1 if spec.row_weight else 0
        field_budget = remaining - spec.base - minimum_rows * spec.row_weight
        if sum(spec.field_weight[f] for f in effective) > field_budget:
            selected = []
            for f in sorted(effective, key=lambda f: (spec.field_weight[f], f not in spec.default_fields, f)):
                if spec.field_weight[f] <= field_budget:
                    selected.append(f)
                    field_budget -= spec.field_weight[f]
            if not selected and effective:
                return self.deny(cmd, "no useful requested response fits the allowance")
            fields = cheap_mask(server, tool, tuple(selected)) if (server, tool) in TOOL_SPECS else tuple(sorted(selected))
        if spec.row_weight:
            limit = args.get("limit", 5)
            if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
                return self.deny(cmd, "query limit must be a positive integer")
            fixed = spec.base + sum(spec.field_weight[f] for f in (fields or spec.default_fields))
            max_rows = min(3, (remaining - fixed) // spec.row_weight)
            if max_rows < 1:
                return self.deny(cmd, "query cannot fit remaining round allowance")
            args["limit"] = min(limit, max_rows)
            rows = args["limit"]
        else:
            rows = 1
        call = ToolCall(server=server, tool=tool, args=args, fields=fields, headers=headers,
                        lease_id=cmd.lease_id, call_index=cmd.call_index)
        # Nine legitimate server extensions share ToolSpec's schema but are not
        # in specs.TOOL_SPECS; use their real prices, never invent a fallback.
        effective = fields or spec.default_fields
        estimate = spec.base + sum(spec.field_weight[f] for f in effective) + rows * spec.row_weight
        if estimate > remaining:
            return self.deny(cmd, "call exceeds remaining credits or round allowance")
        original = self._to_tool_call(cmd)
        verdict = "forward" if call == original else "rewrite"
        decision = Decision(verdict=verdict, call=call)
        self._round_spend[rnd] = spent + estimate
        self._pending += estimate
        self._credits_authorised += estimate
        self._reservations[(rnd, cmd.cmd_id)] = estimate
        if spec.rate_limit:
            self._rates.setdefault((server, tool), []).append(rnd)
        if spec.is_write:
            self._idempotency.add(headers["idempotency-key"])
            self._write_attempts[key] = (rnd, cmd.call_index)
        if token_id:
            self._tokens.add(token_id)
        self._emit("decision_made", cmd, decision)
        return decision

    def _to_tool_call(self, cmd: Command) -> "ToolCall":
        fields = dict(server=cmd.server, tool=cmd.tool, args=dict(cmd.args), fields=cmd.fields,
                      headers=dict(cmd.headers), lease_id=cmd.lease_id, call_index=cmd.call_index)
        return ToolCall(**fields) if _TOOLCALL_AVAILABLE else fields


if __name__ == "__main__":
    print("=== agent.gateway: Command / Decision validation ===\n")

    good_cmd = Command(
        cmd_id="cmd:0000",
        kind="mcp",
        raw="MCP slides.get_frame anchor=Frame:3f2a9c11/w/041 fields=title,body lease=lse_7f21",
        server="slides",
        tool="get_frame",
        args={"anchor": "Frame:3f2a9c11/w/041"},
        fields=("body", "title"),
        headers={},
        lease_id="lse_7f21",
        call_index=0,
    )
    print(f"  Command constructed: {good_cmd}")
    assert good_cmd.kind == "mcp"

    print("\n  Rejection demo (each must raise ValueError):")

    def _expect_value_error(label: str, fn) -> None:
        try:
            fn()
        except ValueError as exc:
            print(f"    [{label:38}] -> ValueError: {exc}")
        else:
            raise AssertionError(f"expected ValueError for case {label!r}")

    _expect_value_error("Command.kind == 'answer'", lambda: Command(
        cmd_id="cmd:0001", kind="answer", raw="x", server="slides", tool="get_frame",
        args={}, fields=(), headers={}, lease_id=None, call_index=0,
    ))
    _expect_value_error("Decision verdict='deny' with no reason", lambda: Decision(verdict="deny"))
    _expect_value_error(
        "Decision verdict='forward' with no call", lambda: Decision(verdict="forward")
    )
    _expect_value_error(
        "Decision verdict='deny' carrying a call",
        lambda: Decision(verdict="deny", reason="nope", call={"server": "x", "tool": "y"}),
    )
    _expect_value_error("Decision verdict='?' unknown", lambda: Decision(verdict="???"))

    print("\n=== Command.from_action_dict — real canonicaliser integration ===\n")
    if _canonicalise_action is None:
        print("  kit.loop.agent not importable yet — skipping the live canonicaliser demo")
        demo_commands: list[Command] = [good_cmd]
    else:
        raw_actions = [
            "MCP registry.provenance anchor=Frame:3f2a9c11/w/041 fields=etag",
            'MCP slides.query q="streamable http replaces http+sse" fields=title,body',
            "A2A curriculum-analyst.which_days_cover concept=Concept:streamable-http fields=anchor,course_day,track",
            "DISCOVER registry.list_servers fields=name",
        ]
        demo_commands = []
        for i, raw in enumerate(raw_actions):
            action = _canonicalise_action(raw, call_index=i)
            cmd = Command.from_action_dict(action, cmd_id=f"cmd:{i:04d}")
            print(f"  {raw!r}\n    -> {cmd.kind}: {cmd.server}.{cmd.tool} fields={cmd.fields}")
            demo_commands.append(cmd)
        assert {c.kind for c in demo_commands} == {"mcp", "a2a", "discover"}

        answer_action = _canonicalise_action(
            'ANSWER {"text": "day 26, track P2T2"}', call_index=None
        )
        try:
            Command.from_action_dict(answer_action, cmd_id="cmd:9999")
        except ValueError as exc:
            print(f"\n  an 'answer' action correctly refuses to become a Command: {exc}")
        else:
            raise AssertionError("expected ValueError for an 'answer' action")

    print("\n=== Gateway.decide — route, admit, authorize, and budget ===\n")
    ctx = RecordingGatewayContext(
        act="learner:sv-0401",
        sub="agent:demo-team",
        scopes=frozenset({"wiki.read"}),
        credits=100,
        round=1,
        call_index=0,
        leases=(),
        history=(),
    )
    assert isinstance(ctx, GatewayContext), "RecordingGatewayContext must structurally satisfy GatewayContext"
    gw = Gateway(ctx)
    for cmd in demo_commands:
        decision = gw.decide(cmd)
        print(f"  decide({cmd.server}.{cmd.tool}) -> verdict={decision.verdict!r} quarantine={decision.quarantine}")
        assert decision.verdict in {"forward", "rewrite", "deny"}
        if decision.verdict == "deny":
            assert decision.reason and decision.call is None
            continue
        assert decision.call is not None
        call_dict = decision.call.to_dict() if hasattr(decision.call, "to_dict") else decision.call
        assert call_dict["server"] == cmd.server
        assert call_dict["tool"] == cmd.tool
        assert tuple(call_dict["fields"]) == cmd.fields

    print(f"\n=== Gateway.deny — free abstention ===\n")
    denial = gw.deny(demo_commands[0], reason="demo: withholding pending a fresher registry.provenance read")
    print(f"  gw.deny(...) -> verdict={denial.verdict!r} reason={denial.reason!r} call={denial.call!r}")
    assert denial.verdict == "deny"
    assert denial.call is None
    assert demo_commands[0].cmd_id in gw._denied_cmd_ids

    print(f"\n=== own_telemetry — recorded on YOUR side only, never shown to the opponent ===\n")
    print(f"  {len(ctx.events)} events recorded on this ctx this run:")
    for ev in ctx.events:
        print(f"    {ev['name']}: {sorted(ev['payload'].keys())}")
    assert len(ctx.events) >= len(demo_commands) * 2 + 1  # decision_seen + decision_made per call, plus the deny

    print("\nAll agent/gateway.py demos passed.")
