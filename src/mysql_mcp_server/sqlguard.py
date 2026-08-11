"""Statement classification for the read/write tool split.

**This is not the security boundary.** The boundary is MySQL: the read tools
connect as a user holding only ``SELECT``, so a statement that slips past this
classifier is refused by the server itself. Treating a hand-written SQL
classifier as a boundary is how these things fail — there is always one more
syntax nobody thought of.

What this module is *for*: rejecting a write attempt on the read path with a
clear, immediate error instead of an opaque ``ERROR 1142 (access denied)``, and
catching the cases that a read-only DB user does not (``SELECT LOAD_FILE(...)``
reads the filesystem, ``SELECT ... FOR UPDATE`` takes write locks, and
``SELECT SLEEP(...)`` burns a connection — all of which a SELECT-only grant
happily permits).

The classification runs on a *noise-stripped* copy of the statement: comments
and string literals are removed first, so ``/*x*/DROP TABLE t`` and
``SELECT 'DROP TABLE t'`` are both handled correctly — the first is a write,
the second is a read whose payload happens to contain keywords.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class Kind(str, Enum):
    READ = "read"
    WRITE = "write"


# MySQL error numbers that mean "the server refused on policy grounds", as
# opposed to "your SQL is wrong" or "the connection broke". Matching on errno
# rather than message text keeps this stable across MySQL versions, locales, and
# message rewording.
#
# A denial is a deliberate outcome, so the caller can be told plainly that it is
# not permitted and should not retry. Everything else is a real fault: generic
# message to the caller, full detail to the server log.
DENIAL_ERRNOS = frozenset(
    {
        1044,  # ER_DBACCESS_DENIED_ERROR      - no access to the database
        1045,  # ER_ACCESS_DENIED_ERROR        - bad credentials for this action
        1142,  # ER_TABLEACCESS_DENIED_ERROR   - e.g. DROP denied on a table
        1143,  # ER_COLUMNACCESS_DENIED_ERROR
        1227,  # ER_SPECIFIC_ACCESS_DENIED     - e.g. INTO OUTFILE needs FILE
        1290,  # ER_OPTION_PREVENTS_STATEMENT  - server started --read-only
        1370,  # ER_PROCACCESS_DENIED_ERROR
        1792,  # ER_CANT_EXECUTE_IN_READ_ONLY_TRANSACTION
    }
)

#: Shown to the caller for any denial. Deliberately says nothing about which
#: MySQL account is in use: the server's own message names the user and host
#: (``DROP command denied to user 'mcp_ro'@'localhost'``), which is information
#: an unauthorized caller should not be handed.
DENIAL_MESSAGE = (
    "This statement is not permitted. The read path connects with read-only "
    "privileges; use write_query with a token carrying the write scope if you "
    "intend to modify data."
)


class StatementDenied(Exception):
    """A statement was refused on policy grounds, not because of a fault.

    Raised rather than returned so the MCP layer marks the tool result
    ``isError: true``. A refusal returned as ordinary content reads to a model
    as "the call succeeded and here is the answer", and an agent may narrate the
    refusal text as though it were data. The distinction is the difference
    between an agent retrying sensibly and an agent reporting a denial as a
    result.
    """


def is_denial(exc: object) -> bool:
    """Whether a MySQL error represents a policy refusal rather than a fault."""
    errno = getattr(exc, "errno", None)
    return errno in DENIAL_ERRNOS


@dataclass(frozen=True)
class Verdict:
    kind: Kind
    #: ``None`` when the statement is allowed on the read path. Otherwise the
    #: reason to show the caller.
    refusal: str | None = None
    #: True when the classifier could not confidently place the statement and
    #: fell back to treating it as a write.
    uncertain: bool = False


# Statements that only read. `WITH` is deliberately absent: a CTE can end in
# INSERT/UPDATE/DELETE, so it is resolved by scanning for write keywords.
_READ_HEADS = frozenset(
    {"SELECT", "SHOW", "DESCRIBE", "DESC", "EXPLAIN", "ANALYZE", "TABLE", "VALUES", "HELP"}
)

# Anything that writes data, changes schema, alters server or session state, or
# runs code whose effects cannot be seen from the call site.
_WRITE_HEADS = frozenset(
    {
        "INSERT", "UPDATE", "DELETE", "REPLACE", "TRUNCATE", "MERGE",
        "CREATE", "DROP", "ALTER", "RENAME",
        "GRANT", "REVOKE",
        "SET", "RESET", "FLUSH", "KILL", "SHUTDOWN",
        "LOAD", "LOCK", "UNLOCK", "HANDLER",
        "CALL", "DO", "PREPARE", "EXECUTE", "DEALLOCATE",
        "START", "BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT", "RELEASE",
        "OPTIMIZE", "REPAIR", "CHECKSUM", "IMPORT", "INSTALL", "UNINSTALL",
        "CHANGE", "PURGE", "BINLOG", "CACHE", "ALTERUSER",
    }
)

# Write keywords that make a CTE or subquery-led statement a write.
_WRITE_TOKENS = frozenset(
    {"INSERT", "UPDATE", "DELETE", "REPLACE", "MERGE", "TRUNCATE", "DROP", "ALTER", "CREATE", "GRANT", "REVOKE"}
)

# Constructs refused on the read path even though a SELECT-only grant allows
# them. Each is a real capability, not a theoretical one:
_READ_PATH_REFUSALS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bINTO\s+OUTFILE\b"), "INTO OUTFILE writes a file on the database server"),
    (re.compile(r"\bINTO\s+DUMPFILE\b"), "INTO DUMPFILE writes a file on the database server"),
    (re.compile(r"\bLOAD_FILE\s*\("), "LOAD_FILE() reads a file from the database server"),
    (re.compile(r"\bLOAD\s+DATA\b"), "LOAD DATA reads a file and writes rows"),
    (re.compile(r"\bFOR\s+UPDATE\b"), "FOR UPDATE takes write locks"),
    (re.compile(r"\bLOCK\s+IN\s+SHARE\s+MODE\b"), "LOCK IN SHARE MODE takes locks"),
    (re.compile(r"\bFOR\s+SHARE\b"), "FOR SHARE takes locks"),
    (re.compile(r"\bSLEEP\s*\("), "SLEEP() holds the connection open"),
    (re.compile(r"\bBENCHMARK\s*\("), "BENCHMARK() burns server CPU"),
    (re.compile(r"\bGET_LOCK\s*\("), "GET_LOCK() acquires a named lock"),
    (re.compile(r"\bINTO\s+@"), "SELECT ... INTO assigns a session variable"),
)

_LEADING_TOKEN = re.compile(r"[A-Za-z_]+")


def strip_noise(sql: str) -> str:
    """Remove comments and string/identifier literals.

    Literals become empty strings rather than being deleted outright, so token
    boundaries survive: ``a'x'b`` does not collapse into ``ab``.

    Handles ``/* */``, ``--`` (which MySQL requires be followed by whitespace),
    ``#``, single and double quotes with both backslash and doubled-quote
    escapes, and backtick identifiers.
    """
    out: list[str] = []
    i = 0
    n = len(sql)
    while i < n:
        ch = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""

        if ch == "/" and nxt == "*":
            end = sql.find("*/", i + 2)
            inner_start = i + 2
            inner = sql[inner_start:] if end == -1 else sql[inner_start:end]
            i = n if end == -1 else end + 2
            if inner.startswith("!"):
                # `/*! ... */` is NOT a comment: MySQL parses and executes its
                # contents (optionally gated on a version number, as in
                # `/*!80000 ... */`). Stripping it would delete real SQL from the
                # text being classified -- `/*!DROP TABLE t*/ SELECT 1` would
                # look like a plain SELECT while MySQL still runs the DROP.
                # Keep the payload as code and drop only the `!` and version.
                payload = inner[1:]
                digits = 0
                while digits < len(payload) and payload[digits].isdigit():
                    digits += 1
                out.append(" " + payload[digits:] + " ")
                continue
            out.append(" ")
            continue
        if ch == "-" and nxt == "-" and (i + 2 >= n or sql[i + 2] in " \t\r\n"):
            end = sql.find("\n", i)
            i = n if end == -1 else end + 1
            out.append(" ")
            continue
        if ch == "#":
            end = sql.find("\n", i)
            i = n if end == -1 else end + 1
            out.append(" ")
            continue
        if ch in "'\"`":
            quote = ch
            i += 1
            while i < n:
                if sql[i] == "\\" and quote != "`":
                    i += 2
                    continue
                if sql[i] == quote:
                    if i + 1 < n and sql[i + 1] == quote:
                        i += 2
                        continue
                    i += 1
                    break
                i += 1
            out.append("''")
            continue

        out.append(ch)
        i += 1
    return "".join(out)


def split_statements(sql: str) -> list[str]:
    """Split on semicolons that are not inside a literal or comment.

    Used to detect stacked statements. Splitting the *stripped* text would lose
    the original offsets, so the noise-stripped copy is walked in parallel with
    the original.
    """
    stripped = strip_noise(sql)
    parts = [p.strip() for p in stripped.split(";")]
    return [p for p in parts if p]


def classify(sql: str, *, read_only: bool) -> Verdict:
    """Classify ``sql``.

    ``read_only`` selects the stricter rule set: constructs that reach the
    filesystem or take locks are refused there even though they parse as
    SELECTs and a SELECT-only grant permits them.
    """
    stripped = strip_noise(sql)
    normalised = re.sub(r"\s+", " ", stripped).strip()

    if not normalised:
        return Verdict(Kind.WRITE, "Statement is empty", uncertain=True)

    statements = split_statements(sql)
    if len(statements) > 1:
        # Stacked statements let a write ride along behind a read. The MySQL
        # client protocol rejects these unless CLIENT_MULTI_STATEMENTS was
        # negotiated, but relying on a connector default for a security
        # property is exactly the sort of assumption that changes silently.
        return Verdict(
            Kind.WRITE,
            f"Multiple statements are not allowed ({len(statements)} found); send one at a time",
            uncertain=False,
        )

    match = _LEADING_TOKEN.match(normalised)
    head = match.group(0).upper() if match else ""
    upper = normalised.upper()

    if head in _WRITE_HEADS:
        # On the read path the caller always gets a reason. A bare "refused" is
        # indistinguishable from a bug from the outside.
        return Verdict(Kind.WRITE, _write_refusal(head) if read_only else None)

    if head == "WITH":
        # A CTE is a read only if nothing after it writes.
        if any(re.search(rf"\b{tok}\b", upper) for tok in _WRITE_TOKENS):
            return Verdict(
                Kind.WRITE,
                "This CTE contains a write statement",
            )
        return _read_path_check(upper) if read_only else Verdict(Kind.READ)

    if head in _READ_HEADS or normalised.startswith("("):
        return _read_path_check(upper) if read_only else Verdict(Kind.READ)

    # Unrecognised leading keyword: treat as a write. Failing closed here means
    # a MySQL syntax this classifier has never seen is refused on the read path
    # rather than waved through.
    return Verdict(
        Kind.WRITE,
        f"Unrecognised statement type {head or '?'!r}; refused on the read path",
        uncertain=True,
    )


def _write_refusal(head: str) -> str:
    """Why a statement led by ``head`` cannot run on the read path."""
    specific = {
        "LOAD": "LOAD reads a file and writes rows",
        "SET": "SET changes server or session state",
        "CALL": "CALL runs a stored program whose effects are not visible here",
        "GRANT": "GRANT changes privileges",
        "REVOKE": "REVOKE changes privileges",
        "LOCK": "LOCK takes table locks",
        "FLUSH": "FLUSH changes server state",
        "KILL": "KILL terminates connections",
        "PREPARE": "PREPARE can stage a write for later execution",
        "EXECUTE": "EXECUTE runs a previously prepared statement",
    }
    if head in specific:
        return specific[head] + "; use write_query"
    return f"{head} modifies data or schema; use write_query"


def _read_path_check(upper: str) -> Verdict:
    for pattern, reason in _READ_PATH_REFUSALS:
        if pattern.search(upper):
            return Verdict(Kind.READ, reason)
    return Verdict(Kind.READ)
