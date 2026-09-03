"""Turning MySQL's own refusals into clean tool errors.

The read/write boundary is **MySQL's privilege system**, not this process. Read
traffic connects as an account holding only ``SELECT``, so a statement that
writes is refused by the server. Nothing here inspects SQL.

That is a deliberate reversal. An earlier version of this module classified
statements — parsing them on a comment- and literal-stripped copy to decide
"read" or "write" — and the read path relied on that verdict plus a
``START TRANSACTION READ ONLY``. Measured against MySQL 8.4, that combination
does not hold:

===================================  ==========================  =================
Statement                            READ ONLY txn, RW account   SELECT-only acct
===================================  ==========================  =================
``INSERT`` / ``UPDATE`` / ``DELETE``  refused (1792)              refused (1142)
``CREATE`` / ``DROP`` / ``ALTER``     **executed**                refused (1142)
``TRUNCATE`` / ``RENAME`` / index     **executed**                refused (1142)
``GRANT``                             refused (1044)              refused (1044)
``SELECT 1; DROP TABLE t``            **executed**                refused (1142)
===================================  ==========================  =================

DDL performs an implicit commit, which ends the read-only transaction before the
statement runs, so ``DROP TABLE`` went straight through. The fallback was never
a boundary; the classifier was carrying it alone, and a classifier is exactly
what should not be load-bearing — there is always one more syntax nobody thought
of.

So the read-only account became the whole mechanism and the classifier is gone.
Which connection a call gets is decided by the caller's scope in
``auth.policy.connection_for``; where no read-only account is configured that
routing has nothing to route to, and the server says so at startup.

What a ``SELECT``-only grant still permits was checked too:
``LOAD_FILE()`` returns ``NULL`` without the ``FILE`` privilege, ``INTO OUTFILE``
is refused (1227), and ``SELECT ... FOR UPDATE`` is refused (1142). ``SLEEP()``
and ``GET_LOCK()`` do run — resource consumption rather than a privilege
violation, and bounded by ``MYSQL_STATEMENT_TIMEOUT_MS`` and ``MYSQL_MAX_ROWS``
rather than by parsing.

What remains here is the translation layer: recognising a refusal *as* a refusal
so it reaches the caller as a policy answer instead of an opaque database fault.
"""

from __future__ import annotations

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
        1142,  # ER_TABLEACCESS_DENIED_ERROR   - e.g. DROP denied on a table
        1143,  # ER_COLUMNACCESS_DENIED_ERROR
        1227,  # ER_SPECIFIC_ACCESS_DENIED     - e.g. INTO OUTFILE needs FILE
        1290,  # ER_OPTION_PREVENTS_STATEMENT  - server started --read-only
        1370,  # ER_PROCACCESS_DENIED_ERROR
        1792,  # ER_CANT_EXECUTE_IN_READ_ONLY_TRANSACTION
    }
)

# Deliberately NOT in the set above:
#
#   1045  ER_ACCESS_DENIED_ERROR
#
# It reads like the others -- "Access denied for user" -- but MySQL raises it
# when *credentials* are rejected, which happens at connect time and has nothing
# to do with the statement. Treating it as a policy refusal turned a wrong
# ``MYSQL_PASSWORD`` into "this statement is not permitted, you need the write
# scope": an operator chasing an authorization problem that does not exist,
# while the real one -- a typo in a password -- is never mentioned. Found by
# running the server with a bad password. It now surfaces as the connection
# fault it is.


#: Refusal on the read-only connection: the caller's scope chose that account,
#: so naming the write scope is actionable.
DENIAL_MESSAGE = (
    "This statement is not permitted. It ran on a connection with read-only "
    "privileges, and the database refused it. A token carrying the write scope "
    "is required to modify data."
)

#: Refusal on the read-write connection. The same errnos arrive here whenever
#: the account this server connects as simply lacks a privilege -- and then
#: there is no scope to acquire and no read-only connection involved, so
#: DENIAL_MESSAGE would send the reader looking for an authorization problem
#: that does not exist. Neither message names the account or host; MySQL's own
#: text does, and that is not the caller's business.
DENIAL_MESSAGE_PRIVILEGE = (
    "This statement is not permitted. The database account this server connects "
    "as does not hold the privileges it requires, and MySQL refused it."
)


def denial_message(read_only: bool) -> str:
    """The refusal text for a denial that arrived on this connection."""
    return DENIAL_MESSAGE if read_only else DENIAL_MESSAGE_PRIVILEGE


#: ``1045 ER_ACCESS_DENIED_ERROR``: the server could not authenticate to MySQL
#: at all. Not a refusal of the statement -- see the note under DENIAL_ERRNOS --
#: but not something to hand back verbatim either: MySQL's text names the account
#: and the host it connected from, and a caller can do nothing with either. It is
#: the operator's problem, so the caller gets a pointer and the log gets the rest.
CONNECT_DENIED_ERRNO = 1045

CONNECT_DENIED_MESSAGE = (
    "The server could not authenticate to the database. This is a server "
    "configuration problem, not a problem with your request -- check the "
    "MySQL credentials in the server's environment. Details are in its log."
)


def is_connect_denial(exc: object) -> bool:
    """Whether the error is MySQL rejecting this server's own credentials."""
    return getattr(exc, "errno", None) == CONNECT_DENIED_ERRNO


class StatementDenied(Exception):
    """A statement was refused on policy grounds, not because of a fault.

    Raised rather than returned so the MCP layer marks the tool result
    ``isError: true``. A refusal returned as ordinary content reads to a model
    as "the call succeeded and here is the answer", and an agent may narrate the
    refusal text back to the user as though it were data.
    """


def is_denial(exc: object) -> bool:
    """Whether a MySQL error represents a policy refusal rather than a fault."""
    errno = getattr(exc, "errno", None)
    return errno in DENIAL_ERRNOS
