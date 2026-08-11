"""Statement classification for the read/write split.

These are pure unit tests: no database, no network. They pin what the
classifier accepts and refuses, including the cases that a naive
"does it start with SELECT?" check gets wrong.

Remember what this layer is and is not. The classifier is *not* the security
boundary — `test_sql_boundary.py` covers the boundary, which is MySQL's own
privilege system. A gap here degrades error quality; a gap there is a
vulnerability.
"""

import pytest

from mysql_mcp_server.sqlguard import Kind, classify, split_statements, strip_noise


def refused(query: str) -> bool:
    """Whether the read path rejects this statement, for any reason."""
    verdict = classify(query, read_only=True)
    return verdict.kind is Kind.WRITE or verdict.refusal is not None


# --------------------------------------------------------------------------
# Reads that must keep working. A "secure" server that rejects legitimate
# queries has just broken itself, which is the usual way this kind of change
# fails in practice.
# --------------------------------------------------------------------------

ALLOWED_READS = [
    "SELECT * FROM demo",
    "select 1",
    "  \n  SELECT 1  ",
    "SELECT COUNT(*) FROM demo WHERE id > 1",
    "SHOW TABLES",
    "SHOW COLUMNS FROM demo",
    "DESCRIBE demo",
    "DESC demo",
    "EXPLAIN SELECT * FROM demo",
    "SELECT a.id FROM demo a JOIN demo b ON a.id = b.id",
    "SELECT * FROM (SELECT 1 AS x) t",
    "(SELECT 1)",
    "SELECT 1 UNION SELECT 2",
    "WITH x AS (SELECT 1 AS n) SELECT * FROM x",
    "SELECT ROW_NUMBER() OVER (ORDER BY id) FROM demo",
    "SELECT * FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE()",
    # A string literal that merely contains dangerous keywords is still a read.
    "SELECT 'DROP TABLE demo' AS harmless",
    "SELECT 'INTO OUTFILE' AS harmless",
    "SELECT \"; DROP TABLE demo\" AS harmless",
    # A semicolon inside a literal is not a statement separator.
    "SELECT ';' AS semi",
    # Trailing semicolon on a single statement is fine.
    "SELECT 1;",
]


@pytest.mark.parametrize("query", ALLOWED_READS)
def test_read_path_allows_legitimate_reads(query):
    verdict = classify(query, read_only=True)
    assert verdict.kind is Kind.READ, f"{query!r} should classify as a read"
    assert verdict.refusal is None, f"{query!r} was refused: {verdict.refusal}"


# --------------------------------------------------------------------------
# The bypass corpus. Every entry must be refused on the read path.
#
# The interesting ones are grouped last: they *begin with a read keyword*, so
# any classifier that looks only at the leading token lets them through.
# --------------------------------------------------------------------------

OBVIOUS_WRITES = [
    "INSERT INTO demo VALUES (3, 'c')",
    "UPDATE demo SET name = 'x'",
    "DELETE FROM demo",
    "REPLACE INTO demo VALUES (1, 'z')",
    "TRUNCATE demo",
    "TRUNCATE TABLE demo",
    "DROP TABLE demo",
    "DROP DATABASE testdb",
    "CREATE TABLE t2 (id INT)",
    "ALTER TABLE demo ADD COLUMN x INT",
    "RENAME TABLE demo TO demo2",
    "GRANT ALL ON *.* TO 'mcp'@'%'",
    "REVOKE SELECT ON testdb.* FROM 'mcp'@'%'",
    "SET GLOBAL max_connections = 1",
    "SET SESSION sql_mode = ''",
    "FLUSH TABLES",
    "FLUSH PRIVILEGES",
    "KILL 1",
    "SHUTDOWN",
    "CALL some_procedure()",
    "DO SLEEP(5)",
    "PREPARE stmt FROM 'DROP TABLE demo'",
    "EXECUTE stmt",
    "LOCK TABLES demo WRITE",
    "UNLOCK TABLES",
    "OPTIMIZE TABLE demo",
    "REPAIR TABLE demo",
    "START TRANSACTION",
    "COMMIT",
    "ROLLBACK",
    "INSTALL PLUGIN x SONAME 'x.so'",
]

COMMENT_AND_WHITESPACE_EVASION = [
    "/* comment */ DROP TABLE demo",
    "/* multi\nline */ DELETE FROM demo",
    "-- comment\nDROP TABLE demo",
    "# comment\nDROP TABLE demo",
    "\n\n\tDROP TABLE demo",
    "/*!DROP TABLE demo*/ SELECT 1",  # MySQL executes version-gated comments
    "  /*a*/ /*b*/  INSERT INTO demo VALUES (9, 'i')",
]

STACKED_STATEMENTS = [
    "SELECT 1; DROP TABLE demo",
    "SELECT 1;DROP TABLE demo",
    "SELECT 1 ; DELETE FROM demo",
    "SELECT 1; SELECT 2; DROP TABLE demo",
    "SELECT 1 /* c */; DROP TABLE demo",
]

# These start with SELECT or WITH. This block is the reason the classifier
# strips literals and scans the whole statement instead of checking a prefix.
LOOKS_LIKE_A_READ_BUT_IS_NOT = [
    "WITH x AS (SELECT 1) INSERT INTO demo SELECT 4, 'y'",
    "WITH x AS (SELECT 1) UPDATE demo SET name = 'q'",
    "WITH x AS (SELECT 1) DELETE FROM demo",
    "SELECT * FROM demo INTO OUTFILE '/tmp/leak.csv'",
    "SELECT * FROM demo INTO DUMPFILE '/tmp/leak.bin'",
    "SELECT LOAD_FILE('/etc/passwd')",
    "SELECT load_file('/etc/passwd')",
    "SELECT * FROM demo FOR UPDATE",
    "SELECT * FROM demo LOCK IN SHARE MODE",
    "SELECT * FROM demo FOR SHARE",
    "SELECT SLEEP(100)",
    "SELECT BENCHMARK(9999999, MD5('x'))",
    "SELECT GET_LOCK('x', 100)",
    "SELECT 1 INTO @v",
    "LOAD DATA LOCAL INFILE '/etc/passwd' INTO TABLE demo",
]

UNRECOGNISED = [
    "gibberish foo bar",
    "",
    "   ",
    "/* only a comment */",
    "42",
]


@pytest.mark.parametrize("query", OBVIOUS_WRITES)
def test_read_path_refuses_obvious_writes(query):
    assert refused(query), f"{query!r} must not be allowed on the read path"


@pytest.mark.parametrize("query", COMMENT_AND_WHITESPACE_EVASION)
def test_read_path_refuses_comment_prefixed_writes(query):
    """A write hidden behind a comment is still a write.

    A prefix check on the raw string sees `/*` and gives up, or worse, sees no
    write keyword at position zero and allows it.
    """
    assert refused(query), f"{query!r} must not be allowed on the read path"


@pytest.mark.parametrize("query", STACKED_STATEMENTS)
def test_read_path_refuses_stacked_statements(query):
    """Two statements in one string: the first is bait, the second is the payload."""
    assert refused(query), f"{query!r} must not be allowed on the read path"
    verdict = classify(query, read_only=True)
    assert "Multiple statements" in (verdict.refusal or ""), (
        "the refusal should name the actual problem so the caller can fix it"
    )


@pytest.mark.parametrize("query", LOOKS_LIKE_A_READ_BUT_IS_NOT)
def test_read_path_refuses_statements_that_open_with_a_read_keyword(query):
    """The cases a leading-keyword check gets wrong.

    Each of these begins with SELECT, WITH, or LOAD and would pass any check
    that only inspects the first token. Several are permitted by a SELECT-only
    MySQL grant too, which is why the classifier has to catch them.
    """
    assert refused(query), f"{query!r} must not be allowed on the read path"
    verdict = classify(query, read_only=True)
    assert verdict.refusal, "a refusal reason is required so the caller learns why"


@pytest.mark.parametrize("query", UNRECOGNISED)
def test_unrecognised_statements_fail_closed(query):
    """An unparseable or unknown statement is refused, not waved through.

    MySQL's grammar is large and this classifier does not implement it. Failing
    closed means a syntax nobody anticipated is rejected rather than allowed.
    """
    assert refused(query), f"{query!r} must fail closed"


def test_write_path_allows_writes():
    """The write tool is not subject to the read-path refusals."""
    assert classify("DROP TABLE demo", read_only=False).kind is Kind.WRITE
    assert classify("INSERT INTO demo VALUES (1, 'a')", read_only=False).kind is Kind.WRITE
    verdict = classify("SELECT 1", read_only=False)
    assert verdict.kind is Kind.READ and verdict.refusal is None


# --------------------------------------------------------------------------
# The noise stripper, tested directly. Every refusal above depends on it, so
# a bug here silently weakens all of them.
# --------------------------------------------------------------------------

def test_strip_noise_removes_comments():
    assert "DROP" in strip_noise("/* x */ DROP TABLE t")
    assert "SECRET" not in strip_noise("SELECT 1 /* SECRET */")
    assert "SECRET" not in strip_noise("SELECT 1 -- SECRET\n")
    assert "SECRET" not in strip_noise("SELECT 1 # SECRET\n")


def test_strip_noise_blanks_string_literals():
    """Literal contents must not be scanned for keywords."""
    assert "DROP" not in strip_noise("SELECT 'DROP TABLE t'")
    assert "DROP" not in strip_noise('SELECT "DROP TABLE t"')
    assert "DROP" not in strip_noise("SELECT `DROP` FROM t")


def test_strip_noise_handles_escapes_and_doubled_quotes():
    """A mishandled escape ends the literal early and exposes its contents."""
    assert "DROP" not in strip_noise(r"SELECT 'it\'s DROP TABLE t'")
    assert "DROP" not in strip_noise("SELECT 'it''s DROP TABLE t'")


def test_strip_noise_preserves_token_boundaries():
    """Literals collapse to '' rather than vanishing, so `a'x'b` stays two tokens."""
    assert strip_noise("a'x'b") == "a''b"


def test_strip_noise_survives_unterminated_literal():
    """An unterminated quote must not hang or throw."""
    assert isinstance(strip_noise("SELECT 'unterminated"), str)
    assert isinstance(strip_noise("SELECT /* unterminated"), str)


def test_split_statements_ignores_semicolons_in_literals_and_comments():
    assert len(split_statements("SELECT ';'")) == 1
    assert len(split_statements("SELECT 1 /* ; */")) == 1
    assert len(split_statements("SELECT 1; SELECT 2")) == 2
    assert len(split_statements("SELECT 1;")) == 1
