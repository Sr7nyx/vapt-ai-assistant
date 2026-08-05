"""Schema initialisation, including the row-level-security step.

init() runs on every boot and is the one piece of code that can take the service
down before it serves a request. It also decides whether RLS gets enabled, and
enabling RLS against a role that cannot bypass it would leave the application
reading zero rows from every table -- up, healthy, and apparently empty.

These tests drive init() against a fake cursor rather than a database, so the
decision logic is covered without needing Postgres.
"""
import ast
import os

import pytest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCE = os.path.join(BACKEND, "pg_store.py")


def _load_init():
    """Execute only SCHEMA_STATEMENTS, _touches_rls and init(), so the module's
    database imports are not needed."""
    tree = ast.parse(open(SOURCE).read())
    wanted = [
        n for n in tree.body
        if (isinstance(n, ast.FunctionDef) and n.name in ("init", "_touches_rls"))
        or (isinstance(n, ast.Assign)
            and any(getattr(t, "id", "") == "SCHEMA_STATEMENTS" for t in n.targets))
    ]
    ns = {}
    exec(compile(ast.Module(body=wanted, type_ignores=[]), "<init>", "exec"), ns)
    return ns


class FakeCursor:
    def __init__(self, role_row, fail_on=()):
        self.role_row = role_row
        self.fail_on = fail_on
        self.executed = []
        self._last = None

    def execute(self, sql, params=()):
        if "pg_roles" in sql:
            if self.role_row is RuntimeError:
                raise RuntimeError("permission denied for table pg_roles")
            self._last = self.role_row
            return
        for fragment in self.fail_on:
            if fragment in sql:
                raise RuntimeError(f'role "{fragment}" does not exist')
        self.executed.append(sql.strip().split("\n")[0])

    def fetchone(self):
        return self._last

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeConn:
    def __init__(self, cur):
        self._cur = cur
        self.rollbacks = 0

    def cursor(self):
        return self._cur

    def rollback(self):
        self.rollbacks += 1

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakePool:
    def __init__(self, conn):
        self._conn = conn
        self.closed = False

    def connection(self):
        return self._conn

    def open(self):
        pass


def run_init(role_row, fail_on=()):
    ns = _load_init()
    cur = FakeCursor(role_row, fail_on)
    conn = FakeConn(cur)
    ns["_pool"] = FakePool(conn)
    messages = []
    ns["print"] = lambda *a, **k: messages.append(" ".join(str(x) for x in a))
    ns["init"]()
    return cur, conn, messages


def rls_statements(cur):
    return [s for s in cur.executed if "ROW LEVEL SECURITY" in s]


def tables_created(cur):
    return [s for s in cur.executed if s.startswith("CREATE TABLE")]


class TestPrivilegedRole:
    ROLE = {"role_name": "postgres", "rolbypassrls": True, "rolsuper": False}

    def test_rows_are_read_by_name_not_position(self):
        """Regression: the pool uses row_factory=dict_row, so a row is a mapping.
        Indexing it positionally raised KeyError(0) and crashed startup."""
        cur, _, _ = run_init(self.ROLE)
        assert len(rls_statements(cur)) == 6

    def test_every_table_gets_rls(self):
        cur, _, _ = run_init(self.ROLE)
        for table in ("users", "projects", "findings", "llm_usage", "demo_runs", "finding_events"):
            assert any(table in s for s in rls_statements(cur)), f"{table} not protected"

    def test_a_superuser_also_qualifies(self):
        cur, _, _ = run_init({"role_name": "postgres", "rolbypassrls": False, "rolsuper": True})
        assert len(rls_statements(cur)) == 6


class TestUnprivilegedRole:
    ROLE = {"role_name": "app_user", "rolbypassrls": False, "rolsuper": False}

    def test_rls_is_not_enabled(self):
        """Enabling it here would leave every query returning nothing: the service
        would look healthy and report no data, which is worse than failing."""
        cur, _, _ = run_init(self.ROLE)
        assert rls_statements(cur) == []

    def test_the_schema_is_still_created(self):
        cur, _, _ = run_init(self.ROLE)
        assert tables_created(cur)

    def test_it_warns_exactly_once(self):
        cur, _, messages = run_init(self.ROLE)
        warnings = [m for m in messages if "WARNING" in m]
        assert len(warnings) == 1
        assert "app_user" in warnings[0]
        assert "BYPASSRLS" in warnings[0]


class TestDegradedEnvironments:
    def test_unreadable_pg_roles_does_not_stop_startup(self):
        cur, _, _ = run_init(RuntimeError)
        assert tables_created(cur)
        assert rls_statements(cur) == []

    def test_missing_supabase_roles_do_not_stop_startup(self):
        """anon and authenticated exist only on Supabase, so REVOKE fails on plain
        Postgres and in local development. That must not be fatal."""
        cur, conn, _ = run_init(
            {"role_name": "postgres", "rolbypassrls": True, "rolsuper": True},
            fail_on=("REVOKE",),
        )
        assert len(rls_statements(cur)) == 6
        assert conn.rollbacks > 0

    def test_a_real_schema_error_still_raises(self):
        """Tolerating REVOKE failures must not swallow a genuine schema problem."""
        with pytest.raises(RuntimeError):
            run_init(
                {"role_name": "postgres", "rolbypassrls": True, "rolsuper": True},
                fail_on=("CREATE TABLE",),
            )
