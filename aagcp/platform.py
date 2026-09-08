"""
aagcp/platform.py — the product shell. Deliberately outside core/.

core/ is stdlib-only and has no I/O. This file has both, which is why it
lives here: config parsing, a driver, credentials. Nothing in core imports
it.

CREDENTIALS. This reads a password from config only when there is no other
option, and it never logs one. The `to_dict()` on every config object
redacts, and there is a test asserting the password does not survive
serialisation. If you are wiring this to a real account, use key-pair auth
(`private_key_path`) rather than a password in a file — a YAML on a laptop
is not a secret store, and a password in a config is a password in every
backup of that laptop.

ROLE. The connection refuses ACCOUNTADMIN by default. A governance control
plane whose executor holds the account's most privileged role has a blast
radius of the whole account, and — more practically — makes half of this
system untestable: every executor path that produces PARTIALLY_APPLIED,
orphan policy objects or PRESTATE_NOT_CAPTURED comes from a missing grant,
and under ACCOUNTADMIN none of them can ever fire. Set
`allow_privileged: true` if you really mean it.

YAML. PyYAML if it is installed, otherwise a strict loader for the flat
`key: value` subset that refuses anything it does not understand rather
than guessing. A parser that silently mis-reads a config is worse than one
that will not read it.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

PLATFORM_VERSION = "platform-1.0.0"

PRIVILEGED_ROLES = frozenset({"ACCOUNTADMIN", "SECURITYADMIN", "ORGADMIN"})
_REDACTED = "***redacted***"
_SECRET_KEYS = frozenset({"password", "private_key", "token", "secret",
                          "passphrase"})


class ConfigError(ValueError):
    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


# ---------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------

def _flat_yaml(text: str) -> Dict[str, Any]:
    """A strict reader for the flat two-level shape config files actually
    use. Anything else — anchors, multi-line scalars, nested sequences —
    raises rather than being half-understood."""
    out: Dict[str, Any] = {}
    section: Optional[str] = None
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if indent not in (0, 2):
            raise ConfigError("CONFIG_NOT_UNDERSTOOD",
                              f"line {n}: indentation {indent} is outside the "
                              f"flat subset this loader accepts; install "
                              f"PyYAML for the full grammar")
        if ":" not in line:
            raise ConfigError("CONFIG_NOT_UNDERSTOOD",
                              f"line {n}: no key, and list items are not "
                              f"supported by the fallback loader")
        key, _, value = line.strip().partition(":")
        key, value = key.strip(), value.strip()
        if not value:
            section, out[key] = key, {}
            continue
        parsed: Any = value.strip("'\"")
        if parsed.lower() in ("true", "false"):
            parsed = parsed.lower() == "true"
        elif parsed.isdigit():
            parsed = int(parsed)
        if indent == 2 and section:
            out[section][key] = parsed
        else:
            section, out[key] = None, parsed
    return out


def load_config(path: str) -> Dict[str, Any]:
    text = Path(path).read_text()
    if path.endswith(".json"):
        return json.loads(text)
    try:
        import yaml
        return yaml.safe_load(text) or {}
    except ImportError:
        return _flat_yaml(text)


# ---------------------------------------------------------------------
# Platform config
# ---------------------------------------------------------------------

@dataclass
class SnowflakeConfig:
    account: str
    user: str
    warehouse: str
    database: str
    schema: str
    role: str
    password: str = ""
    private_key_path: str = ""
    allow_privileged: bool = False
    query_tag: str = "aagcp"

    @classmethod
    def from_mapping(cls, m: Dict[str, Any]) -> "SnowflakeConfig":
        p = dict(m)
        p.pop("type", None)
        # Environment beats file, so a deployment can keep the secret out
        # of the config entirely.
        p["password"] = os.environ.get("AAGCP_SNOWFLAKE_PASSWORD",
                                       p.get("password", ""))
        missing = [k for k in ("account", "user", "warehouse", "database",
                               "schema", "role") if not p.get(k)]
        if missing:
            raise ConfigError("CONFIG_INCOMPLETE",
                              f"missing: {', '.join(missing)}")
        unknown = set(p) - {f for f in cls.__dataclass_fields__}
        if unknown:
            raise ConfigError("CONFIG_NOT_UNDERSTOOD",
                              f"unknown keys: {', '.join(sorted(unknown))}; "
                              f"refusing rather than ignoring them")
        return cls(**p)

    def check_role(self) -> List[dict]:
        if self.role.upper() in PRIVILEGED_ROLES and not self.allow_privileged:
            return [{
                "cause": "PRIVILEGED_ROLE_REFUSED",
                "detail": f"{self.role} can act on the entire account. Every "
                          f"permission-failure path in this system — "
                          f"PARTIALLY_APPLIED, orphan policy objects, "
                          f"PRESTATE_NOT_CAPTURED — becomes unreachable under "
                          f"it, so a demo that passes proves less than one "
                          f"that runs as a scoped role. Create a role with "
                          f"grants on {self.database}.{self.schema} only, or "
                          f"set allow_privileged: true"}]
        return []

    def to_dict(self) -> dict:
        return {k: (_REDACTED if k in _SECRET_KEYS and v else v)
                for k, v in self.__dict__.items()}


# ---------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------

class SnowflakeConnection:
    """Satisfies the executors' Connection protocol against the real
    driver. The driver is imported lazily so core/ and every offline test
    keep working without it installed.

    CONFIDENCE: the executors are proven against MockEngine. This adapter
    is written to snowflake-connector-python's documented cursor API and
    has NOT been run against a live account — there was no network egress
    in the environment it was written in. Treat the first live run as the
    test it has not had.
    """

    def __init__(self, cfg: SnowflakeConfig, connect=None):
        problems = cfg.check_role()
        if problems:
            raise ConfigError(problems[0]["cause"], problems[0]["detail"])
        self.cfg = cfg
        self._connect = connect
        self._conn = None

    def connect(self):
        if self._conn is not None:
            return self._conn
        if self._connect is not None:
            self._conn = self._connect(**self._params())
            return self._conn
        try:
            import snowflake.connector as sc
        except ImportError as exc:
            raise ConfigError(
                "DRIVER_NOT_INSTALLED",
                f"snowflake-connector-python is required for a live "
                f"connection ({exc}). pip install snowflake-connector-python"
            ) from exc
        self._conn = sc.connect(**self._params())
        return self._conn

    def _params(self) -> dict:
        p = {"account": self.cfg.account, "user": self.cfg.user,
             "warehouse": self.cfg.warehouse, "database": self.cfg.database,
             "schema": self.cfg.schema, "role": self.cfg.role,
             "session_parameters": {"QUERY_TAG": self.cfg.query_tag}}
        if self.cfg.private_key_path:
            p["private_key_file"] = self.cfg.private_key_path
        elif self.cfg.password:
            p["password"] = self.cfg.password
        else:
            raise ConfigError("NO_CREDENTIAL",
                              "neither private_key_path nor password is set")
        return p

    def cursor(self):
        return _WrappedCursor(self.connect().cursor())

    def close(self):
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __repr__(self):
        return f"SnowflakeConnection({self.cfg.account}/{self.cfg.role})"


class _WrappedCursor:
    """Translates driver errors into the executors' two-way distinction.

    This is the whole point of the wrapper and the thing most likely to be
    wrong on first contact: an error the driver raises for a rejected
    statement must become StatementError, and one raised because the
    connection went away must become TransportError. Collapsing them would
    turn every dropped connection into a definite failure, and the
    executor's UNKNOWN state — the one that stops a run being called
    complete — would never occur.
    """

    _TRANSPORT_MARKERS = ("OperationalError", "InterfaceError",
                          "DatabaseError.*connection", "timeout",
                          "connection is closed", "reset by peer")

    def __init__(self, cur):
        self._cur = cur

    def execute(self, sql: str) -> None:
        from .core.executors.base import StatementError, TransportError
        try:
            self._cur.execute(sql)
        except Exception as exc:
            name = type(exc).__name__
            text = f"{name}: {exc}".lower()
            if (name in ("OperationalError", "InterfaceError")
                    or any(m in text for m in ("timeout", "connection",
                                               "reset by peer", "eof"))):
                raise TransportError(f"{name}: {exc}") from exc
            raise StatementError(f"{name}: {exc}") from exc

    def fetchall(self):
        from .core.executors.base import StatementError, TransportError
        try:
            return list(self._cur.fetchall())
        except Exception as exc:
            name = type(exc).__name__
            if name in ("OperationalError", "InterfaceError"):
                raise TransportError(f"{name}: {exc}") from exc
            raise StatementError(f"{name}: {exc}") from exc


def snowflake_from_config(path: str, connect=None) -> SnowflakeConnection:
    cfg = load_config(path)
    platform = cfg.get("platform", cfg)
    if platform.get("type", "snowflake") != "snowflake":
        raise ConfigError("UNSUPPORTED_PLATFORM",
                          f"{platform.get('type')} has no executor")
    return SnowflakeConnection(SnowflakeConfig.from_mapping(platform),
                               connect=connect)
