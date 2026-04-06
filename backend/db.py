"""SQLite persistence layer with repository pattern."""
import aiosqlite
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("redteam.db")

_db_path: str = ""
_db: Optional[aiosqlite.Connection] = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    target TEXT,
    params TEXT,
    result TEXT,
    progress INTEGER DEFAULT 0,
    current_step TEXT,
    error TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS job_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    level TEXT NOT NULL DEFAULT 'info',
    module TEXT,
    message TEXT NOT NULL,
    data TEXT,
    timestamp TEXT NOT NULL,
    FOREIGN KEY (job_id) REFERENCES jobs(id)
);

CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    job_id TEXT,
    target TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    phases TEXT,
    tools TEXT,
    results TEXT,
    ai_analysis TEXT,
    attack_tree TEXT,
    suggested_chains TEXT,
    recommended_modules TEXT,
    timeline TEXT,
    vault TEXT,
    progress INTEGER DEFAULT 0,
    created_at TEXT NOT NULL,
    finished_at TEXT,
    FOREIGN KEY (job_id) REFERENCES jobs(id)
);

CREATE TABLE IF NOT EXISTS credentials (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT,
    cred_type TEXT,
    username TEXT,
    value TEXT,
    source TEXT,
    target TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    source TEXT,
    detail TEXT,
    data TEXT,
    timestamp TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_job_logs_job ON job_logs(job_id);
CREATE INDEX IF NOT EXISTS idx_scans_job ON scans(job_id);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json(obj) -> str:
    if obj is None:
        return "null"
    return json.dumps(obj, default=str)


def _parse(s: Optional[str]) -> Any:
    if s is None or s == "null":
        return None
    try:
        return json.loads(s)
    except (json.JSONDecodeError, TypeError):
        return s


async def init(db_path: str):
    """Initialize database connection and create schema."""
    global _db_path, _db
    _db_path = db_path
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    _db = await aiosqlite.connect(db_path)
    _db.row_factory = aiosqlite.Row
    await _db.execute("PRAGMA journal_mode=WAL")
    await _db.execute("PRAGMA foreign_keys=ON")
    await _db.executescript(SCHEMA)
    await _db.commit()
    logger.info(f"Database initialized: {db_path}")


async def close():
    global _db
    if _db:
        await _db.close()
        _db = None


def _row_to_dict(row) -> Dict:
    if row is None:
        return None
    return dict(row)


# ─── Config Repository ──────────────────────────────────

async def config_get(key: str, default: Any = None) -> Any:
    row = await _db.execute_fetchall("SELECT value FROM config WHERE key=?", (key,))
    if row:
        return _parse(row[0][0])
    return default


async def config_set(key: str, value: Any):
    await _db.execute(
        "INSERT INTO config(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=?,updated_at=?",
        (key, _json(value), _now(), _json(value), _now())
    )
    await _db.commit()


async def config_get_all() -> Dict:
    rows = await _db.execute_fetchall("SELECT key, value FROM config")
    return {r[0]: _parse(r[1]) for r in rows}


# ─── Job Repository ─────────────────────────────────────

async def job_create(job_id: str, job_type: str, target: str = "", params: Dict = None) -> Dict:
    now = _now()
    await _db.execute(
        "INSERT INTO jobs(id,type,status,target,params,created_at) VALUES(?,?,?,?,?,?)",
        (job_id, job_type, "pending", target, _json(params), now)
    )
    await _db.commit()
    return {"id": job_id, "type": job_type, "status": "pending", "target": target, "created_at": now}


async def job_update(job_id: str, **kwargs):
    sets = []
    vals = []
    for k, v in kwargs.items():
        if k in ("result", "params"):
            v = _json(v)
        sets.append(f"{k}=?")
        vals.append(v)
    vals.append(job_id)
    await _db.execute(f"UPDATE jobs SET {','.join(sets)} WHERE id=?", vals)
    await _db.commit()


async def job_get(job_id: str) -> Optional[Dict]:
    rows = await _db.execute_fetchall("SELECT * FROM jobs WHERE id=?", (job_id,))
    if not rows:
        return None
    d = _row_to_dict(rows[0])
    d["params"] = _parse(d.get("params"))
    d["result"] = _parse(d.get("result"))
    return d


async def job_list(status: str = None, job_type: str = None, limit: int = 50) -> List[Dict]:
    q = "SELECT * FROM jobs WHERE 1=1"
    params = []
    if status:
        q += " AND status=?"
        params.append(status)
    if job_type:
        q += " AND type=?"
        params.append(job_type)
    q += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    rows = await _db.execute_fetchall(q, params)
    result = []
    for r in rows:
        d = _row_to_dict(r)
        d["params"] = _parse(d.get("params"))
        d["result"] = _parse(d.get("result"))
        result.append(d)
    return result


# ─── Job Log Repository ─────────────────────────────────

async def job_log(job_id: str, level: str, message: str, module: str = "", data: Dict = None):
    await _db.execute(
        "INSERT INTO job_logs(job_id,level,module,message,data,timestamp) VALUES(?,?,?,?,?,?)",
        (job_id, level, module, message, _json(data), _now())
    )
    await _db.commit()


async def job_logs_get(job_id: str, limit: int = 200) -> List[Dict]:
    rows = await _db.execute_fetchall(
        "SELECT * FROM job_logs WHERE job_id=? ORDER BY id DESC LIMIT ?", (job_id, limit)
    )
    result = []
    for r in rows:
        d = _row_to_dict(r)
        d["data"] = _parse(d.get("data"))
        result.append(d)
    return list(reversed(result))


# ─── Scan Repository ────────────────────────────────────

async def scan_create(scan_id: str, job_id: str, target: str, phases: List[str], tools: List[str]) -> Dict:
    now = _now()
    await _db.execute(
        "INSERT INTO scans(id,job_id,target,status,phases,tools,results,timeline,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
        (scan_id, job_id, target, "running", _json(phases), _json(tools), _json({}), _json([]), now)
    )
    await _db.commit()
    return {"id": scan_id, "job_id": job_id, "target": target, "status": "running"}


async def scan_update(scan_id: str, **kwargs):
    sets = []
    vals = []
    for k, v in kwargs.items():
        if k in ("results", "ai_analysis", "attack_tree", "suggested_chains",
                  "recommended_modules", "timeline", "vault", "phases", "tools"):
            v = _json(v)
        sets.append(f"{k}=?")
        vals.append(v)
    vals.append(scan_id)
    await _db.execute(f"UPDATE scans SET {','.join(sets)} WHERE id=?", vals)
    await _db.commit()


async def scan_get(scan_id: str) -> Optional[Dict]:
    rows = await _db.execute_fetchall("SELECT * FROM scans WHERE id=?", (scan_id,))
    if not rows:
        return None
    d = _row_to_dict(rows[0])
    for k in ("results", "ai_analysis", "attack_tree", "suggested_chains",
              "recommended_modules", "timeline", "vault", "phases", "tools"):
        d[k] = _parse(d.get(k))
    return d


async def scan_list(limit: int = 50) -> List[Dict]:
    rows = await _db.execute_fetchall(
        "SELECT id, job_id, target, status, progress, created_at, finished_at FROM scans ORDER BY created_at DESC LIMIT ?",
        (limit,)
    )
    return [_row_to_dict(r) for r in rows]


# ─── Credential Repository ──────────────────────────────

async def credential_add(scan_id: str, cred_type: str, username: str, value: str, source: str, target: str):
    await _db.execute(
        "INSERT INTO credentials(scan_id,cred_type,username,value,source,target,created_at) VALUES(?,?,?,?,?,?,?)",
        (scan_id, cred_type, username, value, source, target, _now())
    )
    await _db.commit()


async def credentials_by_scan(scan_id: str) -> List[Dict]:
    rows = await _db.execute_fetchall("SELECT * FROM credentials WHERE scan_id=?", (scan_id,))
    return [_row_to_dict(r) for r in rows]


# ─── Event Repository ───────────────────────────────────

async def event_add(event_type: str, source: str, detail: str, data: Dict = None):
    await _db.execute(
        "INSERT INTO events(event_type,source,detail,data,timestamp) VALUES(?,?,?,?,?)",
        (event_type, source, detail, _json(data), _now())
    )
    await _db.commit()


async def event_list(event_type: str = None, limit: int = 100) -> List[Dict]:
    if event_type:
        rows = await _db.execute_fetchall(
            "SELECT * FROM events WHERE event_type=? ORDER BY id DESC LIMIT ?", (event_type, limit)
        )
    else:
        rows = await _db.execute_fetchall("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,))
    result = []
    for r in rows:
        d = _row_to_dict(r)
        d["data"] = _parse(d.get("data"))
        result.append(d)
    return list(reversed(result))


# ─── Health ──────────────────────────────────────────────

async def is_healthy() -> bool:
    try:
        rows = await _db.execute_fetchall("SELECT 1")
        return bool(rows)
    except Exception:
        return False
