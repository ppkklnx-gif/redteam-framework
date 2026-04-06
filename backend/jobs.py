"""Generic job manager for all async operations."""
import asyncio
import logging
import uuid
import traceback
from datetime import datetime, timezone
from typing import Any, Callable, Coroutine, Dict, Optional

import db

logger = logging.getLogger("redteam.jobs")

# Active tasks keyed by job_id
_tasks: Dict[str, asyncio.Task] = {}


def new_id() -> str:
    return str(uuid.uuid4())[:12]


async def submit(
    job_type: str,
    handler: Callable[..., Coroutine],
    target: str = "",
    params: Dict = None,
    job_id: str = None,
) -> Dict:
    """Submit a job for async execution. Returns immediately with job_id."""
    jid = job_id or new_id()
    job = await db.job_create(jid, job_type, target, params)
    await db.job_log(jid, "info", f"Job created: {job_type}", module="jobs")

    async def _run():
        try:
            await db.job_update(jid, status="running", started_at=datetime.now(timezone.utc).isoformat())
            await db.job_log(jid, "info", "Job started", module="jobs")
            result = await handler(jid, target, params or {})
            await db.job_update(
                jid, status="completed", result=result, progress=100,
                finished_at=datetime.now(timezone.utc).isoformat()
            )
            await db.job_log(jid, "info", "Job completed", module="jobs")
        except asyncio.CancelledError:
            await db.job_update(jid, status="cancelled", finished_at=datetime.now(timezone.utc).isoformat())
            await db.job_log(jid, "warn", "Job cancelled", module="jobs")
        except Exception as e:
            tb = traceback.format_exc()
            await db.job_update(
                jid, status="error", error=str(e),
                finished_at=datetime.now(timezone.utc).isoformat()
            )
            await db.job_log(jid, "error", f"Job failed: {e}", module="jobs", data={"traceback": tb})
            logger.error(f"Job {jid} failed: {e}")
        finally:
            _tasks.pop(jid, None)

    task = asyncio.create_task(_run())
    _tasks[jid] = task
    return {"job_id": jid, "type": job_type, "status": "pending", "target": target}


async def cancel(job_id: str) -> bool:
    """Cancel a running job."""
    task = _tasks.get(job_id)
    if task and not task.done():
        task.cancel()
        await db.job_log(job_id, "warn", "Cancel requested", module="jobs")
        return True
    return False


async def get_status(job_id: str) -> Optional[Dict]:
    """Get job status with recent logs."""
    job = await db.job_get(job_id)
    if not job:
        return None
    logs = await db.job_logs_get(job_id, limit=50)
    job["logs"] = logs
    job["is_active"] = job_id in _tasks
    return job


async def list_active() -> list:
    """List currently running jobs."""
    return list(_tasks.keys())


async def cleanup():
    """Cancel all running tasks on shutdown."""
    for jid, task in list(_tasks.items()):
        if not task.done():
            task.cancel()
    _tasks.clear()
