from __future__ import annotations

import json
import os
import shutil
import threading
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

from engine.logger import HistoryStore, JobLogger
from engine.packer import DEFAULT_FEATURES, PackOptions, Packer

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
UPLOAD_DIR = os.path.join(DATA_DIR, "uploads")
OUTPUT_DIR = os.path.join(DATA_DIR, "output")
LOG_DIR = os.path.join(DATA_DIR, "logs")
JOB_DIR = os.path.join(DATA_DIR, "jobs")

for d in (UPLOAD_DIR, OUTPUT_DIR, LOG_DIR, JOB_DIR):
    os.makedirs(d, exist_ok=True)

history = HistoryStore(os.path.join(DATA_DIR, "history.json"))

app = FastAPI(title="NXShield APK Hardening", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

JOBS: Dict[str, dict] = {}
JOB_LOCK = threading.Lock()
SUBSCRIBERS: Dict[str, List] = {}


class FeatureToggle(BaseModel):
    feature: str
    enabled: bool
    source: str = "ui"


class PackRequest(BaseModel):
    upload_id: str
    options: Optional[dict] = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _emit(job_id: str, record: dict) -> None:
    with JOB_LOCK:
        subs = list(SUBSCRIBERS.get(job_id, []))
    payload = json.dumps(record, ensure_ascii=False)
    for q in subs:
        try:
            q.append(payload)
        except Exception:
            pass


@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "service": "nxshield", "version": "1.0.0", "time": _now()}


@app.get("/api/features")
def features() -> dict:
    return {
        "defaults": DEFAULT_FEATURES,
        "options": {
            "extract_ratio": {"min": 0.0, "max": 1.0, "step": 0.05, "default": 0.45},
            "extra_keywords": {
                "hint": "逗号或换行分隔，内置已包含 vip / premium / 中文字符串",
            },
        },
    }


@app.post("/api/toggles")
def toggle_feature(req: FeatureToggle) -> dict:
    rec = history.add_toggle(req.feature, req.enabled, req.source)
    return {"ok": True, "record": rec}


@app.get("/api/toggles")
def list_toggles(limit: int = 200) -> dict:
    return {"items": history.list_toggles(limit)}


@app.post("/api/upload")
async def upload(file: UploadFile = File(...)) -> dict:
    upload_id = uuid.uuid4().hex
    safe_name = os.path.basename(file.filename or "input.apk")
    dest = os.path.join(UPLOAD_DIR, f"{upload_id}__{safe_name}")
    size = 0
    with open(dest, "wb") as f:
        while True:
            chunk = await file.read(1 << 20)
            if not chunk:
                break
            size += len(chunk)
            f.write(chunk)
    return {
        "ok": True,
        "upload_id": upload_id,
        "filename": safe_name,
        "size": size,
        "path": dest,
    }


def _run_pack(job_id: str, input_path: str, output_path: str, options: PackOptions) -> None:
    logger = JobLogger(LOG_DIR, job_id, on_line=lambda rec: _emit(job_id, rec))
    job = {
        "id": job_id,
        "input": os.path.basename(input_path),
        "input_path": input_path,
        "output_path": output_path,
        "status": "running",
        "progress": 0,
        "stage": "初始化",
        "created_at": _now(),
        "updated_at": _now(),
        "summary": None,
        "error": None,
        "options": options.__dict__,
    }
    with JOB_LOCK:
        JOBS[job_id] = job
    history.add_job(job)

    def progress(pct: int, stage: str, extra: dict) -> None:
        job["progress"] = pct
        job["stage"] = stage
        job["updated_at"] = _now()
        history.update_job(job_id, progress=pct, stage=stage, updated_at=job["updated_at"])

    try:
        logger.info("加固任务启动", input=job["input"], output=os.path.basename(output_path))
        packer = Packer(logger, progress)
        summary = packer.pack(input_path, output_path, options)
        job["status"] = "success"
        job["progress"] = 100
        job["stage"] = "完成"
        job["summary"] = summary
        job["updated_at"] = _now()
        history.update_job(
            job_id,
            status="success",
            progress=100,
            stage="完成",
            summary=summary,
            updated_at=job["updated_at"],
            output_path=output_path,
        )
        logger.info("加固成功", **{k: v for k, v in summary.items() if k in
                                    ("methods_extracted", "strings", "vm_functions",
                                     "assets_encrypted", "elapsed_ms")})
    except Exception as exc:
        job["status"] = "failed"
        job["stage"] = "失败"
        job["error"] = str(exc)
        job["updated_at"] = _now()
        history.update_job(
            job_id, status="failed", stage="失败", error=str(exc), updated_at=job["updated_at"]
        )
        logger.error("加固任务失败", error=str(exc))
    finally:
        _emit(job_id, {"ts": _now(), "level": "INFO", "message": "__job_closed__",
                       "status": job["status"], "job_id": job_id})


@app.post("/api/pack")
def start_pack(req: PackRequest) -> dict:
    dest = None
    for name in os.listdir(UPLOAD_DIR):
        if name.startswith(req.upload_id + "__"):
            dest = os.path.join(UPLOAD_DIR, name)
            break
    if not dest or not os.path.exists(dest):
        raise HTTPException(status_code=404, detail="upload not found")

    options = PackOptions.from_dict(req.options)
    job_id = uuid.uuid4().hex[:12]
    base = os.path.basename(dest).split("__", 1)[-1]
    stem = os.path.splitext(base)[0]
    output_path = os.path.join(OUTPUT_DIR, f"{stem}-nxshield-{job_id}.apk")

    t = threading.Thread(target=_run_pack, args=(job_id, dest, output_path, options), daemon=True)
    t.start()
    return {"ok": True, "job_id": job_id, "output": os.path.basename(output_path)}


@app.get("/api/jobs")
def list_jobs(limit: int = 100) -> dict:
    jobs = history.list_jobs(limit)
    for j in jobs:
        jid = j.get("id")
        if jid in JOBS:
            j["progress"] = JOBS[jid].get("progress", j.get("progress", 0))
            j["stage"] = JOBS[jid].get("stage", j.get("stage"))
            j["status"] = JOBS[jid].get("status", j.get("status"))
    return {"items": jobs}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str) -> dict:
    job = JOBS.get(job_id) or history.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    return job


@app.get("/api/jobs/{job_id}/log")
def get_job_log(job_id: str, tail: int = 0) -> dict:
    path = os.path.join(LOG_DIR, f"{job_id}.log")
    if not os.path.exists(path):
        return {"ok": True, "lines": [], "raw": ""}
    with open(path, "r", encoding="utf-8") as f:
        content = f.read()
    lines = [ln for ln in content.splitlines() if ln]
    if tail > 0:
        lines = lines[-tail:]
    return {"ok": True, "lines": lines, "raw": "\n".join(lines)}


@app.get("/api/jobs/{job_id}/stream")
def stream_job(job_id: str) -> StreamingResponse:
    queue: List[str] = []

    with JOB_LOCK:
        SUBSCRIBERS.setdefault(job_id, []).append(queue)
        job = JOBS.get(job_id)
        initial = list(queue)
        queue.clear()

    def gen():
        try:
            existing = os.path.join(LOG_DIR, f"{job_id}.jsonl")
            if os.path.exists(existing):
                with open(existing, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            yield f"data: {line}\n\n"
            for item in initial:
                yield f"data: {item}\n\n"
            import time as _time

            idle = 0
            while idle < 600:
                if queue:
                    while queue:
                        yield f"data: {queue.pop(0)}\n\n"
                    idle = 0
                else:
                    _time.sleep(0.25)
                    idle += 1
                cur = JOBS.get(job_id)
                if cur and cur.get("status") in ("success", "failed"):
                    if not queue:
                        break
        finally:
            with JOB_LOCK:
                subs = SUBSCRIBERS.get(job_id, [])
                if queue in subs:
                    subs.remove(queue)

    return StreamingResponse(gen(), media_type="text/event-stream")


@app.get("/api/jobs/{job_id}/download")
def download_job(job_id: str):
    job = JOBS.get(job_id) or history.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    path = job.get("output_path")
    if not path or not os.path.exists(path):
        raise HTTPException(status_code=404, detail="output not ready")
    return FileResponse(path, media_type="application/vnd.android.package-archive",
                        filename=os.path.basename(path))


@app.get("/api/jobs/{job_id}/report")
def job_report(job_id: str):
    job = JOBS.get(job_id) or history.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")
    return JSONResponse(job)


@app.get("/api/logs")
def list_logs() -> dict:
    items = []
    for name in os.listdir(LOG_DIR):
        if not name.endswith(".log"):
            continue
        path = os.path.join(LOG_DIR, name)
        items.append(
            {
                "job_id": name[:-4],
                "size": os.path.getsize(path),
                "modified": datetime.fromtimestamp(
                    os.path.getmtime(path), tz=timezone.utc
                ).isoformat(),
            }
        )
    items.sort(key=lambda x: x["modified"], reverse=True)
    return {"items": items}


@app.get("/api/logs/{job_id}")
def read_log(job_id: str, tail: int = 500) -> dict:
    path = os.path.join(LOG_DIR, f"{job_id}.log")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="log not found")
    with open(path, "r", encoding="utf-8") as f:
        lines = [ln for ln in f.read().splitlines() if ln]
    if tail > 0:
        lines = lines[-tail:]
    return {"ok": True, "job_id": job_id, "lines": lines}


@app.get("/api/history")
def get_history(limit: int = 100) -> dict:
    return {
        "jobs": history.list_jobs(limit),
        "toggles": history.list_toggles(limit),
    }


@app.get("/api/settings")
def get_settings() -> dict:
    path = os.path.join(DATA_DIR, "settings.json")
    defaults = {
        "password": "nxshield",
        "extract_ratio": 0.45,
        "encrypt_cjk": True,
        "encrypt_vip_keywords": True,
        "asset_encrypt": True,
        "keep_signature": False,
        "name_obfuscate": False,
    }
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            defaults.update(json.load(f))
    return {"settings": defaults}


@app.put("/api/settings")
def put_settings(payload: dict) -> dict:
    path = os.path.join(DATA_DIR, "settings.json")
    current = {}
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            current = json.load(f)
    current.update(payload or {})
    with open(path, "w", encoding="utf-8") as f:
        json.dump(current, f, ensure_ascii=False, indent=2)
    return {"ok": True, "settings": current}
