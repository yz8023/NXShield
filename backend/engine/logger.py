from __future__ import annotations

import json
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional


LEVELS = ("DEBUG", "INFO", "WARN", "ERROR")


class JobLogger:
    def __init__(self, log_dir: str, job_id: str, on_line: Optional[Callable[[dict], None]] = None):
        self.log_dir = log_dir
        self.job_id = job_id
        self.on_line = on_line
        self.path = os.path.join(log_dir, f"{job_id}.log")
        self.jsonl_path = os.path.join(log_dir, f"{job_id}.jsonl")
        self._lock = threading.Lock()
        os.makedirs(log_dir, exist_ok=True)

    def log(self, level: str, message: str, **extra: Any) -> dict:
        level = level.upper()
        rec = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": level,
            "job_id": self.job_id,
            "message": message,
        }
        if extra:
            rec["extra"] = extra
        line = f"[{rec['ts']}] [{level}] {message}"
        if extra:
            line += " " + json.dumps(extra, ensure_ascii=False)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            with open(self.jsonl_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
        if self.on_line:
            try:
                self.on_line(rec)
            except Exception:
                pass
        return rec

    def debug(self, message: str, **extra: Any) -> dict:
        return self.log("DEBUG", message, **extra)

    def info(self, message: str, **extra: Any) -> dict:
        return self.log("INFO", message, **extra)

    def warn(self, message: str, **extra: Any) -> dict:
        return self.log("WARN", message, **extra)

    def error(self, message: str, **extra: Any) -> dict:
        return self.log("ERROR", message, **extra)

    def read_text(self) -> str:
        if not os.path.exists(self.path):
            return ""
        with open(self.path, "r", encoding="utf-8") as f:
            return f.read()

    def read_records(self) -> List[dict]:
        if not os.path.exists(self.jsonl_path):
            return []
        recs: List[dict] = []
        with open(self.jsonl_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    recs.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return recs


class HistoryStore:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"jobs": [], "toggles": []}, f)

    def _load(self) -> dict:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {"jobs": [], "toggles": []}
        data.setdefault("jobs", [])
        data.setdefault("toggles", [])
        return data

    def _save(self, data: dict) -> None:
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)

    def add_job(self, job: dict) -> None:
        with self._lock:
            data = self._load()
            jobs = data["jobs"]
            jobs = [j for j in jobs if j.get("id") != job.get("id")]
            jobs.insert(0, job)
            data["jobs"] = jobs[:500]
            self._save(data)

    def update_job(self, job_id: str, **fields: Any) -> Optional[dict]:
        with self._lock:
            data = self._load()
            found = None
            for j in data["jobs"]:
                if j.get("id") == job_id:
                    j.update(fields)
                    found = j
                    break
            if found:
                self._save(data)
            return found

    def list_jobs(self, limit: int = 100) -> List[dict]:
        with self._lock:
            data = self._load()
            return data["jobs"][:limit]

    def get_job(self, job_id: str) -> Optional[dict]:
        with self._lock:
            data = self._load()
            for j in data["jobs"]:
                if j.get("id") == job_id:
                    return j
        return None

    def add_toggle(self, feature: str, enabled: bool, source: str = "ui") -> dict:
        rec = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "feature": feature,
            "enabled": enabled,
            "source": source,
        }
        with self._lock:
            data = self._load()
            data["toggles"].insert(0, rec)
            data["toggles"] = data["toggles"][:1000]
            self._save(data)
        return rec

    def list_toggles(self, limit: int = 200) -> List[dict]:
        with self._lock:
            data = self._load()
            return data["toggles"][:limit]


def now_ms() -> int:
    return int(time.time() * 1000)
