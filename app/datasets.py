"""Dataset workbench: view / search / add / edit / remove rows of the local JSONL copies in data/
(harmful_train, harmful_test, harmless_train, dpo_train). Every removal and edit is logged under data/removed/
and data/edits.jsonl, like the notebook's cell 3.8c, so the audit trail stays complete."""
import hashlib
import json
import os
import re
import threading
from datetime import datetime

FILES = {
    "harmful_train.jsonl": {"label": "harmful · train", "repo": "mlabonne/harmful_behaviors", "kind": "prompt", "used": "measuring the direction (first n_train rows)"},
    "harmful_test.jsonl": {"label": "harmful · test", "repo": "mlabonne/harmful_behaviors", "kind": "prompt", "used": "held-out scan / validation prompts (first n_test rows)"},
    "harmless_train.jsonl": {"label": "harmless · train", "repo": "mlabonne/harmless_alpaca", "kind": "prompt", "used": "measuring the direction (first n_train rows) + harmless validation prompts"},
    "dpo_train.jsonl": {"label": "DPO · train", "repo": "mlabonne/orpo-dpo-mix-40k", "kind": "dpo", "used": "DPO healing (notebook section 6), optional"},
}


class Datasets:
    def __init__(self, data_dir):
        self.dir = data_dir
        self.cache = {}
        self.lock = threading.Lock()

    # ------------------------------------------------------------ io
    def path(self, fname):
        if fname not in FILES:
            raise KeyError(fname)
        return os.path.join(self.dir, fname)

    def rows(self, fname):
        with self.lock:
            p = self.path(fname)
            mtime = os.path.getmtime(p) if os.path.isfile(p) else None
            c = self.cache.get(fname)
            if c and c["mtime"] == mtime:
                return c["rows"]
            rows = []
            if mtime is not None:
                with open(p, encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            rows.append(json.loads(line))
            self.cache[fname] = {"mtime": mtime, "rows": rows}
            return rows

    def _write(self, fname, rows):
        p = self.path(fname)
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        self.cache[fname] = {"mtime": os.path.getmtime(p), "rows": rows}

    def _audit(self, fname, kind, records):
        os.makedirs(os.path.join(self.dir, "removed"), exist_ok=True)
        target = os.path.join(self.dir, "removed", fname) if kind == "removed" else os.path.join(self.dir, "edits.jsonl")
        with open(target, "a", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps({"at": datetime.now().isoformat(timespec="seconds"), "file": fname, **r}, ensure_ascii=False) + "\n")

    @staticmethod
    def text_of(row):
        if "prompt" in row:
            return row["prompt"]
        parts = []
        for key in ("chosen", "rejected"):
            for m in row.get(key) or []:
                if isinstance(m, dict):
                    parts.append(m.get("content", ""))
        return "\n".join(parts)

    # ------------------------------------------------------------ status
    def status(self):
        manifest_p = os.path.join(self.dir, "manifest.json")
        manifest = json.load(open(manifest_p, encoding="utf-8")) if os.path.isfile(manifest_p) else {}
        out = []
        for fname, info in FILES.items():
            p = self.path(fname)
            present = os.path.isfile(p)
            m = manifest.get(fname, {})
            removed_p = os.path.join(self.dir, "removed", fname)
            n_removed = sum(1 for l in open(removed_p, encoding="utf-8") if l.strip()) if os.path.isfile(removed_p) else 0
            n_now = len(self.rows(fname)) if present else 0
            edited = None
            if present and m.get("sha256"):
                h = hashlib.sha256()
                with open(p, "rb") as f:
                    for b in iter(lambda: f.read(1 << 20), b""):
                        h.update(b)
                edited = h.hexdigest() != m["sha256"]
            # the source the copy was exported from (ABL_HARMFUL_DATASET / ABL_HARMLESS_DATASET), not only the default
            if present and edited is None and m.get("absent"):
                edited = True                        # the source has no such split: every row was added here
            out.append({"file": fname, **info, "repo": m.get("repo") or info["repo"], "present": present,
                        "rows_original": m.get("rows"), "rows_now": n_now, "removed": n_removed,
                        "revision": m.get("revision"), "requested": m.get("requested"), "column": m.get("column"),
                        "absent": bool(m.get("absent")) and not present,     # e.g. a dataset without a test split
                        "exported": m.get("exported"), "edited": edited, "size_mb": round(os.path.getsize(p) / 1e6, 1) if present else None})
        return out

    # ------------------------------------------------------------ query
    def search(self, fname, q="", offset=0, limit=50, source=None, regex=False):
        rows = self.rows(fname)
        if q:
            if regex:
                rx = re.compile(q, re.IGNORECASE)
                hit = lambda r: rx.search(self.text_of(r)) is not None
            else:
                ql = q.lower()
                hit = lambda r: ql in self.text_of(r).lower()
        else:
            hit = lambda r: True
        if source:
            hit0 = hit
            hit = lambda r: r.get("source") == source and hit0(r)
        matches = [r for r in rows if hit(r)]
        page = matches[offset:offset + limit]
        sources = None
        if FILES[fname]["kind"] == "dpo":
            counts = {}
            for r in rows:
                counts[r.get("source")] = counts.get(r.get("source"), 0) + 1
            sources = sorted(counts.items(), key=lambda x: -x[1])
        return {"file": fname, "total": len(rows), "matches": len(matches), "offset": offset, "limit": limit, "rows": page, "sources": sources}

    # ------------------------------------------------------------ mutations
    def add(self, fname, row):
        rows = self.rows(fname)
        prefix = fname[:-6]
        n = max([int(r["id"].rsplit("-", 1)[1]) for r in rows if str(r.get("id", "")).startswith(prefix) and r["id"].rsplit("-", 1)[1].isdigit()] + [-1]) + 1
        new = {"id": f"{prefix}-{n}", **row, "added_by": "app", "added_at": datetime.now().isoformat(timespec="seconds")}
        self._write(fname, rows + [new])
        self._audit(fname, "edit", [{"action": "add", "row": new}])
        return new

    def edit(self, fname, rid, changes):
        rows = self.rows(fname)
        idx = next((i for i, r in enumerate(rows) if r.get("id") == rid), None)
        if idx is None:
            raise KeyError(rid)
        before = dict(rows[idx])
        rows[idx] = {**rows[idx], **changes, "edited_at": datetime.now().isoformat(timespec="seconds")}
        self._write(fname, rows)
        self._audit(fname, "edit", [{"action": "edit", "id": rid, "before": before, "after": rows[idx]}])
        return rows[idx]

    def remove(self, fname, ids, reason=""):
        ids = set(ids)
        rows = self.rows(fname)
        removed = [r for r in rows if r.get("id") in ids]
        keep = [r for r in rows if r.get("id") not in ids]
        if removed:
            self._write(fname, keep)
            self._audit(fname, "removed", [{"reason": reason or "removed in the app", **r} for r in removed])
        return {"removed": len(removed), "remaining": len(keep)}

    def removed_rows(self, fname, limit=200):
        p = os.path.join(self.dir, "removed", fname)
        if not os.path.isfile(p):
            return []
        out = [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]
        return out[-limit:]

    def restore(self, fname, ids):
        p = os.path.join(self.dir, "removed", fname)
        if not os.path.isfile(p):
            return {"restored": 0}
        entries = [json.loads(l) for l in open(p, encoding="utf-8") if l.strip()]
        back, keep = [], []
        for e in entries:
            (back if e.get("id") in set(ids) else keep).append(e)
        rows = self.rows(fname)
        existing = {r.get("id") for r in rows}
        restored = [{k: v for k, v in e.items() if k not in ("at", "file", "reason")} for e in back if e.get("id") not in existing]
        if restored:
            self._write(fname, rows + restored)
            with open(p, "w", encoding="utf-8") as f:
                for e in keep:
                    f.write(json.dumps(e, ensure_ascii=False) + "\n")
            self._audit(fname, "edit", [{"action": "restore", "ids": [r["id"] for r in restored]}])
        return {"restored": len(restored)}
