"""Knowledge uploads for the copilot's retrieval (design section 6).

A writeup (md, txt, rst, html or pdf, up to 50 MB) is stored under workspace/writeups/<source>/ and ingested with the
same steps as `python -m copilot.ingest`: scrub for its source, chunk, embed (Ollama, the model n8n queries with) and
upsert into Qdrant with deterministic ids, so uploading a file again replaces its chunks. Engagement notes can be
previewed first: the scrubber's redactions and the scrubbed text, before anything is stored or embedded.

Uploaded text stays untrusted. The workflow hands it only to the operator, with addresses masked, never to the judge,
and the policy gate stays the boundary. PDFs are parsed in a separate, memory- and CPU-limited process
(copilot/pdftext.py): the console also hosts the kill switch. Standard library only (plus pypdf in that process).
"""
import hashlib
import os
import re
import tempfile
import threading
import time
import unicodedata

from copilot import chunk as CH
from copilot import ingest as ING
from copilot import scrub as SC
from copilot import sources as SRC

EXTS = SRC.TEXT_EXT | SRC.HTML_EXT | SRC.PDF_EXT
MAX_BYTES = 50 * 1024 * 1024
SOURCE_INFO = {
    "htb": "retired HTB / CTF writeups",
    "blog": "public blogs and PoCs",
    "engagement": "your client notes: scrubbed hard (preview the redactions first)",
    "pwk": "PWK / OSCP material: retrieval only, never training data",
}


def safe_name(filename):
    """A plain file name for the writeups folder: no directories, safe characters, an allowed type. ValueError else."""
    base = os.path.basename(unicodedata.normalize("NFKC", str(filename or "")).replace("\\", "/"))
    stem, ext = os.path.splitext(base)
    ext = ext.lower()
    if ext not in EXTS:
        raise ValueError(f"unsupported type {ext or '(none)'}: {', '.join(sorted(EXTS))}")
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", stem).strip("-._")[:100]
    if not stem:
        raise ValueError("the file needs a name")
    return stem + ext


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%S")


class Knowledge:
    def __init__(self, project, qdrant_url, collection, ollama_url, embed_model, feed=None, audit=None, http_error=None,
                 chunk_chars=1200):
        self.root = os.path.join(project, "writeups")
        self.qdrant_url, self.collection = (qdrant_url or "").rstrip("/"), collection or "writeups"
        self.ollama_url, self.embed_model = (ollama_url or "").rstrip("/"), embed_model or "nomic-embed-text"
        if self.ollama_url and not self.ollama_url.startswith("http"):
            self.ollama_url = "http://" + self.ollama_url
        self.feed, self.audit, self.chunk_chars = feed, audit, chunk_chars
        self.http_error = http_error or (lambda status, msg: RuntimeError(f"{status}: {msg}"))
        self.lock = threading.Lock()
        self.busy = threading.Semaphore(1)        # one ingest at a time: embedding is CPU-heavy in dev
        self.jobs = {}                            # rel -> {status, done, total, chunks, redactions, error, ...}

    def configured(self):
        return bool(self.qdrant_url and self.ollama_url)

    def _qdrant(self):
        return ING.Qdrant(self.qdrant_url, self.collection)

    def _terms(self):
        p = os.path.join(self.root, "redact_terms.txt")
        return SC.load_terms(p if os.path.isfile(p) else None)

    def _log(self, stage, message, who=None, level="info", data=None):
        if self.audit:
            self.audit.write("knowledge", stage, message, level=level, who=who or {}, data=data)
        elif self.feed:
            self.feed.emit("knowledge", stage, message, level, data)

    # ---------------------------------------------------------------- checks
    def _check(self, source, filename, data):
        if source not in SRC.SOURCES:
            raise self.http_error(400, f"source must be one of {', '.join(SRC.SOURCES)}")
        try:
            name = safe_name(filename)
        except ValueError as e:
            raise self.http_error(400, str(e))
        if not data:
            raise self.http_error(400, "the file is empty")
        if len(data) > MAX_BYTES:
            raise self.http_error(413, f"larger than {MAX_BYTES // (1024 * 1024)} MB")
        return name

    def _text(self, name, data):
        """The file's text; PDFs through the limited extractor (which reads a file, hence the temporary copy)."""
        fd, tmp = tempfile.mkstemp(suffix=os.path.splitext(name)[1].lower())
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            text = SRC.read_text(tmp)
        except ValueError as e:
            raise self.http_error(422, f"{name}: {e}")
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        if not text.strip():
            raise self.http_error(422, f"{name}: no text in it")
        return text

    def _rel(self, rel):
        """A document id the list showed: a path inside the writeups folder, never outside it."""
        rel = str(rel or "")
        parts = rel.split("/")
        if (not rel or len(rel) > 400 or "\\" in rel or "\x00" in rel or rel.startswith("/")
                or any(p in ("", ".", "..") for p in parts)):
            raise self.http_error(400, "not a document of the writeups folder")
        root = os.path.realpath(self.root)
        path = os.path.realpath(os.path.join(root, *parts))
        if not path.startswith(root + os.sep):
            raise self.http_error(400, "not a document of the writeups folder")
        return rel, path

    # ---------------------------------------------------------------- actions
    def preview(self, source, filename, data):
        """What ingesting would do, without storing or embedding anything."""
        name = self._check(source, filename, data)
        text = self._text(name, data)
        scrubbed, report = SC.scrub(text, source, self._terms())
        chunks = CH.chunk_markdown(scrubbed, target=self.chunk_chars, hard_limit=self.chunk_chars * 2)
        limit = 30000
        return {"doc": f"{source}/{name}", "source": source, "chars": len(text), "chunks": len(chunks), "redactions": report,
                "scrubbed": scrubbed[:limit] if source == "engagement" else None,
                "truncated": source == "engagement" and len(scrubbed) > limit,
                "sample": chunks[0].text[:800] if chunks else ""}

    def upload(self, source, filename, data, who=None):
        name = self._check(source, filename, data)
        if not self.configured():
            raise self.http_error(409, "no vector store or embedding model configured (QDRANT_URL, RAG_OLLAMA_URL)")
        rel = f"{source}/{name}"
        with self.lock:
            if (self.jobs.get(rel) or {}).get("status") in ("queued", "ingesting"):
                raise self.http_error(409, f"{rel} is being ingested right now")
        text = self._text(name, data)                 # refuse what can't be read before anything is stored
        path = os.path.join(self.root, source, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".part"
        with open(tmp, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
        sha = hashlib.sha256(data).hexdigest()
        job = {"status": "queued", "done": 0, "total": None, "chunks": None, "redactions": None, "error": None,
               "size": len(data), "sha256": sha, "uploaded": _now()}
        with self.lock:
            self.jobs[rel] = job
        self._log("upload", f"knowledge upload {rel} ({len(data):,} bytes)", who,
                  data={"doc": rel, "source": source, "size": len(data), "sha256": sha})
        answer = {"doc": rel, **job}                  # a snapshot: the ingest thread updates job from here on
        threading.Thread(target=self._ingest, args=(rel, source, path, text, who), daemon=True).start()
        return answer

    def _set(self, rel, **kw):
        with self.lock:
            if rel in self.jobs:
                self.jobs[rel].update(kw)

    def _ingest(self, rel, source, path, text, who):
        with self.busy:
            self._set(rel, status="ingesting")
            doc = SRC.Document(path, rel, source, SRC._title(text, rel), text)
            try:
                chunks, report = ING.ingest_document(
                    doc, self._terms(), ING.Ollama(self.ollama_url, self.embed_model), self._qdrant(), self.chunk_chars,
                    progress=lambda done, total: self._set(rel, done=done, total=total))
            except Exception as e:                    # noqa: BLE001  shown in the list and the feed
                self._set(rel, status="error", error=str(e)[:300])
                self._log("ingest", f"{rel}: ingest failed: {str(e)[:200]}", who, level="error", data={"doc": rel})
                return
            self._set(rel, status="done", chunks=len(chunks), redactions=report, total=len(chunks), done=len(chunks))
            self._log("ingest", f"{rel}: {len(chunks)} chunks in the vector store" + (f", redacted {report}" if report else ""),
                      who, data={"doc": rel, "chunks": len(chunks), "redactions": report})

    def list(self):
        files = {}
        if os.path.isdir(self.root):
            for dirpath, dirnames, filenames in os.walk(self.root):
                dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
                for fn in filenames:
                    if fn.startswith(".") or fn == "redact_terms.txt" or fn.endswith(".part"):
                        continue
                    p = os.path.join(dirpath, fn)
                    rel = os.path.relpath(p, self.root).replace(os.sep, "/")
                    st = os.stat(p)
                    files[rel] = {"size": st.st_size, "modified": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(st.st_mtime))}
        counts, qerr = {}, None
        if self.qdrant_url:
            try:
                counts = self._qdrant().doc_counts()
            except Exception as e:                    # noqa: BLE001  the files still list
                qerr = str(e)[:300]
        with self.lock:
            jobs = {k: dict(v) for k, v in self.jobs.items()}
        docs = []
        for rel in sorted(set(files) | set(counts) | set(jobs)):
            f, c, j = files.get(rel) or {}, counts.get(rel) or {}, jobs.get(rel) or {}
            n = c.get("chunks", 0)
            status = j.get("status") if j.get("status") in ("queued", "ingesting", "error") else ("indexed" if n else "not indexed")
            docs.append({"doc": rel, "source": SRC.source_of(rel), "title": c.get("title") or os.path.basename(rel),
                         "file": bool(f), "size": f.get("size"), "modified": f.get("modified"), "chunks": n,
                         "ingested": c.get("ingested"), "status": status, "error": j.get("error"),
                         "progress": [j.get("done"), j.get("total")] if j.get("status") == "ingesting" else None,
                         "redactions": j.get("redactions")})
        docs.sort(key=lambda d: d["modified"] or d["ingested"] or "", reverse=True)
        return {"configured": self.configured(), "collection": self.collection, "qdrant_error": qerr, "docs": docs,
                "sources": SOURCE_INFO, "max_bytes": MAX_BYTES, "types": sorted(EXTS)}

    def delete(self, rel, who=None):
        """The document's vectors first, then its file: if the store can't be reached, nothing is removed."""
        rel, path = self._rel(rel)
        with self.lock:
            if (self.jobs.get(rel) or {}).get("status") in ("queued", "ingesting"):
                raise self.http_error(409, f"{rel} is being ingested right now")
        if self.qdrant_url:
            try:
                self._qdrant().delete_doc(rel)
            except ING.HTTPError as e:
                if "HTTP 404" not in str(e):          # no collection yet: nothing to delete there
                    raise self.http_error(502, f"the vector store refused: {str(e)[:200]}")
        existed = os.path.isfile(path)
        if existed:
            os.remove(path)
        with self.lock:
            self.jobs.pop(rel, None)
        self._log("delete", f"knowledge delete {rel}" + ("" if existed else " (vectors only, no file)"), who, data={"doc": rel})
        return {"doc": rel, "deleted": True, "file": existed}
