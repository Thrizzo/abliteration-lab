r"""Ingest pentest writeups into Qdrant for the n8n copilot's retrieval step.

    python -m copilot.ingest --src /workspace/writeups --dry-run --show-redactions   # read what scrubbing does first
    python -m copilot.ingest --src /workspace/writeups                                 # embed + upsert
    docker compose --env-file deploy/.env run --rm --no-deps app python -m copilot.ingest --src /workspace/writeups

Each document is scrubbed for its source (see copilot/scrub.py), chunked (copilot/chunk.py), embedded with Ollama and
upserted in the payload schema n8n's Qdrant node reads: {"content": <text>, "metadata": {...}}. Point ids are
deterministic (uuid5 of document + chunk index) and a re-ingested document's old points are deleted first, so running
it again after editing a writeup updates instead of duplicating. Standard library only; runs inside the app image.
"""
import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

from .chunk import chunk_markdown
from .scrub import load_terms, scrub
from .sources import SOURCES, iter_documents

NAMESPACE = uuid.UUID("6f1f2b6c-3a9e-4f3e-9d5c-2a7b8c1d0e11")


class HTTPError(RuntimeError):
    pass


class ConfigError(RuntimeError):
    """The store and the embedding model disagree (e.g. the model was changed): a setup problem, not a network one."""


def _req(method, url, body=None, timeout=120, ok404=False):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        if ok404 and e.code == 404:
            return None
        raise HTTPError(f"{method} {url}: HTTP {e.code} {e.read()[:300].decode(errors='replace')}") from None
    except urllib.error.URLError as e:
        raise HTTPError(f"{method} {url}: {e.reason} (is the service running and reachable from here?)") from None


class Ollama:
    def __init__(self, host, model, prefix=""):
        self.host, self.model, self.prefix = host.rstrip("/"), model, prefix

    def embed(self, texts):
        texts = [self.prefix + t for t in texts]
        try:
            return _req("POST", f"{self.host}/api/embed", {"model": self.model, "input": texts})["embeddings"]
        except HTTPError as e:
            if "404" not in str(e):
                raise
            # Ollama < 0.3: one text per call on the legacy endpoint
            return [_req("POST", f"{self.host}/api/embeddings", {"model": self.model, "prompt": t})["embedding"] for t in texts]


class Qdrant:
    def __init__(self, url, collection, api_key=None):
        self.url, self.collection = url.rstrip("/"), collection
        self.api_key = api_key

    def _c(self, suffix=""):
        return f"{self.url}/collections/{self.collection}{suffix}"

    def ensure(self, dim, recreate=False):
        info = _req("GET", self._c(), ok404=True)
        if info is not None and recreate:
            _req("DELETE", self._c())
            info = None
        if info is None:
            _req("PUT", self._c(), {"vectors": {"size": dim, "distance": "Cosine"}})
            # deletes and lists filter on the document: index it, so they don't scan the whole collection
            _req("PUT", self._c("/index?wait=true"), {"field_name": "metadata.doc", "field_schema": "keyword"})
            return "created"
        vectors = ((info.get("result") or {}).get("config") or {}).get("params", {}).get("vectors", {})
        size = vectors.get("size") if isinstance(vectors, dict) else None
        if size and size != dim:
            raise ConfigError(f"collection '{self.collection}' has vectors of size {size} but the embedding model returns {dim}: "
                              f"you changed the embedding model. Use --recreate (re-embeds everything) or another --collection.")
        return "exists"

    def delete_doc(self, rel):
        _req("POST", self._c("/points/delete?wait=true"),
             {"filter": {"must": [{"key": "metadata.doc", "match": {"value": rel}}]}})

    def upsert(self, points):
        _req("PUT", self._c("/points?wait=true"), {"points": points})

    def doc_counts(self, page=1000):
        """{doc: {"chunks", "source", "title", "ingested"}} for every document in the collection ({} if there is none)."""
        if _req("GET", self._c(), ok404=True) is None:
            return {}
        docs, offset = {}, None
        while True:
            body = {"limit": page, "with_vector": False,
                    "with_payload": ["metadata.doc", "metadata.source", "metadata.title", "metadata.ingested"]}
            if offset is not None:
                body["offset"] = offset
            res = _req("POST", self._c("/points/scroll"), body).get("result") or {}
            for p in res.get("points") or []:
                md = (p.get("payload") or {}).get("metadata") or {}
                d = docs.setdefault(md.get("doc") or "?", {"chunks": 0, "source": md.get("source"), "title": md.get("title"),
                                                            "ingested": md.get("ingested")})
                d["chunks"] += 1
                d["ingested"] = max(d["ingested"] or "", md.get("ingested") or "") or None
            offset = res.get("next_page_offset")
            if offset is None:
                return docs


def point_id(rel, index):
    return str(uuid.uuid5(NAMESPACE, f"{rel}#{index}"))


def build_points(doc, chunks, vectors, redactions):
    pts = []
    for ch, vec in zip(chunks, vectors):
        pts.append({"id": point_id(doc.rel, ch.index), "vector": vec, "payload": {
            "content": ch.text,
            "metadata": {"source": doc.source, "doc": doc.rel, "title": doc.title, "heading": ch.heading,
                         "chunk": ch.index, "has_code": ch.has_code, "code_langs": ch.code_langs,
                         "scrubbed": bool(redactions), "ingested": time.strftime("%Y-%m-%dT%H:%M:%S")}}})
    return pts


def ingest_document(doc, terms, ollama, qdrant, chunk_chars=1200, batch=16, recreate=False, progress=None):
    """Scrub, chunk, embed and upsert one document; its earlier chunks are replaced. Returns (chunks, redaction report).
    progress(done, total) after every batch."""
    text, report = scrub(doc.text, doc.source, terms)
    chunks = chunk_markdown(text, target=chunk_chars, hard_limit=chunk_chars * 2)
    for i in range(0, len(chunks), batch):
        part = chunks[i:i + batch]
        vecs = ollama.embed([c.text for c in part])
        if i == 0:
            qdrant.ensure(len(vecs[0]), recreate=recreate)
            qdrant.delete_doc(doc.rel)                # drop this document's previous chunks before writing the new ones
        qdrant.upsert(build_points(doc, part, vecs, report))
        if progress:
            progress(min(i + batch, len(chunks)), len(chunks))
    return chunks, report


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--src", required=True, help="writeups root (htb/, blog/, engagement/, pwk/ subfolders)")
    ap.add_argument("--collection", default=os.environ.get("RAG_COLLECTION", "writeups"))
    ap.add_argument("--ollama", default=os.environ.get("OLLAMA_HOST", "http://localhost:11434"))
    ap.add_argument("--qdrant", default=os.environ.get("QDRANT_URL", "http://localhost:6333"))
    ap.add_argument("--embed-model", default=os.environ.get("RAG_EMBED_MODEL", "nomic-embed-text"))
    ap.add_argument("--doc-prefix", default="", help='text prepended to every chunk before embedding, e.g. "search_document: " for nomic (then also prefix queries)')
    ap.add_argument("--redact-terms", help="file with one client name / domain / project per line (default: <src>/redact_terms.txt if present)")
    ap.add_argument("--only", nargs="*", choices=SOURCES + ("misc",), help="ingest only these sources")
    ap.add_argument("--exclude", nargs="*", default=[], choices=SOURCES + ("misc",), help="skip these sources (e.g. pwk)")
    ap.add_argument("--chunk-chars", type=int, default=1200)
    ap.add_argument("--batch", type=int, default=16)
    ap.add_argument("--recreate", action="store_true", help="drop and recreate the collection (after changing the embedding model)")
    ap.add_argument("--dry-run", action="store_true", help="scrub and chunk only, no network")
    ap.add_argument("--show-redactions", action="store_true", help="print each scrubbed document (dry-run) so you can review it")
    args = ap.parse_args(argv)

    if not args.ollama.startswith("http"):
        args.ollama = "http://" + args.ollama
    terms_path = args.redact_terms or (os.path.join(args.src, "redact_terms.txt") if os.path.isfile(os.path.join(args.src, "redact_terms.txt")) else None)
    terms = load_terms(terms_path)
    docs = iter_documents(args.src, include=set(args.only) if args.only else None, exclude=set(args.exclude))
    skipped = getattr(iter_documents, "skipped", [])
    print(f"ingest: {len(docs)} documents under {args.src}" + (f", redact terms: {len(terms)} from {terms_path}" if terms else ""))

    ollama = None if args.dry_run else Ollama(args.ollama, args.embed_model, args.doc_prefix)
    qdrant = None if args.dry_run else Qdrant(args.qdrant, args.collection)
    recreate, totals, n_chunks = args.recreate, {}, 0
    by_source = {}
    for doc in docs:
        if args.dry_run:
            text, report = scrub(doc.text, doc.source, terms)
            chunks = chunk_markdown(text, target=args.chunk_chars, hard_limit=args.chunk_chars * 2)
        else:
            chunks, report = ingest_document(doc, terms, ollama, qdrant, args.chunk_chars, args.batch, recreate)
            recreate = recreate and not chunks        # drop the collection once, before the first document's chunks
        for k, v in report.items():
            totals[k] = totals.get(k, 0) + v
        n_chunks += len(chunks)
        by_source[doc.source] = by_source.get(doc.source, 0) + 1
        print(f"  {doc.source:10s} {doc.rel}: {len(chunks)} chunks" + (f", redacted {report}" if report else ""))
        if args.dry_run and args.show_redactions and doc.source == "engagement":
            print("  ---- scrubbed " + doc.rel + " ----\n" + text + "\n  ---- end ----")
    for rel, why in skipped:
        print(f"  skipped {rel}: {why}")
    print(f"ingest: {'(dry run) ' if args.dry_run else ''}{len(docs)} docs {by_source}, {n_chunks} chunks, redactions {totals or 'none'}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (HTTPError, ConfigError) as e:
        print(f"ERROR {e}", file=sys.stderr)
        sys.exit(2)
