"""Text from a PDF, for retrieval: the text layer of every page, joined by blank lines.

Runs as its own process, started by copilot.sources.read_pdf:

    python -I copilot/pdftext.py FILE [MEMORY_BYTES CPU_SECONDS]

It limits its own memory and CPU time before it opens the file, so a crafted PDF (a decompression bomb, a parser that
never ends) fails this process and not the lab console that started it, which also hosts the kill switch. It prints
one JSON object: {"text": ..., "pages": n} or {"error": ...}; the exit code is 0 only with text.

Scanned PDFs have no text layer: OCR them first (out of scope here). Encrypted PDFs are read only without a password.
"""
import json
import sys

MAX_PAGES = 1000
MAX_CHARS = 5_000_000


def limit(memory_bytes, cpu_seconds):
    try:
        import resource
    except ImportError:                       # Windows: the parent's timeout still applies
        return
    resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))


def extract(path):
    from pypdf import PdfReader
    reader = PdfReader(path)
    if reader.is_encrypted:
        try:
            ok = reader.decrypt("")
        except Exception:                     # noqa: BLE001
            ok = 0
        if not ok:
            raise ValueError("the PDF is encrypted")
    n = len(reader.pages)
    if n > MAX_PAGES:
        raise ValueError(f"{n} pages; at most {MAX_PAGES}")
    parts, total = [], 0
    for page in reader.pages:
        t = (page.extract_text() or "").strip()
        if t:
            parts.append(t)
            total += len(t)
            if total > MAX_CHARS:
                raise ValueError(f"more than {MAX_CHARS:,} characters of text")
    if not parts:
        raise ValueError("no text layer (a scanned PDF?): OCR it first")
    return "\n\n".join(parts), n


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) >= 3:
        limit(int(argv[1]), int(argv[2]))
    try:
        text, n = extract(argv[0])
        out = {"text": text, "pages": n}
    except ImportError:
        out = {"error": "reading PDFs needs the pypdf package"}
    except MemoryError:
        out = {"error": "the PDF needs more memory than allowed"}
    except ValueError as e:                   # our own reasons (no text layer, encrypted, too big), as written
        out = {"error": str(e)[:300]}
    except Exception as e:                    # noqa: BLE001  a broken PDF is an answer, not a crash
        out = {"error": f"{type(e).__name__}: {e}"[:300]}
    sys.stdout.write(json.dumps(out))
    return 0 if "text" in out else 1


if __name__ == "__main__":
    sys.exit(main())
