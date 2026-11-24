"""Finding and reading writeups. Standard library only.

Layout under the writeups root (the first folder decides the source tag, which controls scrubbing and whether a
document may be used for training):

    writeups/
      htb/          retired HTB / CTF writeups          (public; used for RAG and training)
      blog/         public blogs and PoCs                (public; used for RAG and training)
      engagement/   your own client notes                (scrubbed hard; used for RAG and training after scrubbing)
      pwk/          PWK / OSCP course material           (RAG only - excluded from training data by default)
      redact_terms.txt   optional: one client name / domain / project per line, removed from every source
"""
import html
import html.parser
import os
import re
from dataclasses import dataclass

SOURCES = ("htb", "blog", "engagement", "pwk")
TEXT_EXT = {".md", ".markdown", ".txt", ".rst"}
HTML_EXT = {".html", ".htm"}
MAX_BYTES = 5 * 1024 * 1024
# sources whose content must not end up in model weights unless explicitly allowed (course material licence terms)
NO_TRAIN_SOURCES = {"pwk"}


@dataclass
class Document:
    path: str        # absolute
    rel: str         # relative to the writeups root, forward slashes; stable id for the document
    source: str      # one of SOURCES or "misc"
    title: str
    text: str


class _HTMLToMarkdown(html.parser.HTMLParser):
    """Minimal HTML -> text: keeps headings and <pre>/<code> blocks as fenced code, drops scripts/styles."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out, self.skip, self.pre = [], 0, 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "nav", "footer", "header"):
            self.skip += 1
        elif tag == "pre":
            self.pre += 1
            self.out.append("\n```\n")
        elif tag in ("h1", "h2", "h3", "h4") and not self.pre:
            self.out.append("\n\n" + "#" * int(tag[1]) + " ")
        elif tag in ("p", "div", "li", "br", "tr") and not self.pre:
            self.out.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style", "nav", "footer", "header"):
            self.skip = max(0, self.skip - 1)
        elif tag == "pre":
            self.pre = max(0, self.pre - 1)
            self.out.append("\n```\n")
        elif tag in ("h1", "h2", "h3", "h4", "p") and not self.pre:
            self.out.append("\n")

    def handle_data(self, data):
        if not self.skip:
            self.out.append(data)

    def text(self):
        return re.sub(r"\n{3,}", "\n\n", "".join(self.out)).strip()


def read_text(path):
    ext = os.path.splitext(path)[1].lower()
    with open(path, encoding="utf-8", errors="replace") as f:
        raw = f.read()
    if ext in HTML_EXT:
        p = _HTMLToMarkdown()
        p.feed(raw)
        return html.unescape(p.text())
    return raw


def _title(text, rel):
    for line in text.splitlines()[:40]:
        m = re.match(r"^#\s+(.+)", line)
        if m:
            return m.group(1).strip()
    return os.path.splitext(os.path.basename(rel))[0]


def source_of(rel):
    first = rel.split("/", 1)[0].lower()
    return first if first in SOURCES else "misc"


def iter_documents(root, include=None, exclude=()):
    """Yields Documents under root, plus a list of skipped files (path, reason) via the `skipped` attribute."""
    root = os.path.abspath(root)
    skipped = []
    docs = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if not d.startswith("."))
        for fn in sorted(filenames):
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            ext = os.path.splitext(fn)[1].lower()
            if fn == "redact_terms.txt" or fn.startswith("."):
                continue
            if ext not in TEXT_EXT | HTML_EXT:
                skipped.append((rel, f"unsupported type {ext or '(none)'} (convert PDFs to markdown first)"))
                continue
            if os.path.getsize(path) > MAX_BYTES:
                skipped.append((rel, "larger than 5 MB"))
                continue
            src = source_of(rel)
            if include and src not in include:
                continue
            if src in exclude:
                continue
            text = read_text(path)
            if not text.strip():
                skipped.append((rel, "empty"))
                continue
            docs.append(Document(path, rel, src, _title(text, rel), text))
    iter_documents.skipped = skipped
    return docs
