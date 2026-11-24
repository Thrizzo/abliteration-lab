"""Markdown-aware chunking for writeups.

Writeups are prose interleaved with fenced command blocks. A chunk keeps a command block together with the prose that
explains it (that pairing is what makes retrieval useful), never splits a code fence unless it alone exceeds the hard
limit, and is prefixed with its heading path ("Foothold > SMB") so a retrieved chunk still says where it came from.
Standard library only.
"""
import re
from dataclasses import dataclass, field

RX_HEADING = re.compile(r"^(#{1,6})\s+(.*\S)\s*$")
RX_FENCE = re.compile(r"^(\s*)(`{3,}|~{3,})")


@dataclass
class Chunk:
    text: str
    heading: str
    index: int
    has_code: bool = False
    code_langs: list = field(default_factory=list)


def _blocks(text):
    """Yields (kind, text, heading_level, heading_title) with kind in heading | code | prose."""
    lines = text.replace("\r\n", "\n").split("\n")
    i, buf = 0, []

    def flush():
        para = "\n".join(buf).strip()
        buf.clear()
        return para

    while i < len(lines):
        line = lines[i]
        fence = RX_FENCE.match(line)
        heading = RX_HEADING.match(line)
        if fence:
            para = flush()
            if para:
                yield "prose", para, 0, ""
            marker = fence.group(2)
            code = [line]
            i += 1
            while i < len(lines):
                code.append(lines[i])
                if lines[i].strip().startswith(marker[0] * len(marker)):
                    break
                i += 1
            yield "code", "\n".join(code), 0, ""
        elif heading:
            para = flush()
            if para:
                yield "prose", para, 0, ""
            yield "heading", line, len(heading.group(1)), heading.group(2)
        elif not line.strip():
            para = flush()
            if para:
                yield "prose", para, 0, ""
        else:
            buf.append(line)
        i += 1
    para = flush()
    if para:
        yield "prose", para, 0, ""


def _split_long(block, limit):
    """Hard split for a single block bigger than the limit, on line boundaries."""
    out, cur = [], []
    for line in block.split("\n"):
        if cur and sum(len(x) + 1 for x in cur) + len(line) > limit:
            out.append("\n".join(cur))
            cur = []
        cur.append(line)
    if cur:
        out.append("\n".join(cur))
    return out


def chunk_markdown(text, target=1200, hard_limit=2400, overlap=150):
    """Splits a writeup into Chunks of about `target` characters (never above `hard_limit`)."""
    path = []                      # heading stack [(level, title)]
    chunks, cur, cur_heading = [], [], ""
    tail = ""                      # overlap carried from the previous chunk (prose only)

    def heading_str():
        return " > ".join(t for _, t in path)

    def emit():
        nonlocal cur, tail
        body = "\n\n".join(cur).strip()
        if not body:
            cur = []
            return
        langs = [m.group(1).lower() for m in re.finditer(r"```\s*([A-Za-z0-9_+-]+)", body)]
        prefix = f"[{cur_heading}]\n" if cur_heading else ""
        chunks.append(Chunk(prefix + body, cur_heading, len(chunks), "```" in body or "~~~" in body, langs))
        prose = [b for b in cur if not RX_FENCE.match(b.split("\n", 1)[0])]
        tail = prose[-1][-overlap:] if prose and overlap else ""
        cur = []

    for kind, block, level, title in _blocks(text):
        if kind == "heading":
            emit()
            while path and path[-1][0] >= level:
                path.pop()
            path.append((level, title))
            cur_heading, tail = heading_str(), ""
            continue
        pieces = _split_long(block, hard_limit) if len(block) > hard_limit else [block]
        for piece in pieces:
            size = sum(len(b) + 2 for b in cur)
            if cur and size + len(piece) > target:
                emit()
                if tail and kind == "prose":
                    cur.append("…" + tail.strip())
            cur.append(piece)
    emit()
    return chunks
