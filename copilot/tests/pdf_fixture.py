"""Minimal, valid PDFs for tests, built by hand (no PDF library needed to write them): one Helvetica text line per
entry, pages in order. A page with no lines has no text layer, like a scanned page."""


def make_pdf(pages):
    n_pages = len(pages)
    page_ids = [4 + 2 * i for i in range(n_pages)]
    content_ids = [5 + 2 * i for i in range(n_pages)]
    objects = {
        1: b"<< /Type /Catalog /Pages 2 0 R >>",
        2: ("<< /Type /Pages /Kids [" + " ".join(f"{p} 0 R" for p in page_ids) + f"] /Count {n_pages} >>").encode(),
        3: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    }
    for i, lines in enumerate(pages):
        ops = ["BT", "/F1 12 Tf", "72 720 Td"]
        for j, line in enumerate(lines):
            text = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            if j:
                ops.append("0 -16 Td")
            ops.append(f"({text}) Tj")
        ops.append("ET")
        stream = "\n".join(ops).encode("latin-1")
        objects[content_ids[i]] = b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream"
        objects[page_ids[i]] = ("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                                f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_ids[i]} 0 R >>").encode()
    out = bytearray(b"%PDF-1.4\n")
    offsets = {}
    for k in sorted(objects):
        offsets[k] = len(out)
        out += f"{k} 0 obj\n".encode() + objects[k] + b"\nendobj\n"
    xref, n = len(out), max(objects) + 1
    out += f"xref\n0 {n}\n".encode() + b"0000000000 65535 f \n"
    out += b"".join(f"{offsets[k]:010d} 00000 n \n".encode() for k in range(1, n))
    out += f"trailer\n<< /Size {n} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(out)
