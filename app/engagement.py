"""The copilot's engagement: scope statement, rules of engagement, scope, exclusions, time window, prohibited tools and
auto-run tiers. One engagement is active at a time; every save is a new version under workspace/engagement/ and goes
into the audit log, with who saved it.

The console sends the active version with each copilot run. n8n's scope gate and policy gate enforce it
(deploy/n8n/policy.js), with LAB_ALLOWLIST and LAB_AUTORUN_* as the ceiling: the engagement can narrow the scope and
switch tiers off, never widen them. This module checks what the GUI saves (formats, the ceiling when the console knows
it: the same copilot-scope ConfigMap n8n reads) and hands the payload over; it decides nothing at run time.
Standard library only.
"""
import ipaddress
import json
import os
import re
import tempfile
import threading
from datetime import datetime, timezone

LIMITS = {"name": 120, "scope_statement": 4000, "roe": 8000, "note": 300}
MAX_ENTRIES = 64
# RFC 1123 host names, lower case (the gate compares host names exactly, so case is normalised here)
_HOST = re.compile(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*")
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def now_iso():
    t = datetime.now(timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def scope_entry(value):
    """One scope entry as the gate reads it: an IPv4 address, an IPv4 network (CIDR) or an exact host name. Returns
    (kind, normalised text); ValueError otherwise. No IPv6 and no wildcards: the gate cannot verify them."""
    s = str(value or "").strip().lower()
    if not s:
        raise ValueError("empty entry")
    if "/" in s:
        try:
            net = ipaddress.IPv4Network(s, strict=False)
        except ValueError:
            raise ValueError(f"{value!r} is not an IPv4 network (e.g. 10.10.10.0/24)") from None
        return "net", str(net)
    try:
        return "ip", str(ipaddress.IPv4Address(s))
    except ValueError:
        pass
    if re.fullmatch(r"[0-9.]+", s):
        raise ValueError(f"{value!r} is not an IPv4 address")
    if not _HOST.fullmatch(s):
        raise ValueError(f"{value!r} is not an IPv4 address, IPv4 network or host name (no wildcards, no IPv6)")
    return "host", s


def parse_ceiling(text):
    """LAB_ALLOWLIST ("10.10.10.0/24,192.168.56.0/24,box.htb") as entries; entries that do not parse are left out, as
    the gate never matches them."""
    out = []
    for part in str(text or "").split(","):
        try:
            out.append(scope_entry(part))
        except ValueError:
            continue
    return out


def within(entry, ceiling):
    """Whether a scope entry lies inside the ceiling: an address in one of its networks or equal to one of its
    addresses, a network inside one of its networks (or the single address of a /32), a host name listed exactly."""
    kind, val = entry
    if kind == "host":
        return any(k == "host" and v == val for k, v in ceiling)
    if kind == "ip":
        ip = ipaddress.IPv4Address(val)
        return any((k == "net" and ip in ipaddress.IPv4Network(v)) or (k == "ip" and v == val) for k, v in ceiling)
    net = ipaddress.IPv4Network(val)
    return any((k == "net" and net.subnet_of(ipaddress.IPv4Network(v)))
               or (k == "ip" and net.num_addresses == 1 and str(net.network_address) == v) for k, v in ceiling)


def _text(fields, key, errors):
    v = fields.get(key)
    v = "" if v is None else str(v)
    v = v.replace("\r\n", "\n").strip()
    if _CTRL.search(v):
        errors.append(f"{key}: control characters are not allowed")
    if len(v) > LIMITS[key]:
        errors.append(f"{key}: at most {LIMITS[key]} characters ({len(v)} given)")
    return v


def _lines(value):
    """A list from the GUI: a JSON list, or text with one entry per line or comma-separated."""
    if isinstance(value, list):
        items = value
    else:
        items = re.split(r"[\n,]", str(value or ""))
    return [str(x).strip() for x in items if str(x or "").strip()]


def _when(value, key, errors):
    s = str(value or "").strip()
    if not s:
        return None
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00") if s.endswith("Z") else s)
    except ValueError:
        errors.append(f"{key}: {s!r} is not a date and time (e.g. 2026-11-26T08:00+01:00)")
        return None
    if dt.tzinfo is None:
        errors.append(f"{key}: give a time zone (e.g. +01:00 or Z), so n8n and the console mean the same moment")
        return None
    return dt.isoformat(timespec="seconds")      # one canonical form, which n8n's Date.parse reads


_SENTENCE = re.compile(r"(?<=[.;!?])\s+|\n+")                    # not at ":": "backup01.lab ...: do not touch it" is one
_NEGATED = re.compile(r"\b(not|never|no|don't|avoid|exclude[ds]?|excluding|forbidden|prohibited|off-limits|out of scope)\b", re.I)
_IP_IN_TEXT = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\w.])")
_HOST_IN_TEXT = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:lab|local|htb|thm|corp|internal|lan|intra|com|net|org|io|de)\b", re.I)


def rule_hints(fields):
    """Hosts that a sentence of the rules or the scope statement puts off-limits ("do not touch backup01.lab", "not a
    target") while Out of scope leaves them open. Only Out of scope is enforced in code; measured with Qwen3-8B as the
    judge, rules like that were missed in 2 of 2 cases (copilot/README.md, "Judge eval")."""
    excluded = []
    for raw in _lines(fields.get("scope_out")):
        try:
            excluded.append(scope_entry(raw))
        except ValueError:
            continue
    out, seen = [], set()
    for key in ("roe", "scope_statement"):
        for sentence in _SENTENCE.split(str(fields.get(key) or "")):
            if not _NEGATED.search(sentence):
                continue
            for m in list(_IP_IN_TEXT.finditer(sentence)) + list(_HOST_IN_TEXT.finditer(sentence)):
                try:
                    entry = scope_entry(m.group(0))
                except ValueError:
                    continue
                if entry[1] in seen or any(within(entry, [x]) for x in excluded):
                    continue
                seen.add(entry[1])
                out.append({"host": entry[1], "sentence": sentence.strip()[:200]})
    return out


class Engagements:
    def __init__(self, project, audit=None, feed=None, ceiling=None, autorun=None, http_error=None):
        self.dir = os.path.join(project, "engagement")
        self.audit, self.feed = audit, feed
        # LAB_ALLOWLIST / LAB_AUTORUN_* as n8n reads them (ConfigMap copilot-scope); None: the console does not know them
        self.ceiling = parse_ceiling(ceiling) if ceiling else None
        self.ceiling_text = ceiling or None
        self.autorun = autorun or {}
        self.http_error = http_error or (lambda status, msg: ValueError(f"{status}: {msg}"))
        self.lock = threading.Lock()

    # ---------------------------------------------------------------- validation
    def validate(self, fields):
        """The fields as they are stored and sent, or http_error(400) listing every problem."""
        if not isinstance(fields, dict):
            raise self.http_error(400, "the engagement is a JSON object")
        errors = []
        out = {k: _text(fields, k, errors) for k in ("name", "scope_statement", "roe")}
        for key in ("scope_in", "scope_out"):
            entries, seen = [], set()
            for raw in _lines(fields.get(key)):
                try:
                    kind, val = scope_entry(raw)
                except ValueError as e:
                    errors.append(f"{key}: {e}")
                    continue
                if key == "scope_in" and self.ceiling is not None and not within((kind, val), self.ceiling):
                    errors.append(f"scope_in: {val} is outside LAB_ALLOWLIST ({self.ceiling_text}): the copilot could never "
                                  f"reach it. Widen LAB_ALLOWLIST first (deploy/k8s, copilot scope)")
                if val not in seen:
                    seen.add(val)
                    entries.append(val)
            if len(entries) > MAX_ENTRIES:
                errors.append(f"{key}: at most {MAX_ENTRIES} entries")
            out[key] = entries[:MAX_ENTRIES]
        prohibited = []
        for p in _lines(fields.get("prohibited")):
            p = re.sub(r"\s+", " ", p)
            if len(p) > 64 or _CTRL.search(p):
                errors.append(f"prohibited: {p[:40]!r} is longer than 64 characters or has control characters")
            elif p.lower() not in (x.lower() for x in prohibited):
                prohibited.append(p)
        if len(prohibited) > MAX_ENTRIES:
            errors.append(f"prohibited: at most {MAX_ENTRIES} entries")
        out["prohibited"] = prohibited[:MAX_ENTRIES]
        out["window_start"] = _when(fields.get("window_start"), "window_start", errors)
        out["window_end"] = _when(fields.get("window_end"), "window_end", errors)
        if out["window_start"] and out["window_end"] and \
                datetime.fromisoformat(out["window_end"]) <= datetime.fromisoformat(out["window_start"]):
            errors.append("window_end: must be after window_start")
        for key in ("autorun_passive", "autorun_active", "active"):
            v = fields.get(key, key == "active")
            if not isinstance(v, bool):
                errors.append(f"{key}: true or false")
                v = False
            out[key] = v
        if errors:
            raise self.http_error(400, "; ".join(errors))
        return out

    # ---------------------------------------------------------------- storage
    def _path(self, version):
        return os.path.join(self.dir, "versions", f"v{int(version):04d}.json")

    def _read(self, path):
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            return None

    def _write(self, path, obj):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2, ensure_ascii=False)
        os.replace(tmp, path)

    def current(self):
        """The active record {version, saved, by, note, ...fields}, or None before the first save."""
        return self._read(os.path.join(self.dir, "current.json"))

    def get(self, version):
        rec = self._read(self._path(version))
        if not rec:
            raise self.http_error(404, f"no engagement version {version}")
        return rec

    def versions(self, limit=50):
        try:
            names = sorted((n for n in os.listdir(os.path.join(self.dir, "versions")) if re.fullmatch(r"v\d{4,}\.json", n)), reverse=True)
        except OSError:
            return []
        out = []
        for n in names[:limit]:
            rec = self._read(os.path.join(self.dir, "versions", n)) or {}
            out.append({k: rec.get(k) for k in ("version", "saved", "by", "note", "name", "active")})
        return out

    def save(self, fields, who=None, note=""):
        """A new version from the GUI's fields (validated); saving the same fields again changes nothing."""
        clean = self.validate(fields)
        note = str(note or "").strip()[:LIMITS["note"]]
        with self.lock:
            cur = self.current()
            if cur and all(cur.get(k) == v for k, v in clean.items()):
                return {**cur, "hints": rule_hints(cur)}
            version = max([int(v["version"]) for v in self.versions(limit=1) if v.get("version")] + [0]) + 1
            rec = {"version": version, "saved": now_iso(), "by": (who or {}).get("user") or (who or {}).get("ip"), "note": note, **clean}
            self._write(self._path(version), rec)
            self._write(os.path.join(self.dir, "current.json"), rec)
        changed = sorted(k for k, v in clean.items() if not cur or cur.get(k) != v)
        rec = {**rec, "hints": rule_hints(clean)}           # not stored: worked out from the fields each time
        msg = f"engagement v{version} saved" + (f": {clean['name']}" if clean["name"] else "") + ("" if clean["active"] else " (inactive)")
        data = {"version": version, "changed": changed, "note": note, "scope_in": clean["scope_in"], "scope_out": clean["scope_out"],
                "prohibited": clean["prohibited"], "window": [clean["window_start"], clean["window_end"]], "active": clean["active"]}
        if self.audit:
            self.audit.write("copilot", "engagement", msg, who=who or {}, data=data)
        elif self.feed:
            self.feed.emit("copilot", "engagement", msg, "info", data)
        return rec

    # ---------------------------------------------------------------- what a run gets
    def payload(self):
        """The active engagement as the workflow reads it, or None (no engagement, or switched off): then n8n applies
        LAB_ALLOWLIST alone."""
        cur = self.current()
        if not cur or not cur.get("active", True):
            return None
        keys = ("name", "version", "scope_statement", "roe", "scope_in", "scope_out", "window_start", "window_end", "prohibited",
                "autorun_passive", "autorun_active")
        return {k: cur.get(k) for k in keys}

    def status(self):
        cur = self.current()
        return {"current": cur, "hints": rule_hints(cur) if cur else [], "versions": self.versions(20),
                "ceiling": {"known": self.ceiling is not None, "allowlist": self.ceiling_text,
                            "autorun_passive": self.autorun.get("passive"), "autorun_active": self.autorun.get("active")}}
