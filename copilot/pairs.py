r"""Turn pentest writeups into QLoRA training pairs in the n8n operator's exact contract (copilot/contract.py).

    python -m copilot.pairs --src /workspace/writeups --out /workspace/finetune/pairs
    python -m copilot.pairs --src ... --out ... --include-pwk      # only if your licence allows training on it

A writeup is narrative: prose saying what the author saw, then the command they ran. Every command becomes one pair:
state (section + the prose leading up to it + the previous step) -> the command, as chat messages identical to what n8n
sends the operator, with the operator's single-line JSON as the answer. Built in from the live runs:

- TARGET substitution: every IP in a document is mapped to a fresh lab address (stable per document), lab host names in
  commands are mapped to the target, and the document's main target goes into the prompt's TARGET field. The model learns
  to aim at TARGET, not to copy an address from its context (the failure measured in the n8n run).
- PWK course material is excluded by default (licence; trained weights can reproduce their training text).
- engagement notes are scrubbed with copilot.scrub before anything is extracted.
- train/eval split by DOCUMENT, so eval never contains pairs from a writeup the model trained on.
- catastrophic commands (rm -rf /, mkfs, fork bombs ...) are dropped; they are never a good suggestion.
Standard library only.
"""
import argparse
import hashlib
import json
import os
import re
from collections import Counter

from .chunk import RX_FENCE, RX_HEADING
from .contract import operator_answer, operator_messages
from .scrub import load_terms, scrub
from .sources import NO_TRAIN_SOURCES, SOURCES, iter_documents

SHELL_LANGS = {"", "bash", "sh", "shell", "zsh", "console", "terminal", "text", "powershell", "ps", "ps1", "pwsh", "cmd", "bat"}
# first tokens that make a line a command even without a prompt prefix
TOOLS = set("""nmap rustscan masscan ping fping traceroute arp host dig nslookup whois dnsrecon dnsenum fierce amass subfinder
theharvester curl wget httpx whatweb wafw00f sslscan sslyze testssl.sh gobuster ffuf feroxbuster dirb dirbuster wfuzz nikto
enum4linux enum4linux-ng smbmap smbclient ldapsearch rpcclient rpcinfo showmount snmpwalk onesixtyone nbtscan ike-scan nc
ncat netcat socat ssh scp sftp ftp telnet mysql psql mssqlclient.py sqlmap hydra medusa john hashcat crackmapexec cme
netexec nxc evil-winrm impacket-psexec psexec.py wmiexec.py smbexec.py secretsdump.py getuserspns.py getnpusers.py
gettgt.py kerbrute bloodhound-python responder msfconsole msfvenom searchsploit python python3 php perl ruby bash sh
sudo su chmod chown cat ls find grep awk sed echo id whoami hostname uname ps netstat ss ip ifconfig env export cd pwd
cp mv tar zip unzip base64 xxd openssl git docker kubectl powershell iex certutil wget.exe reg net net.exe whoami.exe
chisel ligolo proxychains linpeas.sh winpeas.exe pspy getcap""".split())
RX_PROMPT = re.compile(r"^\s*(?:\(?[\w.@-]*\)?\s*)?(?:[\w.-]+@[\w.-]+(?::[^\s$#]*)?\s*)?(?:PS [A-Za-z]:\\[^>]*>|[$#>%])\s+")
RX_IP = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.]*\d)|<IP_\d+>")
RX_LABHOST = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:htb|thm|vl|local|lab|lan|internal|corp|offsec)\b|<HOST_\d+>", re.I)
DENY = [re.compile(p, re.I) for p in (r"\brm\s+-rf?\s+/(?![\w.])", r"\bmkfs\b", r":\(\)\s*\{\s*:\|:&\s*\}\s*;",
                                         r"\b(shutdown|reboot|halt)\b", r"history\s+-c")]   # mirrors the hard cases of policy.js


def _rng_ip(seed, k):
    h = hashlib.sha256(f"{seed}:{k}".encode()).digest()
    return f"10.{10 + h[0] % 6}.{h[1] % 254 + 1}.{h[2] % 253 + 2}"


def _is_valid_ip(s):
    return s.startswith("<IP_") or all(0 <= int(o) <= 255 for o in s.split("."))


def address_map(doc_id, text):
    """Every distinct address in the document -> a fresh lab address (stable per doc). The most frequent one is the
    document's target. Loopback/any/broadcast stay as they are."""
    found = [m.group(0) for m in RX_IP.finditer(text) if _is_valid_ip(m.group(0))]
    found = [a for a in found if not (a.startswith("127.") or a.startswith("0.") or a.startswith("255."))]
    if not found:
        return None, {}
    target = Counter(found).most_common(1)[0][0]
    mapping = {a: _rng_ip(doc_id, i) for i, a in enumerate(dict.fromkeys(found))}
    return target, mapping


def apply_map(text, mapping, target_new):
    text = RX_IP.sub(lambda m: mapping.get(m.group(0), m.group(0)), text)
    return RX_LABHOST.sub(target_new, text) if target_new else text


def extract_commands(block):
    """Command lines from a fenced block. Prompt-prefixed lines are commands; un-prefixed lines count only if they start
    with a known tool and the block shows no prompts (pure command block). Backslash continuations are joined."""
    lines = block.split("\n")[1:]                       # drop the opening fence
    if lines and RX_FENCE.match(lines[-1]):
        lines = lines[:-1]
    joined, buf = [], ""
    for ln in lines:
        part = ln.strip() if buf else ln                 # a continuation's indentation is just whitespace to the shell
        if part.rstrip().endswith("\\"):
            buf += part.rstrip()[:-1].rstrip() + " "
            continue
        joined.append(buf + part)
        buf = ""
    if buf:
        joined.append(buf)
    def prompt_rest(ln):
        """Text after a shell prompt, or None. A bare '#' is the root prompt only if a real command follows it
        ('# id'); otherwise it is a comment ('# a comment') and must not flip the block into prompt mode."""
        m = RX_PROMPT.match(ln)
        if not m:
            return None
        rest = ln[m.end():].strip()
        marker = m.group(0).strip()
        if marker == "#":
            first = rest.split()[0].lower().rsplit("/", 1)[-1] if rest else ""
            if first not in TOOLS:
                return None
        return rest

    has_prompt = any(prompt_rest(l) is not None for l in joined)
    cmds = []
    for ln in joined:
        if has_prompt:
            rest = prompt_rest(ln)
            if rest is None:
                continue                                 # output line or comment
            ln = rest
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        first = re.split(r"\s+", ln, maxsplit=1)[0].lower().rsplit("/", 1)[-1]
        if has_prompt or first in TOOLS:
            cmds.append(ln)
    return cmds


def _sentences(text):
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+", text.strip()) if s.strip()]


def doc_pairs(doc, text, max_state=700):
    """Yields pair dicts for one (already scrubbed) document."""
    target_old, mapping = address_map(doc.rel, text)
    if not target_old:
        return                                           # no address -> no TARGET to train against
    target_new = mapping[target_old]
    path, prose, prev_cmd = [], [], ""
    in_fence, fence_buf, fence_lang = False, [], ""
    for line in text.replace("\r\n", "\n").split("\n") + [""]:
        f = RX_FENCE.match(line)
        if in_fence:
            fence_buf.append(line)
            if f:
                in_fence = False
                if fence_lang in SHELL_LANGS:
                    heading = " > ".join(t for _, t in path) or doc.title
                    state = apply_map(" ".join(prose)[-max_state:], mapping, target_new)
                    for cmd in extract_commands("\n".join(fence_buf)):
                        cmd = apply_map(cmd, mapping, target_new)
                        if any(rx.search(cmd) for rx in DENY) or len(cmd) > 400:
                            continue
                        # TARGET is the host THIS step aims at (multi-host engagements); local steps keep the doc target
                        hit = RX_IP.search(cmd)
                        target = hit.group(0) if hit and hit.group(0) in mapping.values() else target_new
                        sents = _sentences(state)
                        rationale = (sents[-1] if sents else heading)[:200]
                        task = f"{heading}. Context: {state}" + (f" Previous step: {prev_cmd}" if prev_cmd else "") + " Suggest the next step."
                        yield {"messages": operator_messages(task, target) + [
                                   {"role": "assistant", "content": operator_answer(cmd, target, rationale)}],
                               "meta": {"source": doc.source, "doc": doc.rel, "heading": heading, "target": target}}
                        prev_cmd = cmd
                fence_buf = []
            continue
        if f:
            in_fence, fence_buf = True, [line]
            fence_lang = line.strip().strip("`~").strip().lower()
            continue
        h = RX_HEADING.match(line)
        if h:
            level = len(h.group(1))
            while path and path[-1][0] >= level:
                path.pop()
            path.append((level, h.group(2)))
            prose, prev_cmd = [], ""
        elif line.strip():
            prose.append(line.strip())
            prose[:] = prose[-6:]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--src", required=True)
    ap.add_argument("--out", required=True, help="output folder for train.jsonl, eval.jsonl, stats.json")
    ap.add_argument("--include-pwk", action="store_true", help="also train on pwk/ (only if your licence allows it)")
    ap.add_argument("--eval-frac", type=float, default=0.1, help="fraction of DOCUMENTS held out for eval")
    ap.add_argument("--redact-terms")
    args = ap.parse_args(argv)

    terms_path = args.redact_terms or (os.path.join(args.src, "redact_terms.txt") if os.path.isfile(os.path.join(args.src, "redact_terms.txt")) else None)
    terms = load_terms(terms_path)
    exclude = set() if args.include_pwk else set(NO_TRAIN_SOURCES)
    docs = iter_documents(args.src, exclude=exclude)
    docs.sort(key=lambda d: hashlib.sha256(d.rel.encode()).hexdigest())
    n_eval = max(1, round(len(docs) * args.eval_frac)) if len(docs) >= 2 else 0
    eval_docs = {d.rel for d in docs[:n_eval]}

    os.makedirs(args.out, exist_ok=True)
    seen, stats = set(), {"docs": len(docs), "eval_docs": sorted(eval_docs), "pairs": {"train": 0, "eval": 0},
                          "by_source": {}, "excluded_sources": sorted(exclude)}
    with open(os.path.join(args.out, "train.jsonl"), "w", encoding="utf-8") as ft, \
         open(os.path.join(args.out, "eval.jsonl"), "w", encoding="utf-8") as fe:
        for doc in docs:
            text, _ = scrub(doc.text, doc.source, terms)
            for pair in doc_pairs(doc, text):
                key = (pair["meta"]["doc"], pair["messages"][-1]["content"])
                if key in seen:
                    continue
                seen.add(key)
                split = "eval" if doc.rel in eval_docs else "train"
                (fe if split == "eval" else ft).write(json.dumps(pair, ensure_ascii=False) + "\n")
                stats["pairs"][split] += 1
                stats["by_source"][doc.source] = stats["by_source"].get(doc.source, 0) + 1
    with open(os.path.join(args.out, "stats.json"), "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)
    print(f"pairs: train {stats['pairs']['train']}, eval {stats['pairs']['eval']} from {len(docs)} docs "
          f"(eval docs: {len(eval_docs)}; excluded sources: {sorted(exclude) or 'none'}) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
