"""The operator/judge prompt contract, shared with the n8n workflow (deploy/n8n/build_workflow.js reads the same
operator_contract.json), so QLoRA training pairs and the eval talk to the operator exactly the way n8n does.

    operator_messages(task, target, references="", engagement=None)  ->  [system, user] chat messages, identical to the
                                                     n8n "Build operator prompt" node
    judge_user(task, target, command, read_only, tier, engagement=None, allowlist=None)  ->  the n8n "Build judge prompt"
                                                     node's message
    engagement_text(engagement)                      ->  the console's engagement (scope, rules) as both prompts show it
    neutral(text)                                    ->  the address neutralizer of the n8n "Build reference context" node
    OUTPUT_KEYS                                      ->  the JSON object the operator must answer with
"""
import json
import os
import re

_HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(_HERE, "operator_contract.json"), encoding="utf-8") as _f:
    CONTRACT = json.load(_f)

OPERATOR_SYSTEM = CONTRACT["operator_system"]
JUDGE_SYSTEM = CONTRACT["judge_system"]
REFERENCE_HEADER = CONTRACT["reference_header"]
ENGAGEMENT_HEADER = CONTRACT["engagement_header"]
ENGAGEMENT_MAX = 4000          # characters of engagement text in a prompt (the operator may have an 8k context)
OUTPUT_KEYS = ("command", "target", "rationale")

# mirrors the JS neutralizer in build_workflow.js; both are checked against tests/fixtures/neutral_vectors.json
_RX_IP = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.]*\d)")
_RX_LABHOST = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:htb|thm|vl|local|lab|lan|internal|corp|offsec)\b", re.I)


def neutral(text):
    """Addresses and lab host names in past writeups belong to OTHER machines; replace them so the operator keeps the
    technique but cannot copy the address."""
    text = re.sub(r"<HOST_\d+>", "<other-host>", re.sub(r"<IP_\d+>", "<other-host-ip>", str(text)))   # scrubbed notes
    text = _RX_IP.sub(lambda m: "<other-host-ip>" if all(int(o) <= 255 for o in m.group(0).split(".")) else m.group(0), text)
    return _RX_LABHOST.sub("<other-host>", text)


def engagement_text(e):
    """The engagement as both prompts show it (mirrors engagementText in deploy/n8n/build_workflow.js). The rules come
    last: past ENGAGEMENT_MAX characters it is their end that is cut."""
    if not isinstance(e, dict):
        return ""

    def s(v):
        return "" if v is None else str(v).strip()

    def joined(v):
        return ", ".join(s(x) for x in (v if isinstance(v, list) else []) if s(x))
    lines = []
    if s(e.get("name")):
        lines.append(f"ENGAGEMENT: {s(e.get('name'))}" + (f" (version {s(e.get('version'))})" if s(e.get("version")) else ""))
    for label, value in (("SCOPE STATEMENT", s(e.get("scope_statement"))), ("IN SCOPE", joined(e.get("scope_in"))),
                         ("OUT OF SCOPE", joined(e.get("scope_out")))):
        if value:
            lines.append(f"{label}: {value}")
    if s(e.get("window_start")) or s(e.get("window_end")):
        lines.append(f"WINDOW: {s(e.get('window_start')) or 'open'} to {s(e.get('window_end')) or 'open'}")
    for label, value in (("PROHIBITED", joined(e.get("prohibited"))), ("RULES", s(e.get("roe")))):
        if value:
            lines.append(f"{label}: {value}")
    text = "\n".join(lines)
    return text if len(text) <= ENGAGEMENT_MAX else text[:ENGAGEMENT_MAX] + " ..."


def operator_user(task, target, references="", engagement=None):
    msg = f"TASK: {task}\nTARGET (authorized, in scope): {target}"
    rules = engagement_text(engagement)
    if rules:
        msg += f"\n\n{ENGAGEMENT_HEADER}\n<<<\n{rules}\n>>>"
    if references:
        msg += f"\n\n{REFERENCE_HEADER}\n<<<\n{references}\n>>>"
    return msg


def operator_messages(task, target, references="", engagement=None):
    return [{"role": "system", "content": OPERATOR_SYSTEM},
            {"role": "user", "content": operator_user(task, target, references, engagement)}]


def judge_user(task, target, command, read_only, tier, engagement=None, allowlist=None):
    """What the judge reads (its system prompt is JUDGE_SYSTEM): the scope (LAB_ALLOWLIST), the rules of engagement and
    the vetted command, never the operator's free text."""
    rules = engagement_text(engagement)
    scope = ", ".join(s for s in (str(x if x is not None else "").strip() for x in (allowlist or [])) if s)
    return (f"TASK: {task}\nTARGET: {target}" + (f"\nSCOPE (LAB_ALLOWLIST): {scope}" if scope else "")
            + (f"\n{ENGAGEMENT_HEADER}\n<<<\n{rules}\n>>>" if rules else "")
            + f"\nPROPOSED COMMAND (already passed the scope + denylist gate):\n{command}\nread-only: "
            + ("true" if read_only else "false") + f"  tier: {tier or 'none'}")


def operator_answer(command, target, rationale):
    """The exact single-line JSON the operator is trained and prompted to emit."""
    return json.dumps({"command": command, "target": target, "rationale": rationale}, ensure_ascii=False)


def parse_answer(text):
    """Same extraction order as the n8n Parse proposal node: first {...} JSON object, else a fenced block, else the
    first non-empty line. Returns (proposal_dict, json_ok)."""
    raw = str(text or "")
    m = re.search(r"\{[\s\S]*\}", raw)
    if m:
        try:
            p = json.loads(m.group(0))
            return {k: str(p.get(k, "") or "") for k in OUTPUT_KEYS}, True
        except ValueError:
            pass
    fence = re.search(r"```(?:bash|sh)?\n([\s\S]*?)```", raw)
    line = fence.group(1) if fence else next((s.strip() for s in raw.split("\n") if s.strip()), "")
    return {"command": line.strip(), "target": "", "rationale": ""}, False
