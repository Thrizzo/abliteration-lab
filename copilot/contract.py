"""The operator/judge prompt contract, shared with the n8n workflow (deploy/n8n/build_workflow.js reads the same
operator_contract.json), so QLoRA training pairs and the eval talk to the operator exactly the way n8n does.

    operator_messages(task, target, references="")  ->  [system, user] chat messages, identical to the n8n operator node
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


def operator_user(task, target, references=""):
    msg = f"TASK: {task}\nTARGET (authorized, in scope): {target}"
    if references:
        msg += f"\n\n{REFERENCE_HEADER}\n<<<\n{references}\n>>>"
    return msg


def operator_messages(task, target, references=""):
    return [{"role": "system", "content": OPERATOR_SYSTEM}, {"role": "user", "content": operator_user(task, target, references)}]


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
