"""Connects n8n to the lab console: one run sets up everything the console's copilot runs need. Re-running is safe.

  1. an n8n API key for the console that may only read and stop executions (created through your n8n login; a
     temporary setup key does the rest and is deleted at the end). With --api-key, that key is used for both;
  2. the copilot's credentials: the operator (OpenAI-compatible: glm-serve), Ollama (judge, embeddings), Qdrant, and
     the console's webhook secret (Header Auth, X-Lab-Secret);
  3. the workflow (deploy/n8n/workflows/pentest-copilot.json) with those credentials selected, published;
  4. the console's Secret "copilot" (webhook-secret, n8n-api-key), applied with kubectl or written to a file.
     The console reads it from a mounted file, so no restart is needed (it can take a minute to appear).

Reach n8n through a port-forward first:
    kubectl -n lab-copilot port-forward svc/n8n 5678:5678
    python deploy/n8n/connect_console.py --email you@example.com --apply-secret
The password is asked for (or N8N_PASSWORD). Standard library only; works on Windows, macOS and Linux.
"""
import argparse
import getpass
import json
import os
import secrets
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

HERE = os.path.dirname(os.path.abspath(__file__))
WORKFLOW = os.path.join(HERE, "workflows", "pentest-copilot.json")
KEY_LABEL = "lab console"
SETUP_LABEL = "lab console setup (temporary)"
CONSOLE_SCOPES = ["execution:read", "execution:list", "execution:stop"]     # follow and stop runs, nothing else

# credential name -> type, and which node types use it
CREDS = {
    "operator": ("Lab: operator (OpenAI-compatible)", "openAiApi"),
    "ollama": ("Lab: Ollama (judge, embeddings)", "ollamaApi"),
    "qdrant": ("Lab: Qdrant", "qdrantApi"),
    "webhook": ("Lab: console webhook secret", "httpHeaderAuth"),
}
NODE_CREDS = {
    "@n8n/n8n-nodes-langchain.lmChatOpenAi": "operator",
    "@n8n/n8n-nodes-langchain.lmChatOllama": "ollama",
    "@n8n/n8n-nodes-langchain.embeddingsOllama": "ollama",
    "@n8n/n8n-nodes-langchain.vectorStoreQdrant": "qdrant",
    "n8n-nodes-base.webhook": "webhook",
}
# what the public API accepts when it creates or updates a workflow
WORKFLOW_FIELDS = ("name", "nodes", "connections", "settings")


class N8n:
    def __init__(self, base, browser_id=None):
        self.base = base.rstrip("/")
        self.cookie = None
        self.api_key = None
        self.browser_id = browser_id or str(uuid.uuid4())     # the login cookie can be bound to it

    def call(self, method, path, body=None, auth="api"):
        headers = {"Accept": "application/json", "browser-id": self.browser_id}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        if auth == "api":
            headers["X-N8N-API-KEY"] = self.api_key
        elif auth == "session" and self.cookie:
            headers["Cookie"] = self.cookie
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                raw = r.read()
                for v in r.headers.get_all("Set-Cookie") or []:     # sent explicitly: the cookie may be Secure-only
                    if v.startswith("n8n-auth="):
                        self.cookie = v.split(";", 1)[0]
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:400]
            raise RuntimeError(f"{method} {path}: HTTP {e.code} {detail}") from None

    # ---------------------------------------------------------------- API key (internal REST API, your login)
    def owner_setup(self, email, password):
        try:
            self.call("POST", "/rest/owner/setup", {"email": email, "firstName": "Lab", "lastName": "Owner", "password": password},
                      auth="none")
            return True
        except RuntimeError as e:
            if "already" in str(e).lower():
                return False
            raise

    def login(self, email, password):
        self.call("POST", "/rest/login", {"emailOrLdapLoginId": email, "password": password}, auth="none")
        if not self.cookie:
            raise RuntimeError("n8n answered the login without a session cookie")

    def delete_api_keys(self, label):
        data = self.call("GET", "/rest/api-keys", auth="session").get("data") or {}
        for k in (data.get("items") if isinstance(data, dict) else data) or []:
            if k.get("label") == label:
                self.call("DELETE", f"/rest/api-keys/{k['id']}", auth="session")

    def create_api_key(self, label, scopes=None):
        """A new key (replacing earlier ones with this label); scopes default to everything the login may grant."""
        self.delete_api_keys(label)
        allowed = self.call("GET", "/rest/api-keys/scopes", auth="session").get("data") or []
        scopes = [s for s in (scopes or allowed) if s in allowed]
        made = self.call("POST", "/rest/api-keys", {"label": label, "scopes": scopes, "expiresAt": None}, auth="session")
        return (made.get("data") or made)["rawApiKey"]

    # ---------------------------------------------------------------- public API
    def list_all(self, path):
        items, cursor = [], None
        while True:
            q = "?limit=100" + (f"&cursor={urllib.parse.quote(cursor)}" if cursor else "")
            page = self.call("GET", path + q)
            items += page.get("data") or []
            cursor = page.get("nextCursor")
            if not cursor:
                return items

    def credential_data(self, ctype, values):
        """Only the fields the credential type knows, plus defaults for required ones we don't set."""
        schema = self.call("GET", f"/api/v1/credentials/schema/{ctype}")
        props = schema.get("properties") or {}
        data = {k: v for k, v in values.items() if k in props}
        for k in schema.get("required") or []:
            if k not in data:
                t = (props.get(k) or {}).get("type")
                data[k] = False if t == "boolean" else ("" if t == "string" else data.get(k))
        return data

    def upsert_credential(self, name, ctype, values):
        data = self.credential_data(ctype, values)
        existing = next((c for c in self.list_all("/api/v1/credentials") if c.get("name") == name and c.get("type") == ctype), None)
        if existing:
            self.call("PATCH", f"/api/v1/credentials/{existing['id']}", {"name": name, "type": ctype, "data": data})
            return existing["id"], "updated"
        made = self.call("POST", "/api/v1/credentials", {"name": name, "type": ctype, "data": data})
        return made["id"], "created"

    def upsert_workflow(self, wf):
        body = {k: wf[k] for k in WORKFLOW_FIELDS if k in wf}
        found = [w for w in self.list_all("/api/v1/workflows") if w.get("name") == wf["name"]]
        if found:
            wid = found[0]["id"]
            self.call("PUT", f"/api/v1/workflows/{wid}", body)
            how = "updated"
        else:
            wid = self.call("POST", "/api/v1/workflows", body)["id"]
            how = "created"
        self.call("POST", f"/api/v1/workflows/{wid}/publish", {})
        return wid, how


def with_credentials(wf, ids):
    """The workflow with each model / store / webhook node pointing at the lab's credentials."""
    wf = json.loads(json.dumps(wf))
    for n in wf["nodes"]:
        key = NODE_CREDS.get(n["type"])
        if key:
            name, ctype = CREDS[key]
            n["credentials"] = {ctype: {"id": ids[key], "name": name}}
    return wf


def secret_manifest(namespace, webhook_secret, api_key):
    return json.dumps({"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
                       "metadata": {"name": "copilot", "namespace": namespace, "labels": {"app": "console"}},
                       "stringData": {"webhook-secret": webhook_secret, "n8n-api-key": api_key}}, indent=2)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--n8n", default="http://127.0.0.1:5678", help="n8n's base URL (a port-forward)")
    ap.add_argument("--email", help="your n8n login (to create the API key)")
    ap.add_argument("--password", help="default: N8N_PASSWORD, else asked")
    ap.add_argument("--setup-owner", action="store_true", help="a fresh n8n: create the owner account with --email/--password first")
    ap.add_argument("--api-key", help="use this n8n API key instead of creating one (Settings > n8n API)")
    ap.add_argument("--operator-url", default="http://glm-serve.lab.svc:8000/v1", help="OpenAI-compatible base URL of the operator model")
    ap.add_argument("--ollama-url", default="http://ollama.lab-copilot.svc:11434", help="Ollama for the judge and the embeddings")
    ap.add_argument("--qdrant-url", default="http://qdrant.lab-copilot.svc:6333")
    ap.add_argument("--webhook-secret", help="default: keep the one in --secret-file / a new random one")
    ap.add_argument("--workflow", default=WORKFLOW)
    ap.add_argument("--namespace", default="lab", help="the console's namespace (for the Secret)")
    ap.add_argument("--apply-secret", action="store_true", help="apply the console's Secret with kubectl (Kubernetes)")
    ap.add_argument("--secret-file", help="write the console's Secret (JSON manifest) here instead")
    a = ap.parse_args(argv)

    n8n = N8n(a.n8n)
    if a.api_key:
        n8n.api_key = console_key = a.api_key
    else:
        if not a.email:
            ap.error("--email is needed to create the API keys (or pass --api-key)")
        password = a.password or os.environ.get("N8N_PASSWORD") or getpass.getpass("n8n password: ")
        if a.setup_owner and n8n.owner_setup(a.email, password):
            print("owner account created")
        n8n.login(a.email, password)
        n8n.api_key = n8n.create_api_key(SETUP_LABEL)
        console_key = n8n.create_api_key(KEY_LABEL, CONSOLE_SCOPES)
        print(f'API key "{KEY_LABEL}" created (scopes: {", ".join(CONSOLE_SCOPES)})')

    webhook_secret = a.webhook_secret or secrets.token_urlsafe(32)
    values = {
        "operator": {"apiKey": "unused", "url": a.operator_url, "header": False},
        "ollama": {"baseUrl": a.ollama_url},
        "qdrant": {"qdrantUrl": a.qdrant_url},
        "webhook": {"name": "X-Lab-Secret", "value": webhook_secret},
    }
    ids = {}
    for key, (name, ctype) in CREDS.items():
        ids[key], how = n8n.upsert_credential(name, ctype, values[key])
        print(f"credential {how}: {name}")

    with open(a.workflow, encoding="utf-8") as f:
        wf = with_credentials(json.load(f), ids)
    wid, how = n8n.upsert_workflow(wf)
    print(f"workflow {how} and published: {wf['name']} (id {wid}); the console posts to /webhook/copilot-run")

    if not a.api_key:
        n8n.delete_api_keys(SETUP_LABEL)
        print("temporary setup key deleted")
    manifest = secret_manifest(a.namespace, webhook_secret, console_key)
    if a.secret_file:
        fd = os.open(a.secret_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(manifest + "\n")
        print(f"console Secret written to {a.secret_file}: kubectl apply -f {a.secret_file}")
    if a.apply_secret:
        r = subprocess.run(["kubectl", "apply", "-f", "-"], input=manifest, text=True, capture_output=True)
        if r.returncode:
            sys.exit(f"kubectl apply failed: {r.stderr.strip()}")
        print(f"console Secret applied: {a.namespace}/copilot")
    if not (a.apply_secret or a.secret_file):
        print("console Secret not written (no --apply-secret / --secret-file): fine for the compose stack, whose console does not start runs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
