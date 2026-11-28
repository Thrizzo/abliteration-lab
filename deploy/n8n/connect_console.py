"""Connects n8n to the lab console: one run sets up everything the console's copilot runs need. Re-running is safe.

  1. an n8n API key for the console that may only read and stop executions (created through your n8n login; a
     temporary setup key does the rest and is deleted at the end). With --api-key, that key is used for both;
  2. the copilot's credentials: the operator (OpenAI-compatible: glm-serve), Ollama (judge, embeddings), Qdrant, and
     the console's webhook secret (Header Auth, X-Lab-Secret);
  3. the workflow (deploy/n8n/workflows/pentest-copilot.json) with those credentials selected, published;
  4. the console's Secret "copilot" (webhook-secret, n8n-api-key), applied with kubectl or written to a file; for the
     Docker stack, the same two values as files in a folder (--secrets-dir workspace/.copilot), which its console reads
     as COPILOT_SECRETS_DIR. The console reads them on every use, so no restart is needed (in Kubernetes the mounted
     Secret can take a minute to appear).

Reach n8n through a port-forward first:
    kubectl -n lab-copilot port-forward svc/n8n 5678:5678
    python deploy/n8n/connect_console.py --email you@example.com --apply-secret
The password is asked for (or N8N_PASSWORD). Standard library only; works on Windows, macOS and Linux.
With --setup-owner on a fresh n8n, the login is checked against n8n's rules for its owner account first (8 to 64
characters with a digit 0-9 and a capital letter A-Z; an e-mail address both its owner setup and its login take), so
nothing is created with a login n8n would refuse.
"""
import argparse
import getpass
import http.client
import json
import os
import re
import secrets
import subprocess
import sys
import time
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

# What n8n refuses for its owner account (2.48.7): the owner setup's schema (@n8n/api-types OwnerSetupRequestDto, zod 3)
# and, for the e-mail, the login that follows it (class-validator isEmail). owner_rule_cases.json holds answers taken
# from n8n's own code; rancher-dev.ps1 checks the same.
PASSWORD_MAX = 64
EMAIL_RULE = re.compile(r"(?!\.)(?!.*\.\.)[A-Za-z0-9_'+\-.]*[A-Za-z0-9_+-]@([A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}")


def password_problem(password, min_length=8):
    """What a new account's password lacks for n8n, '' if nothing: min_length (8, or N8N_PASSWORD_MIN_LENGTH) to 64
    characters, a digit and a capital letter, as JavaScript reads them (/\\d/ is 0-9 only, /[A-Z]/ is A-Z only, so an
    umlaut is no capital here; the length is in UTF-16 units, a lone surrogate counting as one)."""
    n = len(password.encode("utf-16-le", "surrogatepass")) // 2
    missing = []
    if not min_length <= n <= PASSWORD_MAX:
        missing.append(f"{min_length} to {PASSWORD_MAX} characters (it has {n})")
    if not re.search("[0-9]", password):
        missing.append("a digit 0-9")
    if not re.search("[A-Z]", password):
        missing.append("a capital letter A-Z")
    return ", ".join(missing)


def email_ok(email):
    """An address n8n takes for its owner: zod's rule, which the owner setup applies (its /.../i: A-Z there means A-Z and
    a-z, nothing else), and what the login after it adds (class-validator isEmail): at most 254 characters, at most 64
    before the @, and domain labels of at most 63 that do not end in '-'. An owner created with an address only the
    owner setup takes could never log in."""
    email = email or ""
    if EMAIL_RULE.fullmatch(email) is None or len(email) > 254:
        return False
    local, _, domain = email.rpartition("@")
    return len(local) <= 64 and all(len(label) <= 63 and not label.endswith("-") for label in domain.split("."))


def owner_problem(email, password, min_length=8):
    """What n8n would refuse in a new owner account, '' if nothing."""
    problems = [] if email_ok(email) else ["the e-mail is not an address n8n takes (name@domain.tld)"]
    missing = password_problem(password, min_length)
    if missing:
        problems.append(f"the password needs {missing}")
    return "; ".join(problems)


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
        raw = b""
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
        except (OSError, http.client.HTTPException) as e:      # refused, reset, timed out, a dropped port-forward
            why = e.reason if isinstance(getattr(e, "reason", None), BaseException) else e   # urllib wraps the socket's error
            raise RuntimeError(f"{method} {path}: no answer from n8n at {self.base} ({type(why).__name__}: {why})") from None
        except ValueError:
            raise RuntimeError(f"{method} {path}: n8n answered something other than JSON: {raw[:200]!r}") from None

    def wait_ready(self, timeout=300, every=2.0, log=print):
        """Until n8n can serve its REST API, which GET /healthz/readiness answers with 200. /healthz and even /rest/settings
        are no proof: while n8n migrates its database it answers every request with 200 "n8n is starting up", and its
        routes come after that (a request in between gets a plain 404). An n8n without the readiness endpoint (404)
        counts as ready once /rest/settings answers with its JSON."""
        t0, said = time.time(), False
        while True:
            status, _ = self._probe("/healthz/readiness")
            if status == 200:
                return
            if status == 404:
                s2, body = self._probe("/rest/settings")
                if s2 == 200 and body.lstrip().startswith("{"):
                    return
            if time.time() - t0 > timeout:
                raise RuntimeError(f"n8n at {self.base} was not ready after {timeout} s (GET /healthz/readiness: {status})")
            if not said:
                log(f"waiting for n8n to finish starting (GET /healthz/readiness: {status})")
                said = True
            time.sleep(every)

    def _probe(self, path):
        try:
            with urllib.request.urlopen(urllib.request.Request(self.base + path, headers={"Accept": "application/json"}),
                                        timeout=10) as r:
                return r.status, r.read(200).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, ""
        except OSError as e:
            return f"unreachable, {type(e).__name__}", ""

    # ---------------------------------------------------------------- API key (internal REST API, your login)
    def owner_rule(self):
        """From n8n's public settings: (True while it has no owner account yet, False once it has one, None when they
        do not say; the minimum password length they report, the one n8n's own setup page uses)."""
        try:
            um = self.call("GET", "/rest/settings", auth="none")["data"]["userManagement"]
            fresh, min_length = um.get("showSetupOnFirstLoad"), max(8, int(um.get("passwordMinLength") or 8))
        except (RuntimeError, ValueError, TypeError, KeyError, AttributeError):
            return None, 8
        return (fresh if isinstance(fresh, bool) else None), min_length

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


def write_secrets_dir(path, webhook_secret, api_key):
    """The console's two secrets as files in path, named as the Kubernetes Secret mounts them (webhook-secret,
    n8n-api-key): the Docker stack's console reads them there (COPILOT_SECRETS_DIR). Each file is replaced whole."""
    os.makedirs(path, exist_ok=True)
    for name, value in (("webhook-secret", webhook_secret), ("n8n-api-key", api_key)):
        tmp = os.path.join(path, f".{name}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(value)
        os.replace(tmp, os.path.join(path, name))


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
    ap.add_argument("--secrets-dir", help="the Docker stack: write the console's two secrets as files into this folder "
                                          "(workspace/.copilot, which the console reads as COPILOT_SECRETS_DIR)")
    ap.add_argument("--wait", type=int, default=300, help="seconds to wait for n8n to finish starting (default 300)")
    a = ap.parse_args(argv)

    n8n = N8n(a.n8n)
    n8n.wait_ready(a.wait)
    if a.api_key:
        n8n.api_key = console_key = a.api_key
    else:
        if not a.email:
            ap.error("--email is needed to create the API keys (or pass --api-key)")
        password = a.password or os.environ.get("N8N_PASSWORD") or getpass.getpass("n8n password: ")
        if a.setup_owner:
            # n8n checks a password's form before it looks for an owner: an n8n that has one would answer a short
            # password with "8 to 64 characters", not with a wrong login. So only a fresh n8n (or one whose settings
            # do not say) gets the owner setup, and only with a login it takes.
            fresh, min_length = n8n.owner_rule()
            problem = owner_problem(a.email, password, min_length) if fresh else ""
            if problem:
                raise SystemExit(f"connect_console.py: n8n has no owner account yet and would refuse this one: {problem}. "
                                 "Nothing was created; run it again with that fixed.")
            if fresh is not False and n8n.owner_setup(a.email, password):
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
    if a.secrets_dir:
        write_secrets_dir(a.secrets_dir, webhook_secret, console_key)
        print(f"console secrets written to {a.secrets_dir} (webhook-secret, n8n-api-key): step 4 of the console can start runs")
    if not (a.apply_secret or a.secret_file or a.secrets_dir):
        print("console secrets not written (no --apply-secret / --secret-file / --secrets-dir): the console cannot start copilot "
              "runs, n8n's own form can (Docker stack: --secrets-dir workspace/.copilot)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as e:          # it names the request and n8n's answer; a traceback adds nothing
        sys.exit(f"connect_console.py: {e}")
