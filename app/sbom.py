"""SBOM (CycloneDX 1.5) + vulnerability scan for the pipeline: every package in .venv and .venv-gguf (PyPI advisory
data / OSV), the non-PyPI parts (Ollama, llama.cpp, NVIDIA driver), the base model and the datasets, and the project's
own Python modules with the third-party packages they import. Ported from notebook cell 1.6 and extended."""
import ast
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from abliterate import platform as PL  # noqa: E402

INVENTORY_SCRIPT = r'''
import json, importlib.metadata as md
out = []
for d in md.distributions():
    m = d.metadata
    name = m.get("Name")
    if not name:
        continue
    lic = m.get("License-Expression") or m.get("License") or ""
    if not lic or len(lic) > 80:
        cls = [c.split("::")[-1].strip() for c in (m.get_all("Classifier") or []) if c.startswith("License ::")]
        lic = ", ".join(cls) if cls else (lic[:80] if lic else "")
    out.append({"name": name, "version": d.version, "license": lic, "summary": (m.get("Summary") or "")[:120],
                "homepage": m.get("Home-page") or next((u.split(",", 1)[-1].strip() for u in (m.get_all("Project-URL") or []) if "," in u), ""),
                "top_level": (d.read_text("top_level.txt") or "").split()})
print(json.dumps(sorted(out, key=lambda x: x["name"].lower())))
'''
MIN_OLLAMA = (0, 17, 6)   # CVE-2026-7482 (<0.17.1), CVE-2026-42248/42249 (Windows updater up to 0.17.5)
STDLIB = set(sys.stdlib_module_names) if hasattr(sys, "stdlib_module_names") else set()


def inventory(python_exe):
    r = subprocess.run([python_exe, "-c", INVENTORY_SCRIPT], capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0:
        raise RuntimeError(f"inventory failed for {python_exe}: {r.stderr[-400:]}")
    return json.loads(r.stdout)


def pypi_vulns(name, version, timeout=20):
    try:
        with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/{version}/json", timeout=timeout) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return None if e.code == 404 else {"error": f"HTTP {e.code}"}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {e}"}
    seen, vulns = set(), []
    for v in data.get("vulnerabilities") or []:
        ids = {v.get("id")} | set(v.get("aliases") or [])
        if seen & ids:
            continue
        seen |= ids
        cve = next((a for a in sorted(ids) if a and a.startswith("CVE-")), v.get("id"))
        summ = (v.get("summary") or v.get("details") or "").strip().splitlines()
        vulns.append({"id": cve, "advisory": v.get("id"), "fixed_in": v.get("fixed_in") or [], "summary": summ[0][:160] if summ else ""})
    return {"vulns": vulns}


def tool_version(cmd, rx=r"(\d+)\.(\d+)\.(\d+)"):
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30)
        m = re.search(rx, out.stdout + out.stderr)
        return tuple(int(x) for x in m.groups()) if m else None
    except Exception:
        return None


def project_imports(project):
    """The project's own modules (abliterate/, app/, run_pipeline.py, build_gui.py) and the third-party top-level names they import."""
    mods = []
    for root in ("abliterate", "app", "."):
        d = os.path.join(project, root)
        for fn in sorted(os.listdir(d)) if os.path.isdir(d) else []:
            if not fn.endswith(".py") or (root == "." and fn not in ("run_pipeline.py", "build_gui.py")):
                continue
            path = os.path.join(d, fn)
            try:
                tree = ast.parse(open(path, encoding="utf-8").read())
            except SyntaxError:
                continue
            names = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names |= {a.name.split(".")[0] for a in node.names}
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    names.add(node.module.split(".")[0])
            local = {"abliterate", "app"} | ({"rundata", "lab", "sbom", "datasets", "server"} if root == "app" else set())
            third = sorted(n for n in names if n not in STDLIB and n not in local)
            mods.append({"path": os.path.relpath(path, project).replace(os.sep, "/"), "imports": third,
                         "lines": sum(1 for _ in open(path, encoding="utf-8"))})
    return mods


class SbomJob:
    def __init__(self, project):
        self.project = project
        self.dir = os.path.join(project, "sbom")
        self.running = False
        self.progress = ""
        self.error = None
        self.last = None

    def latest(self):
        if not os.path.isdir(self.dir):
            return None
        files = sorted(f for f in os.listdir(self.dir) if f.startswith("sbom-") and f.endswith(".cdx.json"))
        if not files:
            return None
        path = os.path.join(self.dir, files[-1])
        bom = json.load(open(path, encoding="utf-8"))
        summ_p = os.path.join(self.dir, files[-1].replace("sbom-", "summary-").replace(".cdx.json", ".json"))
        summary = json.load(open(summ_p, encoding="utf-8")) if os.path.isfile(summ_p) else None
        return {"file": files[-1], "path": path, "generated": bom.get("metadata", {}).get("timestamp"),
                "n_components": len(bom.get("components", [])), "n_vulnerabilities": len(bom.get("vulnerabilities", [])),
                "summary": summary, "all_files": files}

    def status(self):
        return {"running": self.running, "progress": self.progress, "error": self.error, "latest": self.latest()}

    def start(self):
        if self.running:
            return self.status()
        self.running, self.error, self.progress = True, None, "starting"
        threading.Thread(target=self._run, daemon=True).start()
        return self.status()

    def _run(self):
        try:
            self.generate()
        except Exception as e:
            self.error = f"{type(e).__name__}: {e}"
        finally:
            self.running = False

    def generate(self):
        p = lambda *a: os.path.join(self.project, *a)
        envs_py = {"main": PL.pipeline_python(self.project), "gguf-converter": PL.gguf_python(self.project)}
        envs, flat = {}, []
        for name, py in envs_py.items():
            if not os.path.isfile(py):
                continue
            self.progress = f"inventory {name}"
            pkgs = inventory(py)
            self.progress = f"scanning {len(pkgs)} packages of {name} against PyPI advisories"
            with ThreadPoolExecutor(16) as ex:
                res = list(ex.map(lambda x: pypi_vulns(x["name"], x["version"]), pkgs))
            for pk, r in zip(pkgs, res):
                pk["vuln_scan"] = r
                pk["env"] = name
            envs[name] = pkgs
            flat += pkgs
        self.progress = "project modules + non-PyPI components"
        mods = project_imports(self.project)
        # map imports to packages via top_level.txt of the .venv inventory
        top = {}
        for pk in envs.get("main", []):
            for t in pk.get("top_level") or [pk["name"].lower().replace("-", "_")]:
                top.setdefault(t, pk)
        for m in mods:
            m["packages"] = sorted({top[i]["name"] + "==" + top[i]["version"] for i in m["imports"] if i in top})
            m["unresolved"] = [i for i in m["imports"] if i not in top]
        comps = []
        for env_name, pkgs in envs.items():
            for pk in pkgs:
                c = {"type": "library", "name": pk["name"], "version": pk["version"], "purl": f"pkg:pypi/{pk['name'].lower().replace('_', '-')}@{pk['version']}",
                     "bom-ref": f"{env_name}:{pk['name']}@{pk['version']}", "properties": [{"name": "environment", "value": env_name}]}
                if pk.get("license"):
                    c["licenses"] = [{"license": {"name": pk["license"]}}]
                if pk.get("homepage"):
                    c["externalReferences"] = [{"type": "website", "url": pk["homepage"]}]
                comps.append(c)
        for m in mods:
            comps.append({"type": "application", "name": m["path"], "version": "git", "bom-ref": "project:" + m["path"],
                          "properties": [{"name": "imports", "value": ", ".join(m["imports"])}, {"name": "lines", "value": str(m["lines"])}]})
        extra, notes = [], []
        ollama = None
        try:
            with urllib.request.urlopen(PL.ollama_host() + "/api/version", timeout=5) as r:
                m = re.search(r"(\d+)\.(\d+)\.(\d+)", json.loads(r.read()).get("version", ""))
                ollama = tuple(int(x) for x in m.groups()) if m else None
        except Exception:
            exe = PL.ollama_exe()
            ollama = tool_version([exe, "--version"]) if exe else None
        if ollama:
            ok = ollama >= MIN_OLLAMA
            extra.append({"type": "application", "name": "ollama", "version": ".".join(map(str, ollama)), "purl": f"pkg:github/ollama/ollama@v{'.'.join(map(str, ollama))}"})
            notes.append(f"Ollama {'.'.join(map(str, ollama))}: {'OK' if ok else 'UPDATE NEEDED (>= 0.17.6)'}")
        if os.path.isdir(os.path.join(PL.llama_cpp_dir(self.project), ".git")):
            rev = subprocess.run(["git", "-C", PL.llama_cpp_dir(self.project), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
            extra.append({"type": "library", "name": "llama.cpp", "version": rev[:12], "purl": f"pkg:github/ggml-org/llama.cpp@{rev}"})
            notes.append(f"llama.cpp {rev[:12]} (Python converter only; it does not parse untrusted GGUF)")
        cv = PL.driver_cuda_version()
        if cv:
            extra.append({"type": "platform", "name": "nvidia-driver-cuda", "version": cv})
        models_dir = p("models")
        if os.path.isdir(models_dir):
            for slug in sorted(os.listdir(models_dir)):
                info_p = os.path.join(models_dir, slug, "local_copy.json")
                info = json.load(open(info_p, encoding="utf-8")) if os.path.isfile(info_p) else {}
                extra.append({"type": "machine-learning-model", "name": info.get("repo", slug), "version": (info.get("revision") or "")[:12] or "local",
                              "purl": f"pkg:huggingface/{info.get('repo', slug)}" + (f"@{info['revision']}" if info.get("revision") else "")})
        man_p = p("data", "manifest.json")
        manifest = json.load(open(man_p, encoding="utf-8")) if os.path.isfile(man_p) else {}
        for fname, mm in manifest.items():
            extra.append({"type": "data", "name": mm["repo"], "version": mm["revision"][:12], "purl": f"pkg:huggingface/datasets/{mm['repo']}@{mm['revision']}",
                          "hashes": [{"alg": "SHA-256", "content": mm["sha256"]}], "properties": [{"name": "file", "value": fname}, {"name": "rows", "value": str(mm["rows"])}]})
        vulns = []
        for pk in flat:
            for v in (pk.get("vuln_scan") or {}).get("vulns") or []:
                vulns.append({"id": v["id"], "source": {"name": "PyPI advisory (OSV)"}, "description": v["summary"],
                              "recommendation": ("upgrade to " + ", ".join(v["fixed_in"])) if v["fixed_in"] else "no fixed version listed",
                              "affects": [{"ref": f"{pk['env']}:{pk['name']}@{pk['version']}"}]})
        bom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
               "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                            "component": {"type": "application", "name": "abliteration-lab", "version": "1.0"}},
               "components": comps + extra, "vulnerabilities": vulns}
        os.makedirs(self.dir, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        with open(os.path.join(self.dir, f"sbom-{stamp}.cdx.json"), "w", encoding="utf-8") as f:
            json.dump(bom, f, indent=2)
        summary = {
            "generated": bom["metadata"]["timestamp"], "notes": notes,
            "envs": {name: {"packages": len(pkgs), "vulnerable": sum(1 for x in pkgs if (x.get("vuln_scan") or {}).get("vulns")),
                            "unchecked": sum(1 for x in pkgs if (x.get("vuln_scan") or {}).get("error"))} for name, pkgs in envs.items()},
            "packages": [{"env": x["env"], "name": x["name"], "version": x["version"], "license": x["license"], "summary": x["summary"],
                          "vulns": (x.get("vuln_scan") or {}).get("vulns") or [], "error": (x.get("vuln_scan") or {}).get("error")} for x in flat],
            "project_modules": mods, "extra": extra,
        }
        with open(os.path.join(self.dir, f"summary-{stamp}.json"), "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        self.progress = "done"
        self.last = summary
        return summary
