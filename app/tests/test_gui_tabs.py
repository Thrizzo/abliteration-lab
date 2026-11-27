"""The console's steps (app/static): tab 4 Pentest holds what the copilot panel held.

The header's steps are 1 Model, 2 Abliterate, 3 Compare and 4 Pentest (data-stage="pentest", shown by app.js in the
Kubernetes console only), tabs a keyboard reaches. section#s-pentest, a step in main like the other three, holds the
copilot's cards (models, engagement, the run, the live feed) under the ids app.js reads. The copilot's header button and
panel are gone from the page, the script and the styles, and app.js still parses (node --check, where node is installed).
Where node is installed, app.js's own step and tab 4 code also runs on a stand-in page: one feed poller on tab 4 and none
after it, a run asked for just before leaving shown again on return, a late feed answer not shown twice, a step click
closing only the panels that are open, Back and Forward, the gate and the subtitle.

    python -m unittest discover -s app/tests
"""
import json
import os
import re
import shutil
import subprocess
import unittest
from html.parser import HTMLParser

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(HERE, "..", "static")
NODE = shutil.which("node")


def read(name):
    with open(os.path.join(STATIC, name), encoding="utf-8") as f:
        return f.read()


class Page(HTMLParser):
    """Every element of the page with its attributes and its ancestors; void elements hold nothing."""
    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}

    def __init__(self, html):
        super().__init__()
        self.stack, self.elements = [], []
        self.feed(html)
        self.close()

    def handle_starttag(self, tag, attrs):
        el = {"tag": tag, "attrs": dict(attrs), "ancestors": list(self.stack)}
        self.elements.append(el)
        if tag not in self.VOID:
            self.stack.append(el)

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i]["tag"] == tag:
                del self.stack[i:]
                return


def classes(el):
    return (el["attrs"].get("class") or "").split()


class PentestTab(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html, cls.js, cls.css = read("index.html"), read("app.js"), read("style.css")
        cls.page = Page(cls.html)
        cls.ids = {}
        for el in cls.page.elements:
            if "id" in el["attrs"]:
                cls.ids.setdefault(el["attrs"]["id"], []).append(el)

    def one(self, id_):
        self.assertEqual(len(self.ids.get(id_, [])), 1, f"#{id_} once in index.html")
        return self.ids[id_][0]

    def test_gui_the_fourth_step_is_pentest(self):
        steps = [el for el in self.page.elements
                 if el["tag"] == "li" and any(a["tag"] == "ol" and "stages" in classes(a) for a in el["ancestors"])]
        self.assertEqual([s["attrs"].get("data-stage") for s in steps], ["model", "abl", "compare", "pentest"])
        li = re.search(r'<li data-stage="pentest"[^>]*>(.*?)</li>', self.html).group(1)
        self.assertIn('<span class="n">4</span>', li)
        self.assertIn("<b>Pentest</b>", li)
        self.assertIn('<small id="stPentest">', li)                  # its subtitle: the engagement it works with
        self.assertIn("display:none", steps[3]["attrs"].get("style", ""))   # until the Kubernetes console's GET /api/copilot answers
        # tabs the keyboard reaches (Enter or Space opens one: app.js), in a tablist
        ol = next(a for a in steps[0]["ancestors"] if a["tag"] == "ol")
        self.assertEqual(ol["attrs"].get("role"), "tablist")
        for s in steps:
            self.assertEqual((s["attrs"].get("role"), s["attrs"].get("tabindex")), ("tab", "0"), s["attrs"].get("data-stage"))

    def test_gui_the_pentest_step_holds_the_copilot(self):
        sec = self.one("s-pentest")
        self.assertEqual(sec["tag"], "section")
        self.assertIn("stage", classes(sec))
        self.assertTrue(any(a["tag"] == "main" and "wizmain" in classes(a) for a in sec["ancestors"]), "a step in main")
        for id_ in ("cpModelsCard", "cpEngCard", "cpRunCard", "cpFeed"):
            self.assertIn(sec, self.one(id_)["ancestors"], f"#{id_} in tab 4")
        # every copilot and engagement element app.js reads, other than those it writes itself, is in tab 4: same ids
        read_ = set(re.findall(r"\$\('#((?:cp|eng)\w+)'\)", self.js))
        written = set(re.findall(r'id="(\w+)"', self.js))
        self.assertGreater(len(read_ - written), 40)
        for id_ in sorted(read_ - written):
            self.assertIn(sec, self.one(id_)["ancestors"], f"#{id_} in tab 4")

    def test_gui_no_copilot_panel_or_button_is_left(self):
        for name, text in (("index.html", self.html), ("app.js", self.js), ("style.css", self.css)):
            for gone in ("copilotToggle", "copilotPanel", "copilotClose"):
                self.assertFalse(gone in text, f"{gone} in {name}")
        panels = sorted(el["attrs"]["id"] for el in self.page.elements if el["tag"] == "section" and "panel" in classes(el))
        self.assertEqual(panels, ["dataPanel", "knowledgePanel", "sbomPanel", "servePanel"])
        self.assertIn("#s-pentest label.small{", self.css)             # the panel's own rules moved with it

    def test_gui_tab_4_is_checked_again_and_kept(self):
        js = self.js.replace("\r", "")

        def body(start):
            i = js.index(start)
            return js[i:js.index("\n}\n", i)]
        self.assertIn("cpGate();", body("async function loadEnv(){"))   # every /api/env answer checks tab 4's gate again
        # a model picked on step 1 moves on to step 2 only if step 1 is still shown when its runs have loaded
        self.assertIn("if(!silent && S.stage==='model') go('abl');", body("async function selectModel("))

    @unittest.skipUnless(NODE, "node not installed")
    def test_gui_scripts_parse(self):
        for name in ("app.js", "guide.js"):
            p = subprocess.run([NODE, "--check", os.path.join(STATIC, name)], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, f"{name}: {p.stderr}")


# app.js's own code for the steps (go, the tabs' click and key handlers, Back and Forward), tab 4's subtitle and its
# lifecycle (the run, the feed, entering and leaving, the gate), run with a stand-in $ and document, fake timers and an api
# whose answers the scenario releases in the order it wants. Prints what it saw as JSON.
STANDIN = r"""
const src = require('fs').readFileSync(__APP_JS__, 'utf8').replace(/\r/g, '');
const grab = (start, end) => { const i = src.indexOf(start), j = src.indexOf(end, i); if (i < 0 || j < 0) throw new Error('app.js: ' + start); return src.slice(i, j + end.length); };
const code = [grab('function go(stage){', "if(!showStage(h)) history.replaceState(null, '', '#'+S.stage);\n});"),
  grab('function cpTabInfo(){', '\n}'), grab('async function cpShowRun(id){', '}).catch(()=>false);')].join('\n');
const PARAMS = ['$', 'document', 'location', 'window', 'history', 'addEventListener', 'toast', 'S', 'CP', 'cmpReady', 'chatStatus', 'api',
  'cpRenderRun', 'cpModelsLoad', 'cpEngLoad', 'esc', 'escA', 'RUN_BADGE', 'evRow', 'cpSetMode', 'cpStore', 'envReady',
  'setInterval', 'clearInterval', 'setTimeout', 'clearTimeout'];
const flush = () => new Promise((r) => setImmediate(r));
function make() {
  const P = { calls: [], timers: new Map(), tid: 0, toasts: [], engLoads: 0, focused: null, cmp: false, onHash: null, replaced: [] };
  const el = (name) => ({ name, value: '', checked: false, textContent: '', innerHTML: '', disabled: false, style: {}, dataset: {}, onclick: null, clicks: 0,
    cls: new Set(), get classList() { const c = this.cls; return { toggle: (k, on) => ((on ?? !c.has(k)) ? c.add(k) : c.delete(k)), contains: (k) => c.has(k), add: (k) => c.add(k), remove: (k) => c.delete(k) }; },
    querySelectorAll: () => [], setAttribute(k, v) { this['@' + k] = v; }, focus() { P.focused = this; }, click() { this.clicks++; if (this.onclick) this.onclick(); } });
  const els = {};
  const $ = (sel) => els[sel] || (els[sel] = el(sel));
  const steps = ['model', 'abl', 'compare', 'pentest'];
  P.sections = steps.map((s) => Object.assign(el('#s-' + s), { id: 's-' + s }));
  P.tabs = steps.map((s) => Object.assign(el('li:' + s), { dataset: { stage: s } }));
  P.tabs[3].style.display = 'none';
  els['.stages li[data-stage=pentest]'] = P.tabs[3];
  for (const p of ['data', 'sbom', 'serve', 'knowledge']) { const panel = $('#' + p + 'Panel'); $('#' + p + 'Close').onclick = () => panel.classList.remove('open'); }
  P.body = el('body');
  const document = { querySelectorAll: (q) => (q === '.stage' ? P.sections : q === '.stages li' ? P.tabs : []), body: P.body };
  const location = { h: '', get hash() { return this.h; }, set hash(v) { this.h = v ? (String(v)[0] === '#' ? String(v) : '#' + v) : ''; } };
  const history = { replaceState: (a, b, u) => { P.replaced.push(u); location.hash = u; } };
  const api = (path) => new Promise((resolve, reject) => P.calls.push({ path, resolve, reject }));
  P.answer = async (re, body, fail) => { const i = P.calls.findIndex((c) => re.test(c.path)); if (i < 0) throw new Error('nothing asked for ' + re);
    const [c] = P.calls.splice(i, 1); fail ? c.reject(new Error(fail)) : c.resolve(body); await flush(); await flush(); return c.path; };
  P.asked = (re) => P.calls.filter((c) => re.test(c.path)).length;
  P.live = (ms) => [...P.timers.values()].filter((t) => t.ms === ms).length;
  const T = { setInterval: (fn, ms) => (P.timers.set(++P.tid, { fn, ms }), P.tid), setTimeout: (fn, ms) => (P.timers.set(++P.tid, { fn, ms }), P.tid),
    clear: (id) => P.timers.delete(id) };
  let envDone; const envReady = new Promise((r) => { envDone = r; });
  P.S = { stage: 'model', pentest: false, env: null, model: null };
  P.CP = { run: null, runId: null, runT: null, runSeq: 0, feedT: null, feedNext: 0, feed: [], conn: null, asked: false, eng: null };
  P.els = els; P.location = location; P.envDone = envDone;
  const args = [$, document, location, { scrollTo() {} }, history, (type, fn) => { if (type === 'hashchange') P.onHash = fn; }, (m) => { P.toasts.push(m); }, P.S, P.CP,
    () => P.cmp, () => {}, api, () => {}, () => {}, () => { P.engLoads++; }, (s) => String(s ?? ''), (s) => String(s ?? ''), {}, () => '', () => {},
    { get: (k, d) => d }, envReady, T.setInterval, T.clear, T.setTimeout, T.clear];
  P.f = new Function(...PARAMS, code + '; return { go, showStage, cpShowRun, cpFeedLoad, cpGate, cpTabInfo, cpReady };')(...args);
  return P;
}
const COPILOT = { configured: true, n8n: 'http://n8n:5678', runs: [], model: { configured: true } };
const NO_N8N = { configured: false, missing: ['N8N_URL'], n8n: null, runs: [], model: { configured: false } };
(async () => {
  const out = {};
  // the gate, Kubernetes console without an n8n address: the copilot answers, /api/env fails once (no runner), then
  // answers k8s on its next poll
  const P = make(), { S, CP, f } = P;
  await P.answer(/^\/copilot$/, NO_N8N);
  out.subtitleFirst = P.els['#stPentest'].textContent;
  P.envDone();
  out.readyWithoutEnv = await f.cpReady;
  out.hiddenWithoutEnv = P.tabs[3].style.display;
  S.env = { runner: 'k8s' }; out.gateLater = f.cpGate();
  out.shownLater = P.tabs[3].style.display; out.engLoadsAtGate = P.engLoads;
  // a plain console with N8N_URL shows tab 4 as soon as the copilot answers, before /api/env
  const N = make(); await N.answer(/^\/copilot$/, COPILOT);
  out.plainN8n = { early: N.S.pentest, shown: N.tabs[3].style.display }; N.S.env = { runner: 'local' }; N.envDone();
  out.plainN8n.ready = await N.f.cpReady; out.plainN8n.opens = N.f.go('pentest') === true;
  // a plain console without it never shows tab 4 and does not ask again
  const Q = make(); await Q.answer(/^\/copilot$/, NO_N8N); Q.S.env = { runner: 'local' }; Q.envDone();
  out.plain = { ready: await Q.f.cpReady, shown: Q.tabs[3].style.display, again: Q.f.cpGate(), asked: Q.calls.length, opens: Q.f.go('pentest') === true };
  // a copilot that did not answer the first time is asked again
  const R = make(); await R.answer(/^\/copilot$/, null, 'busy'); R.S.env = { runner: 'k8s' }; R.envDone();
  const r1 = await R.f.cpReady, again = R.asked(/^\/copilot$/); await R.answer(/^\/copilot$/, COPILOT);
  out.retry = { ready: r1, askedAgain: again, pentest: R.S.pentest, shown: R.tabs[3].style.display };
  // the same in a plain console: its copilot is asked again too, and an address then shows tab 4
  const R2 = make(); await R2.answer(/^\/copilot$/, null, 'busy'); R2.S.env = { runner: 'local' }; R2.envDone();
  const r2 = await R2.f.cpReady, again2 = R2.asked(/^\/copilot$/); await R2.answer(/^\/copilot$/, COPILOT);
  out.retryPlain = { ready: r2, askedAgain: again2, pentest: R2.S.pentest, shown: R2.tabs[3].style.display };
  // entering tab 4: one feed poller; leaving: none; 4-1-4 at once and a click on tab 4 while on it: still one
  out.enter = f.showStage('pentest');
  out.onTab4 = { feedPollers: P.live(1500), wide: P.els['main.wizmain'].classList.contains('wide'), header: P.body.classList.contains('pentest'), selected: P.tabs[3]['@aria-selected'], hash: P.location.hash };
  f.showStage('model');
  out.afterLeaving = { feedPollers: P.live(1500), header: P.body.classList.contains('pentest'), selected: P.tabs[3]['@aria-selected'] };
  f.go('pentest'); f.go('model'); f.go('pentest'); P.tabs[3].onclick();
  out.after414 = P.live(1500);
  // two feed requests from the same point (both entries): the first answer is shown, the late one adds nothing
  const ev = (n) => Array.from({ length: n }, (_, i) => ({ seq: i + 1, source: 'model', stage: 'chat', message: 'm' + (i + 1), ts: '' }));
  out.feedAsked = P.asked(/^\/feed\?after=0&/);
  await P.answer(/^\/feed\?after=0&/, { events: ev(2), next: 2 });
  await P.answer(/^\/feed\?after=0&/, { events: ev(3), next: 3 });
  out.feed = { seqs: CP.feed.map((e) => e.seq), next: CP.feedNext };
  await P.answer(/^\/feed\?after=0&/, { events: ev(3), next: 3 }).catch(() => {});
  // a run asked for, tab 4 left before it answers: no poller arms, and it is shown again on return
  f.cpShowRun('7');
  f.showStage('model');
  await P.answer(/^\/copilot\/runs\/7$/, { id: '7', status: 'running', events: [] });
  out.lateRun = { run: CP.run, runPollers: P.live(1000), runId: CP.runId };
  f.showStage('pentest');
  out.reasked = P.asked(/^\/copilot\/runs\/7$/);
  await P.answer(/^\/copilot\/runs\/7$/, { id: '7', status: 'running', events: [] });
  out.onReturn = { run: CP.run && CP.run.id, runPollers: P.live(1000) };
  f.showStage('model');
  out.runPollersAfterLeaving = P.live(1000);
  // a step click closes the panels that are open, through their close buttons, and only those; a locked step closes none
  P.els['#servePanel'].classList.add('open'); S.model = { slug: 'glm' };
  out.stepClick = f.showStage('abl');
  out.closes = Object.fromEntries(['data', 'sbom', 'serve', 'knowledge'].map((p) => [p, P.els['#' + p + 'Close'].clicks]));
  P.els['#dataPanel'].classList.add('open'); P.cmp = false;
  out.locked = { shown: f.showStage('compare'), dataOpen: P.els['#dataPanel'].classList.contains('open'), stage: S.stage, toast: P.toasts.slice(-1)[0] };
  P.els['#dataPanel'].classList.remove('open');
  // the keyboard: Enter on tab 4, the arrows between the steps shown
  P.tabs[3].onkeydown({ key: 'Enter', preventDefault() {} });
  out.enterKey = S.stage;
  P.tabs[0].onkeydown({ key: 'ArrowLeft', preventDefault() {} }); out.arrowLeftFrom1 = P.focused && P.focused.name;
  P.tabs[3].onkeydown({ key: 'ArrowRight', preventDefault() {} }); out.arrowRightFrom4 = P.focused && P.focused.name;
  // Back and Forward: a step the address names is shown; a locked one puts the shown step back in the address
  P.location.hash = '#model'; P.onHash(); out.backTo1 = { stage: S.stage, feedPollers: P.live(1500) };
  P.location.hash = '#pentest'; P.onHash(); out.forwardTo4 = { stage: S.stage, feedPollers: P.live(1500) };
  P.location.hash = '#compare'; P.onHash(); out.backToLocked = { stage: S.stage, hash: P.location.hash, replaced: P.replaced.slice(-1)[0] };
  P.location.hash = '#nonsense'; P.onHash(); out.unknownHash = S.stage;
  // the subtitle
  const sub = (conn, eng) => { CP.conn = conn; CP.eng = eng; f.cpTabInfo(); return P.els['#stPentest'].textContent; };
  out.subtitles = [sub({ configured: false }, null), sub(COPILOT, null), sub(COPILOT, { current: { version: 3, name: 'ACME internal pentest', active: true } }),
    sub(COPILOT, { current: { version: 4, name: 'paused', active: false } }), sub(COPILOT, { current: null }), sub({ configured: false }, { current: { version: 3, name: 'x' } })];
  console.log(JSON.stringify(out));
})().catch((e) => { console.error(e && e.stack || e); process.exit(1); });
"""


class PentestTabBehaviour(unittest.TestCase):
    @unittest.skipUnless(NODE, "node not installed")
    def test_gui_tab_4_pollers_runs_panels_and_gate(self):
        js = STANDIN.replace("__APP_JS__", json.dumps(os.path.join(STATIC, "app.js")))
        p = subprocess.run([NODE, "-e", js], capture_output=True, text=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr)
        got = json.loads(p.stdout)
        # the gate: a copilot without an n8n address is not enough on its own; in the Kubernetes console the next
        # /api/env answer opens tab 4 (which then says what is missing) and loads the engagement for its subtitle; a
        # plain console with N8N_URL opens it as soon as the copilot answers, one without never does; a copilot that
        # failed once is asked again, in either console
        self.assertEqual(got["subtitleFirst"], "n8n not connected")
        self.assertEqual((got["readyWithoutEnv"], got["hiddenWithoutEnv"]), (False, "none"))
        self.assertEqual((got["gateLater"], got["shownLater"], got["engLoadsAtGate"]), (True, "", 1))
        self.assertEqual(got["plainN8n"], {"early": True, "shown": "", "ready": True, "opens": True})
        self.assertEqual(got["plain"], {"ready": False, "shown": "none", "again": False, "asked": 0, "opens": False})
        self.assertEqual(got["retry"], {"ready": False, "askedAgain": 1, "pentest": True, "shown": ""})
        self.assertEqual(got["retryPlain"], {"ready": False, "askedAgain": 1, "pentest": True, "shown": ""})
        # one feed poller on tab 4, none after it, still one after 4-1-4 and a click on tab 4 while on it
        self.assertTrue(got["enter"])
        self.assertEqual(got["onTab4"], {"feedPollers": 1, "wide": True, "header": True, "selected": "true", "hash": "#pentest"})
        self.assertEqual(got["afterLeaving"], {"feedPollers": 0, "header": False, "selected": "false"})
        self.assertEqual(got["after414"], 1)
        # two feed requests from the same point: the events once
        self.assertEqual(got["feedAsked"], 3)
        self.assertEqual(got["feed"], {"seqs": [1, 2], "next": 2})
        # a run asked for just before leaving: its late answer arms no poller, and the run is shown again on return
        self.assertEqual(got["lateRun"], {"run": None, "runPollers": 0, "runId": "7"})
        self.assertEqual(got["reasked"], 1)
        self.assertEqual(got["onReturn"], {"run": "7", "runPollers": 1})
        self.assertEqual(got["runPollersAfterLeaving"], 0)
        # a step click closes only the open panel; a locked step shows its message and closes nothing
        self.assertTrue(got["stepClick"])
        self.assertEqual(got["closes"], {"data": 0, "sbom": 0, "serve": 1, "knowledge": 0})
        self.assertEqual(got["locked"], {"shown": False, "dataOpen": True, "stage": "abl", "toast": "finish an abliteration through Ollama first"})
        # the keyboard
        self.assertEqual(got["enterKey"], "pentest")
        self.assertEqual((got["arrowLeftFrom1"], got["arrowRightFrom4"]), ("li:pentest", "li:model"))
        # Back and Forward
        self.assertEqual(got["backTo1"], {"stage": "model", "feedPollers": 0})
        self.assertEqual(got["forwardTo4"], {"stage": "pentest", "feedPollers": 1})
        self.assertEqual(got["backToLocked"], {"stage": "pentest", "hash": "#pentest", "replaced": "#pentest"})
        self.assertEqual(got["unknownHash"], "pentest")
        # the subtitle
        self.assertEqual(got["subtitles"], ["n8n not connected", "copilot · engagement", "v3 · ACME internal pentest",
                                            "no engagement · LAB_ALLOWLIST", "no engagement · LAB_ALLOWLIST", "n8n not connected"])


if __name__ == "__main__":
    unittest.main()
