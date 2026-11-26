"""The console's tests that need node run in CI's n8n step (.github/workflows/k8s-e2e.yml).

CI runs app/tests inside the console image, which has no node, so every test there that is skipped without node
(@unittest.skipUnless(NODE, ...): the hints read names as policy.js does, the saved engagement through the real gate, the
GUI's own app.js) passes by skipping. The n8n step has node and the checkout; this checks that its command selects each
of them, so a new one is not silently left out.

    python -m unittest discover -s deploy/n8n
"""
import glob
import os
import re
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
CI = os.path.join(ROOT, ".github", "workflows", "k8s-e2e.yml")


def node_tests():
    """(module, test name) for every app test skipped without node."""
    out = []
    for path in sorted(glob.glob(os.path.join(ROOT, "app", "tests", "test_*.py"))):
        with open(path, encoding="utf-8") as f:
            src = f.read()
        mod = os.path.splitext(os.path.basename(path))[0]
        out += [(mod, name) for name in re.findall(r"@unittest\.skipUnless\(NODE\b[^\n]*\n\s*def (test_\w+)", src)]
    return out


class NodeTestsInCI(unittest.TestCase):
    def test_every_node_test_of_the_console_runs_in_the_n8n_step(self):
        with open(CI, encoding="utf-8") as f:
            ci = f.read()
        runs = re.findall(r"python3 -m unittest\b([^\n)]*)", ci)
        selected = []                                  # (modules, -k patterns) of each command that names app test modules
        for args in runs:
            words = args.split()
            ks = [words[i + 1] for i, w in enumerate(words[:-1]) if w == "-k"]
            mods = [w for i, w in enumerate(words) if re.fullmatch(r"test_\w+", w) and (i == 0 or words[i - 1] != "-k")]
            if mods:
                selected.append((mods, ks))
        tests = node_tests()
        self.assertGreaterEqual(len(tests), 5)
        missing = [f"{mod}.{name}" for mod, name in tests
                   if not any(mod in mods and (not ks or any(k in name for k in ks)) for mods, ks in selected)]
        self.assertEqual(missing, [], "add them to the n8n step's unittest command in .github/workflows/k8s-e2e.yml")


if __name__ == "__main__":
    unittest.main()
