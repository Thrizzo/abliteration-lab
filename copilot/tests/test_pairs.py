"""Tests for copilot.pairs. Run: python -m unittest discover -s copilot/tests -t ."""
import json
import os
import tempfile
import unittest

from copilot.pairs import extract_commands, main

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "writeups")


def build(src, *extra):
    out = tempfile.mkdtemp()
    main(["--src", src, "--out", out, *extra])
    rows = {s: [json.loads(l) for l in open(os.path.join(out, s + ".jsonl"), encoding="utf-8")] for s in ("train", "eval")}
    return rows, json.load(open(os.path.join(out, "stats.json"), encoding="utf-8"))


class Pairs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rows, cls.stats = build(FIX)
        cls.all = cls.rows["train"] + cls.rows["eval"]

    def test_contract_shape(self):
        self.assertTrue(self.all)
        for r in self.all:
            roles = [m["role"] for m in r["messages"]]
            self.assertEqual(roles, ["system", "user", "assistant"])
            ans = json.loads(r["messages"][2]["content"])
            self.assertEqual(set(ans), {"command", "target", "rationale"})
            self.assertIn(f"TARGET (authorized, in scope): {ans['target']}", r["messages"][1]["content"])

    def test_network_steps_aim_at_their_target(self):
        for r in self.all:
            ans = json.loads(r["messages"][2]["content"])
            if any(t in ans["command"] for t in ("nmap", "smbclient", "gobuster", "curl", "crackmapexec", "evil-winrm")):
                self.assertIn(ans["target"], ans["command"], ans)

    def test_original_addresses_never_leak(self):
        blob = json.dumps(self.all)
        for leak in ("10.10.11.42", "lantern.htb", "10.20.30.", "acmecorp", "jdoe", "Sup3rS3cret"):
            self.assertNotIn(leak, blob)

    def test_pwk_excluded_by_default_and_opt_in(self):
        self.assertEqual(self.stats["excluded_sources"], ["pwk"])
        self.assertNotIn("pwk", self.stats["by_source"])
        rows, stats = build(FIX, "--include-pwk")
        self.assertIn("pwk", stats["by_source"])

    def test_split_is_by_document(self):
        tr = {r["meta"]["doc"] for r in self.rows["train"]}
        ev = {r["meta"]["doc"] for r in self.rows["eval"]}
        self.assertTrue(ev)
        self.assertFalse(tr & ev)

    def test_catastrophic_commands_dropped(self):
        with tempfile.TemporaryDirectory() as td:
            os.makedirs(os.path.join(td, "htb"))
            with open(os.path.join(td, "htb", "x.md"), "w", encoding="utf-8") as f:
                f.write("# X\n\nTarget 10.10.10.9.\n\n```bash\nnmap -sV 10.10.10.9\nrm -rf /\n```\n")
            rows, _ = build(td, "--eval-frac", "0")
            cmds = [json.loads(r["messages"][2]["content"])["command"] for r in rows["train"] + rows["eval"]]
            self.assertTrue(any(c.startswith("nmap") for c in cmds))
            self.assertFalse(any("rm -rf" in c for c in cmds))


class ExtractCommands(unittest.TestCase):
    def test_prompt_lines_and_output(self):
        block = "```console\nkali@kali:~$ nmap -sV 10.0.0.1\nPORT   STATE SERVICE\n22/tcp open  ssh\n$ whoami\nkali\n```"
        self.assertEqual(extract_commands(block), ["nmap -sV 10.0.0.1", "whoami"])

    def test_pure_command_block_and_continuation(self):
        block = "```bash\ngobuster dir -u http://10.0.0.1 \\\n  -w common.txt\n# a comment\nsomething-not-a-tool here\n```"
        self.assertEqual(extract_commands(block), ["gobuster dir -u http://10.0.0.1 -w common.txt"])

    def test_bare_hash_is_root_prompt_only_before_a_command(self):
        block = "```bash\n# id\nuid=0(root) gid=0(root)\n# cat /root/root.txt\n```"
        self.assertEqual(extract_commands(block), ["id", "cat /root/root.txt"])

    def test_powershell_prompt(self):
        block = "```powershell\nPS C:\\Users\\bob> whoami /priv\nPRIVILEGES INFORMATION\n```"
        self.assertEqual(extract_commands(block), ["whoami /priv"])


if __name__ == "__main__":
    unittest.main()
