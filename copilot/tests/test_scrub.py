"""Leak tests for copilot.scrub. Run: python -m unittest discover -s copilot/tests -t ."""
import os
import unittest

from copilot.scrub import compile_terms, load_terms, scrub

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "writeups")


def read(rel):
    with open(os.path.join(FIX, rel), encoding="utf-8") as f:
        return f.read()


class EngagementLeaks(unittest.TestCase):
    """Every fake client identifier in the engagement fixture must be gone after scrubbing."""

    @classmethod
    def setUpClass(cls):
        cls.terms = load_terms(os.path.join(FIX, "redact_terms.txt"))
        cls.out, cls.report = scrub(read("engagement/acme-internal.md"), "engagement", cls.terms)

    def test_no_client_identifier_survives(self):
        leaks = ["acmecorp", "project falcon", "j.smith", "jdoe", "svc_backup", "svc_sql", "fs01", "dc01", "sql01",
                 "10.20.30", "winter2026", "sup3rs3cret", "aad3b435b51404ee", "31d6cfe0d16ae931", "8846f7eaee8fb117",
                 "krb5tgs", "ghp_abcdefghij", "deadbeefcafe"]
        low = self.out.lower()
        found = [s for s in leaks if s in low]
        self.assertEqual(found, [], f"leaked: {found}\n---\n{self.out}")

    def test_public_references_and_harmless_values_survive(self):
        for keep in ("https://github.com/fortra/impacket", "attack.mitre.org", "127.0.0.1", "255.255.255.0",
                     "crackmapexec", "evil-winrm", "psexec.py", "secretsdump"):
            self.assertIn(keep, self.out, f"over-redacted: {keep}")

    def test_placeholders_are_stable_within_a_document(self):
        # svc_backup appears in the secretsdump line, impacket, evil-winrm -u and /home: one placeholder for all of them;
        # jdoe in crackmapexec -u, DOMAIN\user and C:\Users: one placeholder. Builtin Administrator stays readable.
        import re
        users = set(re.findall(r"<USER_\d+>", self.out))
        self.assertEqual(len(users), 2, users)
        self.assertIn("Administrator:500:<LM_HASH>:<NT_HASH>:::", self.out)
        self.assertTrue(self.report.get("SECRET", 0) >= 5, self.report)

    def test_sentence_punctuation_not_swallowed(self):
        self.assertRegex(self.out, r"/home/<USER_\d+>\s*$|/home/<USER_\d+>\.", self.out)
        out, _ = scrub("Logged in as CORP\\alice. Then C:\\Users\\alice, and -u alice; done.", "engagement")
        self.assertEqual(len(set(__import__("re").findall(r"<USER_\d+>", out))), 1, out)
        self.assertIn("<USER_1>. Then", out)

    def test_cidr_suffix_kept(self):
        self.assertRegex(self.out, r"<IP_\d+>/24")


class PublicSources(unittest.TestCase):
    def test_htb_keeps_lab_context(self):
        out, report = scrub(read("htb/lantern.md"), "htb")
        for keep in ("10.10.11.42", "lantern.htb", "gobuster dir", "sudo tar"):
            self.assertIn(keep, out)
        self.assertEqual(report, {})

    def test_hard_secrets_removed_from_every_source(self):
        text = ("key: -----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n"
                "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\n"
                "aws AKIAABCDEFGHIJKLMNOP and Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345")
        for src in ("htb", "blog", "pwk", "engagement"):
            out, _ = scrub(text, src)
            for leak in ("BEGIN OPENSSH", "eyJhbGci", "AKIAABCDEFGHIJKLMNOP", "abcdefghijklmnopqrstuvwxyz012345"):
                self.assertNotIn(leak, out, f"{src}: {leak}")

    def test_terms_apply_to_every_source(self):
        terms = compile_terms(["Contoso"])
        out, _ = scrub("Notes from the Contoso lab and contoso.local", "blog", terms)
        self.assertNotIn("contoso", out.lower())

    def test_file_names_are_not_hosts(self):
        out, _ = scrub("ran linpeas.sh then read config.php and id_rsa.pub on 10.1.2.3", "engagement")
        for keep in ("linpeas.sh", "config.php", "id_rsa.pub"):
            self.assertIn(keep, out)
        self.assertNotIn("10.1.2.3", out)


if __name__ == "__main__":
    unittest.main()
