"""Tests for the parts of Eve that decide what is shown. They run the workflow's own code with a fake model (no network, no key):
    python3 .github/eve-eval/test_eve.py"""
import json
import os
import re
import unittest

import eve_loader as L

SCRIPT = L.load_script()
CODE = """package x

func f(v string) string {
	if v == "" {
		return "empty"
	}
	return v
}
"""


def fake(answers):
    """A query_nim that answers from a list (or a function of the model and prompt) and remembers the prompts."""
    calls = []

    def q(model, messages, *a, **k):
        calls.append((model, messages[-1]["content"]))
        ans = answers(model, messages[-1]["content"]) if callable(answers) else answers[min(len(calls) - 1, len(answers) - 1)]
        return True, json.dumps(ans)
    q.calls = calls
    return q


def finding(**kw):
    f = {"priority": "warning", "file": "x.go", "line": 4, "title": "t", "impact": "i", "evidence": "", "fix": "", "reports": 1}
    f.update(kw)
    return f


def ns(q, notes="", files=None):
    return L.namespace(SCRIPT, query_nim=q, files=files or {"x.go": CODE}, notes=notes)


class Workflow(unittest.TestCase):
    def test_script_compiles_and_has_each_region_once(self):
        compile(SCRIPT, "eve", "exec")
        for name in ("nim", "numbered", "parse", "checks"):
            self.assertEqual(SCRIPT.count(f"# eve:{name}-begin"), 1, name)
            self.assertEqual(SCRIPT.count(f"# eve:{name}-end"), 1, name)

    def test_notes_are_read_from_the_base_branch_not_the_pull_request(self):
        with open(L.WORKFLOW, encoding="utf-8") as fh:
            text = fh.read()
        step = text[text.index("Read the project's review notes"):text.index("- name: Run Multi-Model Review Pipeline")]
        self.assertIn("?ref=$BASE_REF", step)
        self.assertIn("github.event.repository.default_branch", step)
        self.assertNotIn("head.sha", step)
        self.assertNotIn("head.ref", step)

    def test_no_backslash_inside_an_f_string_expression(self):
        # Python before 3.12 refuses it, and the runner's version is not ours to assume.
        for line in SCRIPT.split("\n"):
            if re.match(r"\s*(?:\w+ = |\w+\(|return |out\.append\()?f[\"']", line.strip()) or 'f"' in line:
                for m in re.finditer(r"\{([^{}]*)\}", line):
                    self.assertNotIn("\\", m.group(1), line)


class Verify(unittest.TestCase):
    def test_a_quote_that_is_not_in_the_code_is_not_trusted(self):
        n = ns(fake([{"verdict": "confirmed", "quote": "this line is invented", "trace": "t", "severity": "blocker", "attacker": "a"}]))
        self.assertEqual(n["verify"](finding(), 0, "m")[0], "unclear")

    def test_confirmed_with_a_real_quote_keeps_severity_and_attacker(self):
        n = ns(fake([{"verdict": "confirmed", "quote": 'return "empty"', "trace": "t", "severity": "info", "attacker": "nobody who isn't root"}]))
        v = n["verify"](finding(), 0, "m")
        self.assertEqual(v[0], "confirmed")
        self.assertEqual((v[3], v[4]), ("info", "nobody who isn't root"))

    def test_an_unknown_severity_is_ignored(self):
        n = ns(fake([{"verdict": "refuted", "quote": 'return "empty"', "trace": "t", "severity": "catastrophic"}]))
        self.assertEqual(n["verify"](finding(), 0, "m")[3], "")

    def test_a_file_that_was_not_fetched_is_unclear(self):
        n = ns(fake([{}]), files={})
        self.assertEqual(n["verify"](finding(), 0, "m")[0], "unclear")

    def test_the_prompt_carries_the_notes_and_the_cross_file_rule_and_the_attacker_question(self):
        q = fake([{"verdict": "unclear", "quote": "", "trace": ""}])
        ns(q, notes="-addr is the HTTPS listen address")["verify"](finding(), 0, "m")
        prompt = q.calls[0][1]
        self.assertIn("-addr is the HTTPS listen address", prompt)
        self.assertIn("ANOTHER file", prompt)
        self.assertIn("who can trigger it, and what can they ALREADY do", prompt)

    def test_without_notes_the_prompt_has_no_notes_block(self):
        q = fake([{"verdict": "unclear", "quote": "", "trace": ""}])
        ns(q)["verify"](finding(), 0, "m")
        self.assertNotIn("Facts about this project", q.calls[0][1])


class Combine(unittest.TestCase):
    def setUp(self):
        self.n = ns(fake([{}]))

    def test_agreement_confirms_and_lowers_to_the_lowest_severity(self):
        f = finding(priority="blocker")
        self.n["combine"](f, [("confirmed", "q", "why", "blocker", "x"), ("confirmed", "q", "why", "warning", "the installer is already root")])
        self.assertEqual((f["verdict"], f["priority"]), ("confirmed", "warning"))
        self.assertIn("the installer is already root", f["note"])
        self.assertIn("rated it blocker", f["note"])

    def test_severity_is_never_raised(self):
        f = finding(priority="warning")
        self.n["combine"](f, [("confirmed", "q", "why", "blocker", "x")])
        self.assertEqual(f["priority"], "warning")
        self.assertNotIn("note", f)

    def test_a_missing_severity_leaves_the_rating(self):
        f = finding(priority="blocker")
        self.n["combine"](f, [("confirmed", "q", "why", "", "")])
        self.assertEqual(f["priority"], "blocker")

    def test_disagreement_proves_nothing(self):
        f = finding(priority="blocker")
        self.n["combine"](f, [("confirmed", "q", "w", "blocker", ""), ("refuted", "q", "w", "", "")])
        self.assertEqual(f["verdict"], "unclear")
        self.assertEqual(f["why"], "the independent checks did not agree")

    def test_refuted_stays_refuted(self):
        f = finding()
        self.n["combine"](f, [("refuted", "the line", "it handles it", "", "")])
        self.assertEqual((f["verdict"], f["quote"]), ("refuted", "the line"))


class Triage(unittest.TestCase):
    def setUp(self):
        self.n = ns(fake([{}]))

    def test_only_confirmed_findings_and_infos_are_shown(self):
        fs = [finding(title="confirmed", verdict="confirmed"), finding(title="refuted", verdict="refuted"),
              finding(title="unclear", verdict="unclear"), finding(title="info", priority="info", verdict="n/a"),
              finding(title="blocker unclear", priority="blocker", verdict="unclear")]
        shown, unconfirmed, dismissed = self.n["triage"](fs)
        self.assertEqual([f["title"] for f in shown], ["confirmed", "info"])
        self.assertEqual([f["title"] for f in unconfirmed], ["unclear", "blocker unclear"])
        self.assertEqual([f["title"] for f in dismissed], ["refuted"])

    def test_an_unconfirmed_blocker_is_never_a_blocker(self):
        shown, _, _ = self.n["triage"]([finding(priority="blocker", verdict="unclear")])
        self.assertEqual(sum(f["priority"] == "blocker" for f in shown), 0)

    def test_the_suspicions_are_collapsed_and_say_why(self):
        text = self.n["render_unconfirmed"]([finding(title="Typo | key", impact="It misses\nthe key", verdict="unclear", why="the quoted proof does not appear")])
        self.assertTrue(text.strip().startswith("<details><summary>Suspicions the checks could not confirm (1)"))
        self.assertIn("**Typo | key** (`x.go:4`)", text)
        self.assertIn("Not confirmed: the quoted proof does not appear", text)
        self.assertNotIn("\n\nthe key", text)
        self.assertEqual(self.n["render_unconfirmed"]([]), "")


class WholeRun(unittest.TestCase):
    """The whole pipeline script, with fake models: what a review looks like once the checks have run."""

    DIFF = ("diff --git a/x.go b/x.go\n--- a/x.go\n+++ b/x.go\n@@ -1,3 +1,8 @@\n package x\n+\n+func f(v string) string {\n"
            "+\tif v == \"\" {\n+\t\treturn \"empty\"\n+\t}\n+\treturn v\n+}\n")
    STUB = ("def query_nim(model_id, messages, temperature=0.7, timeout=120, retries=0, max_tokens=None, deadline=None):\n"
            "    return ANSWER(model_id, messages[-1][\"content\"])\n")

    def run_script(self, verdicts, tmp):
        import contextlib
        import io
        script = SCRIPT.replace(L.region(SCRIPT, "nim"), self.STUB)
        findings = [
            {"priority": "blocker", "file": "x.go", "line": 6, "title": "Root fallback", "impact": "falls back to root", "fix": "check it",
             "evidence": 'return "empty"', "reports": 2},
            {"priority": "warning", "file": "x.go", "line": 4, "title": "Wrong claim", "impact": "never happens", "fix": "", "evidence": "", "reports": 1},
            {"priority": "warning", "file": "x.go", "line": 7, "title": "Cannot tell", "impact": "depends on another file", "fix": "", "evidence": "", "reports": 1},
            {"priority": "info", "file": "x.go", "line": 3, "title": "A style note", "impact": "", "fix": "", "evidence": "", "reports": 1},
        ]

        def answer(model, prompt):
            if prompt.startswith("You are an expert code reviewer"):
                return True, "a report"
            if "Claim (" in prompt:
                title = re.search(r"Claim \((?:blocker|warning)\): (.*)", prompt).group(1)
                return True, json.dumps(verdicts[title])
            return True, json.dumps({"verdict": "Reviewers' own words, written before the checks.", "findings": findings})
        old = os.getcwd()
        os.chdir(tmp)
        try:
            os.makedirs("context")
            for name, text in (("pr.json", json.dumps({"title": "t", "body": "b"})), ("pr_diff.patch", self.DIFF), ("context/1", CODE),
                               ("context/index.tsv", "1\tx.go\n"), ("eve-context.md", "Facts: -addr is the HTTPS address.")):
                with open(name, "w", encoding="utf-8") as fh:
                    fh.write(text)
            os.environ["NVIDIA_API_KEY"] = "test"
            with contextlib.redirect_stdout(io.StringIO()):
                exec(compile(script, "eve-whole", "exec"), {"__name__": "__main__", "ANSWER": answer})
            with open("review_comment.md", encoding="utf-8") as fh, open("blockers.txt", encoding="utf-8") as fb:
                return fh.read(), fb.read()
        finally:
            os.chdir(old)

    def test_a_review_shows_only_what_the_checks_confirmed(self):
        import tempfile
        yes = {"verdict": "confirmed", "quote": 'return "empty"', "trace": "t", "reason": "r", "attacker": "the installer is already root", "severity": "warning"}
        no = {"verdict": "refuted", "quote": "return v", "trace": "it is handled", "reason": "r", "attacker": "", "severity": ""}
        unsure = {"verdict": "unclear", "quote": "", "trace": "it depends on another file", "reason": "", "attacker": "", "severity": ""}
        with tempfile.TemporaryDirectory() as tmp:
            md, blockers = self.run_script({"Root fallback": yes, "Wrong claim": no, "Cannot tell": unsure}, tmp)
        self.assertEqual(blockers.strip(), "0")                       # confirmed, but lowered: not a blocker
        self.assertIn("**No verified blockers.**", md)
        self.assertIn("1 finding(s) confirmed against the code", md)
        self.assertIn("1 suspicion(s) the checks could not confirm", md)
        self.assertIn("1 claim(s) dismissed after checking", md)
        self.assertIn("1 lowered in severity", md)
        self.assertNotIn("Reviewers' own words", md)                  # their summary predates the checks
        table = md.split("### 🛠️ Actionable Findings")[0]
        self.assertIn("Root fallback", table)
        self.assertIn("🟡 Warning", table)
        self.assertNotIn("Wrong claim", table)
        self.assertNotIn("Cannot tell", table)                        # suspicions are not in the table
        self.assertIn("A style note", table)
        self.assertIn("Suspicions the checks could not confirm (1)", md)
        self.assertIn("the installer is already root", md)            # why it was lowered
        self.assertIn("Considered and dismissed after checking the code (1)", md)

    def test_a_confirmed_blocker_still_blocks(self):
        import tempfile
        yes = {"verdict": "confirmed", "quote": 'return "empty"', "trace": "t", "reason": "r", "attacker": "any user", "severity": "blocker"}
        unsure = {"verdict": "unclear", "quote": "", "trace": "", "reason": "", "attacker": "", "severity": ""}
        with tempfile.TemporaryDirectory() as tmp:
            md, blockers = self.run_script({"Root fallback": yes, "Wrong claim": unsure, "Cannot tell": unsure}, tmp)
        self.assertEqual(blockers.strip(), "1")
        self.assertIn("**1 verified blocker(s): resolve before merging.**", md)

    def test_when_the_checks_change_nothing_the_reviewers_summary_stays(self):
        import tempfile
        yes = {"verdict": "confirmed", "quote": 'return "empty"', "trace": "t", "reason": "r", "attacker": "any user", "severity": "warning"}
        with tempfile.TemporaryDirectory() as tmp:
            md, _ = self.run_script({"Root fallback": dict(yes, severity="blocker"), "Wrong claim": yes, "Cannot tell": yes}, tmp)
        self.assertIn("Reviewers' own words", md)


class Labels(unittest.TestCase):
    def test_the_labeled_findings_are_well_formed(self):
        with open(os.path.join(L.HERE, "labeled-findings.json"), encoding="utf-8") as fh:
            doc = json.load(fh)
        ids = set()
        for e in doc["findings"]:
            self.assertNotIn(e["id"], ids)
            ids.add(e["id"])
            self.assertRegex(e["sha"], r"^[0-9a-f]{40}$")
            self.assertIn(e["truth"], ("false", "true", "overstated"))
            self.assertIn(e["priority"], ("blocker", "warning", "info"))
            for k in ("pr", "file", "line", "title", "impact", "why"):
                self.assertTrue(e.get(k), (e["id"], k))
            if e["truth"] != "false":
                self.assertIn(e.get("max_priority"), ("info", "warning", "blocker"), e["id"])
        self.assertGreaterEqual(len(ids), 20)


if __name__ == "__main__":
    unittest.main(verbosity=1)
