# Eve's accuracy

Eve reviews pull requests with several models, then **checks** each blocker and warning against the code before showing it
(`.github/workflows/ai-pr-review.yml`). This folder keeps that checking honest.

## What the checks do

- A claim the checks **refute** is dismissed. One they **cannot prove** (the quoted proof is missing, the checks cannot tell, or two
  checks disagree) is never shown as a finding: it goes in a collapsed "Suspicions the checks could not confirm" list.
- A **confirmed** defect is rated by who could trigger it and what they already hold, never above what the reviewers said. A flaw only
  someone who is already root can reach is a warning at most.
- A claim that depends on code in another file (what a flag means, who calls a function) must be answered "unclear", not guessed.
- Facts the code does not show live in [`../eve-context.md`](../eve-context.md). They are read from the **default branch**, never from
  the pull request, so a pull request cannot write its own instructions for the reviewers. Add to it whenever Eve gets a project fact wrong.
- The summary line is built from what the checks found. The reviewers' own summary was written before the checks, so it is kept
  only when the checks changed nothing.

## Keeping it accurate

- `labeled-findings.json` holds findings Eve made on real pull requests (#66, #79, #83, #84) with what was actually true of the code at that
  commit: `false` (the claim is wrong), `true` (a real defect, at most `max_priority`) or `overstated` (the fact is right, the severity is not).
- `python3 .github/eve-eval/test_eve.py` tests the checking code with a fake model (no key, no network). CI runs it.
- `NVIDIA_API_KEY=... python3 .github/eve-eval/replay.py` runs the **real** checking stage and models on the labeled findings, using the code as it was at
  the commit Eve reviewed (fetch the pull request commits first: `git fetch origin pull/<n>/head`). It prints how many wrong claims would still
  be shown, how many real findings are kept, and how many overstated ones are rated too high. Run it before and after a change to the prompts or
  the models, and keep the change only if the numbers improve. `--only 83` limits it to some findings; `--strict` exits 1 on any wrong outcome.
- When Eve gets a new pull request wrong, add the finding to `labeled-findings.json` with its truth.

The workflow stays one self-contained file: `eve_loader.py` pulls the checking code out of it (the parts between `# eve:<name>-begin` and
`# eve:<name>-end`), so the tests and the replay run the code that really runs.
