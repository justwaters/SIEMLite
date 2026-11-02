#!/usr/bin/env python3
"""Replays Eve's checking stage on findings whose truth is known (labeled-findings.json), to measure how many wrong claims it would
show and how many real ones it keeps. It runs the workflow's own verification code against the code as it was at the commit Eve
reviewed, with the real models, so it needs NVIDIA_API_KEY and takes a few minutes.

    NVIDIA_API_KEY=... python3 .github/eve-eval/replay.py [--only 83] [--strict]

Run it from a clone with the pull request commits fetched (git fetch origin pull/<n>/head). Change the prompts or models in the
workflow, run this before and after, and keep the change only if the numbers improve."""
import argparse
import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import eve_loader as L

RANK = {"info": 0, "warning": 1, "blocker": 2}


def git(repo, *args):
    r = subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr.strip()


def judge(entry, f, triage):
    """Was the outcome right? false: the claim must not be shown. true: shown, rated no higher than max_priority. overstated: hidden, or
    shown no higher than max_priority."""
    shown, _, _ = triage([f])
    top = RANK[entry.get("max_priority", "info")]
    if entry["truth"] == "false":
        return not shown
    if entry["truth"] == "true":
        return bool(shown) and RANK[f["priority"]] <= top
    return (not shown) or RANK[f["priority"]] <= top


def replay_one(entry, script, repo, notes, models, key, ns_cache):
    code, text, err = git(repo, "show", f"{entry['sha']}:{entry['file']}")
    if code:
        return {"id": entry["id"], "error": f"can't read {entry['file']} at {entry['sha'][:7]} ({err}); fetch it with: git fetch origin pull/{entry['pr']}/head"}
    base = git(repo, "merge-base", entry["sha"], "origin/main")[1].strip() or entry["sha"] + "~1"
    diff = git(repo, "diff", base, entry["sha"], "--", entry["file"])[1]
    ns = L.namespace(script, files={entry["file"]: text}, full_diff=diff, notes=notes, api_key=key)
    f = {k: entry[k] for k in ("priority", "file", "line", "title", "impact", "evidence")}
    f["fix"], f["reports"] = "", 1
    verifiers = [models[0]] + ([models[1]] if f["priority"] == "blocker" else [])
    rs = [ns["verify"](f, __import__("time").time() + 270, m) for m in verifiers]
    ns["combine"](f, rs)
    ok = judge(entry, f, ns["triage"])
    return {"id": entry["id"], "truth": entry["truth"], "claimed": entry["priority"], "verdict": f["verdict"], "priority": f["priority"], "ok": ok,
            "why": re.sub(r"\s+", " ", f.get("why", ""))[:160]}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--only", default="", help="only findings whose id contains this text")
    ap.add_argument("--repo", default=".", help="the clone to read code from")
    ap.add_argument("--notes", default=".github/eve-context.md", help="the project notes to give the verifier ('' for none)")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--json", default="", help="also write the results here")
    ap.add_argument("--strict", action="store_true", help="exit 1 if any outcome is wrong")
    args = ap.parse_args()
    key = os.environ.get("NVIDIA_API_KEY", "")
    if not key:
        sys.exit("Set NVIDIA_API_KEY.")
    script = L.load_script()
    models = [re.search(rf'^{n} = "([^"]+)"', script, re.M).group(1) for n in ("VERIFIER", "VERIFIER2")]
    notes = open(args.notes, encoding="utf-8").read().strip() if args.notes and os.path.exists(args.notes) else ""
    entries = [e for e in json.load(open(os.path.join(L.HERE, "labeled-findings.json")))["findings"] if args.only in e["id"]]
    print(f"Replaying {len(entries)} finding(s) with {models[0]} (blockers also {models[1]}); notes: {len(notes)} characters.")
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        results = list(ex.map(lambda e: replay_one(e, script, args.repo, notes, models, key, {}), entries))
    bad = 0
    for r in results:
        if "error" in r:
            print(f"ERROR {r['id']}: {r['error']}")
            bad += 1
            continue
        bad += not r["ok"]
        print(f"{'ok   ' if r['ok'] else 'WRONG'} {r['id']:<22} truth={r['truth']:<10} claimed={r['claimed']:<8} -> {r['verdict']:<9} {r['priority']:<8} {r['why']}")
    by = {t: [r for r in results if r.get("truth") == t] for t in ("false", "true", "overstated")}
    shown_wrong = sum(1 for r in by["false"] if not r["ok"])
    print(f"\nWrong claims shown as findings: {shown_wrong} of {len(by['false'])}")
    print(f"Real findings kept at a fair rating: {sum(r['ok'] for r in by['true'])} of {len(by['true'])}")
    print(f"Overstated findings rated too high: {sum(1 for r in by['overstated'] if not r['ok'])} of {len(by['overstated'])}")
    if args.json:
        json.dump(results, open(args.json, "w"), indent=1)
    sys.exit(1 if args.strict and bad else 0)


if __name__ == "__main__":
    main()
