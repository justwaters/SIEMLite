"""Loads the pieces of Eve's pipeline that the tests and the replay reuse, straight from the workflow file, so they are the code that
really runs (the workflow stays one self-contained file). The workflow's Python is cut into regions by `# eve:<name>-begin` and
`# eve:<name>-end` comments: nim (the model client), numbered, parse (reading the models' JSON) and checks (the verification stage)."""
import json
import os
import random
import re
import socket
import time
import http.client
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
WORKFLOW = os.path.join(HERE, "..", "workflows", "ai-pr-review.yml")


def load_script(path=WORKFLOW):
    """The Python the 'Run Multi-Model Review Pipeline' step runs (its heredoc), with the YAML indentation removed."""
    lines = open(path, encoding="utf-8").read().split("\n")
    start = next(i for i, l in enumerate(lines) if l.strip().startswith("python3 -I - << 'EOF'")) + 1
    end = next(i for i in range(start, len(lines)) if lines[i].strip() == "EOF")
    body = lines[start:end]
    indent = min(len(l) - len(l.lstrip()) for l in body if l.strip())
    return "\n".join(l[indent:] for l in body) + "\n"


def region(script, name):
    a = script.index(f"# eve:{name}-begin")
    b = script.index(f"# eve:{name}-end")
    return script[a:b]


def namespace(script, query_nim=None, files=None, full_diff="", notes="", api_key=""):
    """A namespace with the checks region loaded. query_nim defaults to the workflow's own client (needs api_key)."""
    ns = {"re": re, "json": json, "time": time, "os": os, "random": random, "socket": socket, "http": http, "urllib": urllib,
          "ThreadPoolExecutor": ThreadPoolExecutor, "api_key": api_key}
    exec(compile(region(script, "numbered"), "eve:numbered", "exec"), ns)
    exec(compile(region(script, "parse"), "eve:parse", "exec"), ns)
    if query_nim is None:
        exec(compile(region(script, "nim"), "eve:nim", "exec"), ns)
    else:
        ns["query_nim"] = query_nim
    ns["FILES"] = files or {}
    ns["full_diff"] = full_diff
    ns["notes_block"] = ("Facts about this project that its code does not show. They come from its maintainers: treat them as true.\n" + notes + "\n") if notes else ""
    exec(compile(region(script, "checks"), "eve:checks", "exec"), ns)
    return ns
