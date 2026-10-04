"""Browser test of the web UI against a real SIEMLite with sample data.

    go build -o siemlite . && python3 e2e/ui_test.py ./siemlite

Needs Playwright for Python (pip install playwright && playwright install chromium).
Exits non-zero, listing every failure, if a check fails.
"""

import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

PAGES = ["dashboard", "database", "alerts", "users", "sources", "parsers", "system"]
failures = []


def check(ok, what):
    print(("ok    " if ok else "FAIL  ") + what)
    if not ok:
        failures.append(what)


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start(binary, workdir):
    port = free_port()
    log = open(os.path.join(workdir, "server.log"), "w+")
    proc = subprocess.Popen([binary, "-addr", f"127.0.0.1:{port}", "-db", os.path.join(workdir, "siemlite.db"), "-sample"],
                            stdout=log, stderr=subprocess.STDOUT)
    password = None
    for _ in range(300):
        log.seek(0)
        text = log.read()
        m = re.search(r"password: (\S+)", text)
        if m and "listening" in text:
            password = m.group(1)
            break
        if proc.poll() is not None:
            sys.exit("server exited:\n" + text)
        time.sleep(0.1)
    if not password:
        proc.kill()
        sys.exit("server did not start")
    return proc, f"https://127.0.0.1:{port}/", password


def main(binary):
    version = Path("VERSION").read_text().strip()
    workdir = tempfile.mkdtemp(prefix="siemlite-e2e-")
    proc, url, password = start(binary, workdir)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            errors = []

            def session(width=1440, height=900, user="admin", pw=password):
                ctx = browser.new_context(ignore_https_errors=True, viewport={"width": width, "height": height})
                page = ctx.new_page()
                page.on("pageerror", lambda e: errors.append(str(e)))
                # 401s are expected: the page asks who is signed in before anyone is.
                page.on("console", lambda m: m.type == "error" and "status of 401" not in m.text and errors.append(m.text))
                page.goto(url)
                page.fill("#username", user)
                page.fill("#password", pw)
                page.click("#login-btn")
                return page

            # A wrong password is refused, and lands in the audit log.
            bad = session(pw="not the password")
            bad.wait_for_selector("#login-err:not([hidden])")
            check("incorrect" in bad.inner_text("#login-err").lower() or bad.is_visible("#login-err"), "wrong password is refused")
            errors.clear()  # the refused sign-in logs a 401 to the console

            page = session()
            page.wait_for_selector("#ver:not(:empty)")
            check(page.inner_text("#ver").strip() == version, f"version {version} is shown next to the name")

            for name in PAGES:
                page.goto(url + "#/" + name)
                page.wait_for_selector(f"#view-{name}:not([hidden])")
                page.wait_for_timeout(400)
                check(page.is_visible(f"#view-{name}"), f"{name} page opens")

            # Sample data raises alerts, and an alert links to its events.
            page.goto(url + "#/alerts")
            page.wait_for_selector("#alerts-body tr")
            body = page.inner_text("#alerts-body")
            check("SSH brute force" in body, "sample data raised an SSH brute force alert")
            check(page.inner_text("#nav-alerts").strip() not in ("", "0"), "the sidebar counts open alerts")
            page.locator("#alerts-body tr", has_text="SSH brute force").get_by_role("link", name=re.compile("View events")).first.click()
            page.wait_for_selector("tr.ev")
            check(page.locator("tr.ev").count() >= 10, "an alert's events open in the Database")

            # Search finds events, and the audit log is searchable.
            page.goto(url + "#/database?q=" + "%22failed%20password%22")
            page.wait_for_selector("tr.ev")
            check(page.locator("tr.ev").count() > 0, "full-text search finds events")
            page.goto(url + "#/database?q=" + "%22sign-in%20failed%22")
            page.wait_for_selector("tr.ev")
            rows = " ".join(page.locator("tr.ev").all_inner_texts())
            check("INTERNAL" in rows and "Sign-in failed" in rows, "a failed sign-in is in the audit log from INTERNAL")

            # Acknowledge and close an alert.
            page.goto(url + "#/alerts")
            page.wait_for_selector("#alerts-body tr")
            before = page.locator("#alerts-body tr").count()
            page.locator("#alerts-body tr").first.get_by_role("button", name="Acknowledge").click()
            page.wait_for_function(f"document.querySelectorAll('#alerts-body tr').length < {before}")
            check(True, "acknowledging moves an alert off the Open tab")

            # Every page fits a phone screen.
            phone = session(390, 844)
            phone.wait_for_selector("#ver:not(:empty)")
            for name in PAGES:
                phone.goto(url + "#/" + name)
                phone.wait_for_selector(f"#view-{name}:not([hidden])")
                phone.wait_for_timeout(300)
                wide = phone.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
                check(wide <= 0, f"{name} page fits a phone screen (overflow {wide}px)")

            check(not errors, "no script errors" + ("" if not errors else ": " + "; ".join(errors[:5])))
            browser.close()
    finally:
        proc.terminate()
        proc.wait(10)
    if failures:
        print(f"\n{len(failures)} check(s) failed")
        sys.exit(1)
    print("\nall checks passed")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "./siemlite")
