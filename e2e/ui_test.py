"""Browser test of the web UI against a real SIEMLite fed by the log generator.

    go build -o siemlite . && go build -o loggen ./cmd/loggen && python3 e2e/ui_test.py ./siemlite ./loggen

Needs Playwright for Python (pip install playwright && playwright install chromium).
Exits non-zero, listing every failure, if a check fails.
"""

import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from playwright.sync_api import sync_playwright

PAGES = ["dashboard", "database", "alerts", "users", "sources", "intel", "parsers", "reports", "system"]
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
    proc = subprocess.Popen([binary, "-addr", f"127.0.0.1:{port}", "-db", os.path.join(workdir, "siemlite.db")],
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


EXPRESS_STUB = """const http = require("http");
function express() {
  const routes = {};
  return {
    post(path, parse, handler) { routes["POST " + path] = handler; },
    listen(port) {
      http.createServer((req, res) => {
        let body = "";
        req.on("data", (c) => (body += c));
        req.on("end", async () => {
          const h = routes[req.method + " " + req.url];
          if (!h) { res.statusCode = 404; return res.end(); }
          req.body = body;
          res.status = (c) => { res.statusCode = c; return res; };
          res.send = (t) => res.end(t);
          try { await h(req, res); } catch (e) { res.statusCode = 500; res.end(String(e)); }
        });
      }).listen(port, "127.0.0.1");
    },
  };
}
express.text = () => null;
module.exports = express;
"""


def run(cmd, cwd, env=None, timeout=120):
    e = dict(os.environ)
    e.update(env or {})
    return subprocess.run(cmd, cwd=cwd, env=e, capture_output=True, text=True, timeout=timeout)


def run_snippets(snips, workdir, base_url):
    """Run each snippet the dialog showed against the test server. Returns how many ran."""
    ran = 0
    work = Path(tempfile.mkdtemp(prefix="siemlite-snippets-"))
    shutil.copy(os.path.join(workdir, "siemlite.crt"), work / "siemlite.crt")
    cert = str(work / "siemlite.crt")

    def report(lang, r, want_status=True):
        nonlocal ran
        ran += 1
        out = (r.stdout + r.stderr).strip()
        ok = r.returncode == 0 and (("202" in r.stdout and "accepted" in r.stdout) if want_status else '"accepted"' in r.stdout)
        check(ok, f"the {lang} snippet sends a log and gets 202: {out[:120]!r}")

    if shutil.which("curl"):
        report("curl", run(["sh", "-c", snips["curl"]], work), want_status=False)
    else:
        print("skip  curl is not installed")
    if shutil.which("python3"):
        (work / "send.py").write_text(snips["python"])
        report("Python", run(["python3", "send.py"], work))
    else:
        print("skip  python3 is not installed")
    if shutil.which("node"):
        (work / "app.mjs").write_text(snips["javascript"])
        report("JavaScript", run(["node", "app.mjs"], work, {"NODE_EXTRA_CA_CERTS": cert}))
    else:
        print("skip  node is not installed")
    if shutil.which("go"):
        gdir = work / "gosnip"
        gdir.mkdir()
        (gdir / "go.mod").write_text("module snippet\n\ngo 1.21\n")
        (gdir / "main.go").write_text(snips["go"])
        shutil.copy(cert, gdir / "siemlite.crt")
        report("Go", run(["go", "run", "main.go"], gdir, {"GOFLAGS": "-mod=mod"}, timeout=300))
    else:
        print("skip  go is not installed")

    # React: the hook and the Express handler are in the text; the hook parses as JSX;
    # the handler forwards a log to SIEMLite (run with a small stand-in for express).
    react = snips["react"]
    client, _, server = react.partition("// On your server")
    check("export function useSiemLog()" in client and 'fetch("/api/log"' in client and "<button" in client
          and "express.text()" in server and 'app.post("/api/log"' in server, "the React tab has the useSiemLog hook and the Express /api/log handler")
    if shutil.which("npx"):
        (work / "Hook.jsx").write_text(client)
        r = run(["npx", "--yes", "esbuild", "Hook.jsx", "--loader:.jsx=jsx", "--log-level=warning"], work, timeout=180)
        if r.returncode == 0:
            check(True, "the React snippet parses as JSX (esbuild)")
        else:
            print("skip  esbuild could not run here: " + r.stderr.strip()[:100])
    if shutil.which("node"):
        (work / "node_modules" / "express").mkdir(parents=True)
        (work / "node_modules" / "express" / "index.js").write_text(EXPRESS_STUB)
        port = free_port()
        (work / "server.mjs").write_text("import express from \"express\";" + server.split('import express from "express";', 1)[1].replace("app.listen(3000)", f"app.listen({port})"))
        srv = subprocess.Popen(["node", "server.mjs"], cwd=work, env={**os.environ, "NODE_EXTRA_CA_CERTS": cert},
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        try:
            out = ""
            for _ in range(50):
                time.sleep(0.2)
                r = run(["curl", "-s", "-X", "POST", f"http://127.0.0.1:{port}/api/log", "-H", "Content-Type: text/plain",
                         "--data-binary", "ERROR payment failed user=bob order=1042"], work)
                if r.returncode == 0:
                    out = r.stdout
                    break
            ran += 1
            check('"accepted"' in out, f"the React tab's Express handler forwards a log to SIEMLite: {out[:80]!r}")
        finally:
            srv.kill()
    return ran


def main(binary, loggen):
    version = Path("VERSION").read_text().strip()
    workdir = tempfile.mkdtemp(prefix="siemlite-e2e-")
    proc, url, password = start(binary, workdir)
    try:
        # Test data from the log generator, with the source and token SIEMLite
        # made for it on first start.
        gen = subprocess.run([loggen, "-eps", "200", "-for", "20s", "-seed", "7", "-to", url.rstrip("/"),
                              "-token-file", os.path.join(workdir, "siemlite-loggen.token"),
                              "-cacert", os.path.join(workdir, "siemlite.crt")], capture_output=True, text=True)
        check(gen.returncode == 0 and "sent" in gen.stderr, "the log generator sends to the source made for it: " + gen.stderr.strip().splitlines()[-1])
        with sync_playwright() as p:
            browser = p.chromium.launch()
            errors = []

            def session(width=1440, height=900, user="admin", pw=password):
                ctx = browser.new_context(ignore_https_errors=True, viewport={"width": width, "height": height})
                page = ctx.new_page()
                page.on("pageerror", lambda e: errors.append(str(e)))
                # 401s are expected: the page asks who is signed in before anyone is. So are the 400s of checks that enter something wrong on purpose.
                page.on("console", lambda m: m.type == "error" and "status of 401" not in m.text and "status of 400" not in m.text and errors.append(m.text))
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

            # The Look selector is on Original until Glass is chosen, then stays on after a reload, and turns off again.
            page.goto(url + "#/account")
            page.wait_for_selector("#view-account:not([hidden])")
            look = lambda: page.evaluate("document.documentElement.dataset.look || ''")
            check(look() == "", "the glass look is off by default")
            pressed = lambda name: page.get_attribute(f'[data-look-choice="{name}"]', "aria-pressed")
            check(pressed("original") == "true" and pressed("glass") == "false", "the Look selector starts on Original")
            page.click('[data-look-choice="glass"]')
            check(look() == "glass" and pressed("glass") == "true", "choosing Glass turns it on")
            page.reload()
            page.wait_for_selector("#view-account:not([hidden])")
            check(look() == "glass" and pressed("glass") == "true", "the glass look is still on after a reload")
            page.click('[data-look-choice="original"]')
            check(look() == "" and pressed("original") == "true", "choosing Original turns it off again")

            # The generator's attacks raise alerts (the engine checks every 10s),
            # and an alert links to its events.
            page.goto(url + "#/sources")
            row = page.locator("#view-sources tbody tr").filter(
                has=page.locator("td:first-child", has_text=re.compile(r"^\s*Log generator\s*$"))).first
            row.wait_for()
            sel = row.locator("select")
            chosen = sel.evaluate("s => s.options[s.selectedIndex].text") if sel.count() else ""
            check("Access token" in row.inner_text() and chosen == "Log generator",
                  f"the Log generator source is set up with its parser (parser: {chosen!r})")
            # The parser dropdown offers Automatic and None before the parsers,
            # and choosing None sticks across a reload.
            ui_row = lambda: page.locator("#view-sources tbody tr").filter(
                has=page.locator("td:first-child", has_text=re.compile(r"^\s*Added in the UI\s*$"))).first
            ui_sel = ui_row().locator("select")
            options = ui_sel.evaluate("s => [...s.options].map(o => o.text)")
            check(options[:2] == ["Automatic", "None"] and "Log generator" in options[2:],
                  f"the parser dropdown lists Automatic, None, then the parsers ({options})")
            check(ui_sel.evaluate("s => s.options[s.selectedIndex].text") == "Automatic", "a source starts on Automatic")
            ui_btns = ui_row().locator(".row-actions > .btn").all_inner_texts()
            check(ui_btns == ["View logs", "Rename", "Add logs"], f"the Added in the UI source offers View logs, Rename, Add logs ({ui_btns})")
            ui_sel.select_option(label="None")
            page.wait_for_selector("#sources-msg:not([hidden])")
            check("no parser" in page.inner_text("#sources-msg"), "choosing None says so")
            page.reload()
            page.wait_for_selector("#view-sources tbody tr")
            chosen = ui_row().locator("select").evaluate("s => s.options[s.selectedIndex].text")
            check(chosen == "None", f"None is still chosen after a reload ({chosen!r})")
            ui_row().locator("select").select_option(label="Automatic")
            page.wait_for_selector("#sources-msg:not([hidden]):has-text('automatic')")
            page.reload()
            page.wait_for_selector("#view-sources tbody tr")
            chosen = ui_row().locator("select").evaluate("s => s.options[s.selectedIndex].text")
            check(chosen == "Automatic", f"choosing Automatic again clears it ({chosen!r})")

            # An access token is managed in a popup: Enable, Disable, New token or Delete.
            gen_row = lambda: page.locator("#view-sources tbody tr").filter(
                has=page.locator("td:first-child", has_text=re.compile(r"^\s*Log generator\s*$"))).first
            buttons = gen_row().locator("button").all_inner_texts()
            check("Manage" in buttons and "Revoke" not in buttons, f"the Log generator row has Manage and no Revoke ({buttons})")
            gen_row().get_by_role("button", name="Manage").click()
            dlg = page.locator("#dlg-manage")
            dlg.wait_for(state="visible")
            names = dlg.locator(".manage-choices button").all_inner_texts()
            check(dlg.locator("#manage-title").inner_text() == "Manage Log generator" and names == ["Enable", "Disable", "New token", "Delete"],
                  f"the Manage popup offers Enable, Disable, New token and Delete ({names})")
            check("Enabled" in dlg.locator("#manage-state").inner_text(), "the popup says the source is enabled")
            check(dlg.locator("#manage-enable").is_disabled() and dlg.locator("#manage-disable").is_enabled(),
                  "Enable is greyed out while the source is enabled")
            # New token asks first, and Cancel changes nothing.
            dlg.locator("#manage-rotate").click()
            confirm_buttons = dlg.locator("#manage-confirm button:visible").all_inner_texts()
            check("new token" in dlg.locator("#manage-confirm-title").inner_text().lower() and confirm_buttons == ["Cancel", "Create new token"],
                  f"New token asks before it does anything ({confirm_buttons})")
            dlg.locator("#manage-cancel").click()
            check(dlg.locator("#manage-main").is_visible(), "Cancel goes back to the Manage popup")
            page.keyboard.press("Escape")
            check(not dlg.is_visible(), "Escape closes the Manage popup")

            gen_row().get_by_role("button", name="Manage").click()
            dlg.locator("#manage-disable").click()
            page.wait_for_selector("#sources-msg:has-text('Disabled Log generator.')")
            check("disabled" in gen_row().locator("td.kind").inner_text() and not dlg.is_visible(),
                  "Disable closes the popup and the row says disabled")
            gen_buttons = gen_row().locator("button").all_inner_texts()
            check("Manage" in gen_buttons and "Rename" not in gen_buttons, f"a disabled source keeps Manage, not Rename ({gen_buttons})")
            gen_row().get_by_role("button", name="Manage").click()
            dlg.wait_for(state="visible")
            check("Disabled" in dlg.locator("#manage-state").inner_text() and dlg.locator("#manage-disable").is_disabled()
                  and dlg.locator("#manage-enable").is_enabled(), "Disable is greyed out while the source is disabled")
            dlg.locator("#manage-enable").click()
            page.wait_for_selector("#sources-msg:has-text('Enabled Log generator.')")
            check("disabled" not in gen_row().locator("td.kind").inner_text(), "Enable puts the row back")

            # Delete asks again first; cancelling keeps the source.
            gen_row().get_by_role("button", name="Manage").click()
            dlg.locator("#manage-delete").click()
            check("Delete Log generator?" in dlg.locator("#manage-confirm-title").inner_text()
                  and "Deleted source" in dlg.locator("#manage-confirm-body").inner_text(), "Delete asks for confirmation")
            dlg.locator("#manage-cancel").click()
            check(dlg.locator("#manage-main").is_visible() and gen_row().count() == 1, "cancelling the delete keeps the source")
            page.keyboard.press("Escape")

            # A throwaway source shows deleting end to end.
            page.evaluate("""() => fetch('/api/v1/sources', {method: 'POST', headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({name: 'Throwaway'})})""")
            page.reload()
            throw_row = lambda: page.locator("#view-sources tbody tr").filter(
                has=page.locator("td:first-child", has_text=re.compile(r"^\s*Throwaway\s*$")))
            throw_row().get_by_role("button", name="Manage").click()
            dlg.locator("#manage-delete").click()
            dlg.locator("#manage-delete-ok").click()
            page.wait_for_selector("#sources-msg:has-text('Deleted Throwaway.')")
            check(throw_row().count() == 0 and not dlg.is_visible(), "deleting a source removes its row")

            # Add source: the button, the form, then the Connect screen.
            page.goto(url + "#/sources")
            page.wait_for_selector("#view-sources tbody tr")
            check(page.inner_text("#add-source").strip() == "Add source", "the Sources button reads Add source")
            page.click("#add-source")
            add = page.locator("#dlg-source")
            add.wait_for(state="visible")
            check(add.locator("h2").inner_text() == "Add source" and add.locator("#s-save").inner_text() == "Add source",
                  "the form is titled Add source and submits with Add source")
            check("application or device" in add.locator("#source-dlg-sub").inner_text(), "the form says what a source is")
            page.fill("#s-name", "Snippet app")
            page.click("#s-save")
            conn = page.locator("#dlg-token")
            conn.wait_for(state="visible")
            check(conn.locator("#t-title").inner_text() == "Connect Snippet app", "the Connect screen is titled Connect <name>")
            origin = url.rstrip("/")
            check(page.input_value("#t-address") == origin, f"the SIEMLite address is prefilled with the browser's ({page.input_value('#t-address')})")
            check(page.input_value("#t-url") == origin + "/api/v1/logs", "the full URL to send logs to is shown")
            token = page.input_value("#t-token")
            check(len(token) >= 20, "the one-time access token is shown")
            tabs = conn.get_by_role("tab")
            check(tabs.all_inner_texts() == ["curl", "Python", "Go", "JavaScript", "React"], f"the five language tabs are there ({tabs.all_inner_texts()})")
            check(conn.get_by_role("tablist").count() == 1 and conn.get_by_role("tabpanel").count() == 1, "one tablist and one visible tab panel")
            for sel in ["#t-url-copy", "#t-copy", "#copy-curl"]:
                check(page.locator(sel).count() == 1, f"a Copy button exists ({sel})")
            check("Copy" == page.inner_text("#copy-curl") and token in page.text_content("#code-curl"), "the curl snippet has the token filled in")

            # Keyboard: arrows, Home and End move between tabs.
            selected = lambda: page.evaluate("[...document.querySelectorAll('#t-tabs [role=tab]')].filter(t => t.getAttribute('aria-selected') === 'true').map(t => t.textContent)")
            page.locator("#tab-curl").focus()
            page.keyboard.press("ArrowRight")
            check(selected() == ["Python"] and page.evaluate("document.activeElement.id") == "tab-python", "Right arrow moves to the next tab")
            page.keyboard.press("End")
            check(selected() == ["React"], "End moves to the last tab")
            page.keyboard.press("ArrowRight")
            check(selected() == ["curl"], "Right arrow wraps around to the first tab")
            page.keyboard.press("ArrowLeft")
            check(selected() == ["React"], "Left arrow wraps around to the last tab")
            page.keyboard.press("Home")
            check(selected() == ["curl"], "Home moves to the first tab")
            check(page.evaluate("[...document.querySelectorAll('#t-tabs [role=tab]')].map(t => t.tabIndex)") == [0, -1, -1, -1, -1], "only the chosen tab is in the tab order")
            page.click("#tab-go")
            page.reload()
            page.wait_for_selector("#view-sources tbody tr")
            check(page.evaluate("localStorage.getItem('siemlite.connect-tab')") == "go", "the chosen tab is remembered")

            # Editing the address changes every snippet.
            page.click("#add-source")
            page.fill("#s-name", "Second app")
            page.click("#s-save")
            conn.wait_for(state="visible")
            check(selected() == ["Go"], "the last chosen tab is open next time")
            page.fill("#t-address", "http://logs.example.test:9000///")
            check(page.input_value("#t-url") == "http://logs.example.test:9000/api/v1/logs", "editing the address updates the URL and trims slashes")
            texts = {}
            for lang in ["curl", "python", "go", "javascript", "react"]:
                page.click("#tab-" + lang)
                texts[lang] = page.text_content("#code-" + lang)
            check(all("http://logs.example.test:9000/api/v1/logs" in t for t in texts.values()), "every snippet follows the address")
            page.fill("#t-address", "not a url")
            check(page.input_value("#t-url") == "https://siemlite.example.com/api/v1/logs", "an invalid address falls back to the placeholder")
            page.fill("#t-address", "")
            check("https://siemlite.example.com/api/v1/logs" in page.text_content("#code-react"), "an empty address falls back to the placeholder")
            page.fill("#t-address", "https://a.test/it's \"x\" $(id)")
            odd = page.input_value("#t-url")
            page.click("#tab-curl")
            echoed = run(["sh", "-c", page.text_content("#code-curl").replace("curl --cacert siemlite.crt -X POST", "printf '%s\\n'", 1)], ".").stdout.splitlines()
            check(odd.startswith("https://a.test/") and echoed[:1] == [odd], f"an address with quotes and $() reaches the shell as one plain word ({odd!r})")
            page.keyboard.press("Escape")

            # The snippets themselves work: read them from a fresh Connect screen with
            # the test server's address and run them.
            page.click("#add-source")
            page.fill("#s-name", "Runnable app")
            page.click("#s-save")
            conn.wait_for(state="visible")
            page.fill("#t-address", origin)
            snips = {}
            for lang in ["curl", "python", "go", "javascript", "react"]:
                page.click("#tab-" + lang)
                snips[lang] = page.text_content("#code-" + lang)
            check(all(snips.values()), "every tab shows a snippet")
            page.keyboard.press("Escape")
            ran = run_snippets(snips, workdir, url)
            print(f"      ran {ran} snippet check(s) against {origin}")
            sources = page.evaluate("fetch('/api/v1/sources').then(r => r.json())")
            sources = sources.get("sources", sources) if isinstance(sources, dict) else sources
            sid = [x["id"] for x in sources if x["name"] == "Runnable app"][0]
            page.goto(url + f"#/database?source={sid}")
            got = 0
            for _ in range(20):
                page.goto(url + f"#/database?source={sid}")
                page.reload()
                page.wait_for_timeout(700)
                got = page.locator("tr.ev").count()
                if got >= ran:
                    break
            check(got == ran, f"the Runnable app source shows {got} events in the Database from {ran} snippet runs (React included)")

            for _ in range(15):
                page.goto(url + "#/alerts")
                page.wait_for_timeout(1500)
                if "SSH brute force" in page.inner_text("#alerts-body"):
                    break
            body = page.inner_text("#alerts-body")
            check("SSH brute force" in body, "the generator's attack raised an SSH brute force alert")
            check(page.inner_text("#nav-alerts").strip() not in ("", "0"), "the sidebar counts open alerts")
            page.locator("#alerts-body tr", has_text="SSH brute force").get_by_role("link", name=re.compile("View events")).first.click()
            page.wait_for_selector("tr.ev")
            check(page.locator("tr.ev").count() >= 10, "an alert's events open in the Database")

            # Search finds events, and the audit log is searchable.
            page.goto(url + "#/database?q=" + "%22failed%20password%22")
            page.wait_for_selector("tr.ev")
            check(page.locator("tr.ev").count() > 0, "full-text search finds events")
            # The Event column shows the parsed message (the last field of a
            # generator line), not the pipe-separated line it came in as.
            event_text = page.locator("tr.ev").first.locator("td:last-child").inner_text()
            check("|" not in event_text and "ailed password" in event_text, f"the Event column shows the parsed message ({event_text!r})")
            page.goto(url + "#/database?q=" + "%22sign-in%20failed%22")
            try:  # the previous results stay until the new ones arrive
                page.wait_for_selector('tr.ev:has-text("Sign-in failed")', timeout=10000)
            except Exception:
                pass
            rows = " ".join(page.locator("tr.ev").all_inner_texts())
            check("INTERNAL" in rows and "Sign-in failed" in rows, "a failed sign-in is in the audit log from INTERNAL")

            # The Database loads 100 events at a time, with a button (and scrolling) for more.
            page.goto(url + "#/database")
            page.locator("tr.ev").nth(99).wait_for()  # (the page changes its hash, so the earlier results stay up until these arrive)
            check(page.locator("tr.ev").count() == 100, f"the Database starts with 100 events ({page.locator('tr.ev').count()})")
            check(page.locator("#prev, #next").count() == 0, "there are no Newer and Older buttons")
            check(page.is_visible("#more"), "a Show more events button is under the table")
            page.click("#more")
            page.locator("tr.ev").nth(199).wait_for()
            ids = page.locator("tr.ev").count()
            check(ids >= 200, f"Show more events adds the next 100 ({ids} shown)")
            # A public IP is a link: hovering shows its details, clicking goes to Talos without opening the row.
            link = page.locator("tr.ev a.ip-link").first
            if link.count():
                ip = link.inner_text()
                check((link.get_attribute("href") or "").endswith("search=" + ip) and "talosintelligence.com" in link.get_attribute("href"),
                      f"a public IP links to its Talos lookup ({ip})")
                link.hover()
                page.wait_for_selector(".ip-tip:not([hidden])")
                check("Talos" in page.inner_text(".ip-tip"), "hovering an IP shows its card")
                check(page.locator("tr.detail").count() == 0 or page.locator("tr.ev.open").count() == 0, "hovering an IP doesn't open the row")
                page.mouse.move(5, 5)
            else:
                check(False, "the Database shows a public IP as a link")
            # Field terms beside the words, the format the search box is meant to take.
            page.fill("#q", "source=INTERNAL")
            page.press("#q", "Enter")
            sources = set()
            for _ in range(100):  # the earlier results stay up until the new ones arrive
                page.wait_for_selector("tr.ev")
                sources = {t.strip() for t in page.locator("tr.ev td:nth-child(3)").all_inner_texts()}
                if sources == {"INTERNAL"}:
                    break
                time.sleep(0.1)
            check(page.is_hidden("#db-error") and sources == {"INTERNAL"}, f"a source=INTERNAL term narrows the search ({sources})")
            page.fill("#q", "severity=high,critical ip=198.51.100.141,203.0.113.7")
            page.press("#q", "Enter")
            page.wait_for_selector("#summary:not(:empty)")
            check(page.is_hidden("#db-error"), "a search with several field terms and comma lists is accepted")
            page.fill("#q", "")
            page.press("#q", "Enter")
            page.wait_for_selector("tr.ev")

            # Dragging the | between two column headers resizes the columns,
            # with a real mouse (the Database table sizes its columns with <col>s).
            first = page.locator("table.events thead th").first
            w0 = first.bounding_box()["width"]
            # Measure the grip once the layout has settled: a drag aimed at a
            # position that is still moving grabs nothing ("156px to 156px").
            grip_loc = first.locator(".col-grip")
            grip, prev = None, None
            for _ in range(40):
                grip = grip_loc.bounding_box()
                if grip == prev:
                    break
                prev = grip
                page.wait_for_timeout(100)
            w0 = first.bounding_box()["width"]
            x, y = grip["x"] + grip["width"] / 2, grip["y"] + grip["height"] / 2
            page.mouse.move(x, y)
            page.mouse.down()
            page.mouse.move(x + 40, y, steps=5)
            page.mouse.up()
            w1 = first.bounding_box()["width"]
            check(abs(w1 - w0 - 40) < 3, f"dragging a column divider resizes the column ({w0:.0f}px to {w1:.0f}px)")

            # A rule on how much one source sends: the form drops the search and
            # grouping, asks for a source (no "any"), and the list reads it back.
            page.goto(url + "#/alerts?tab=rules")
            page.wait_for_selector("#rules-body tr")
            page.click("#add-rule")
            page.select_option("#r-kind", "volume_under")
            check(not page.is_visible("#r-query") and not page.is_visible("#r-group"), "a volume rule hides the search and grouping")
            check(page.locator("#r-source option", has_text="Any source").count() == 0, "a volume rule must name a source")
            page.fill("#r-name", "Source went quiet")
            page.fill("#r-threshold", "1")
            page.fill("#r-window", "15")
            page.click("#r-save")
            page.locator("#rules-body tr", has_text="Source went quiet").wait_for()
            sentence = page.locator("#rules-body tr", has_text="Source went quiet").locator(".rule-sentence").inner_text()
            check("sends fewer than 1 event in 15 minutes" in sentence, f"the rule list reads a volume rule back ({sentence!r})")

            # A rule on repeated events by one user: the form asks what is the same, hides the search and
            # grouping, and the list reads it back.
            page.click("#add-rule")
            page.select_option("#r-kind", "repeat")
            check(page.is_visible("#r-same") and not page.is_visible("#r-query") and not page.is_visible("#r-group"),
                  "a repeat rule asks what is the same and hides the search and grouping")
            check(not page.is_visible("#r-keywords"), "the keywords box is hidden while the same severity is chosen")
            page.select_option("#r-same", "repeat_keyword")
            check(page.is_visible("#r-keywords"), "choosing the same keyword shows the keywords box")
            page.fill("#r-name", "Same keyword again")
            page.fill("#r-keywords", "denied, failed, blocked")
            page.fill("#r-threshold", "5")
            page.fill("#r-window", "10")
            page.click("#r-save")
            page.locator("#rules-body tr", has_text="Same keyword again").wait_for()
            sentence = page.locator("#rules-body tr", has_text="Same keyword again").locator(".rule-sentence").inner_text()
            check("User has 5+ events with the same keyword in 10 min" in sentence and "denied, failed, blocked" in sentence,
                  f"the rule list reads a repeat rule back ({sentence!r})")

            # The built-in "Improbable travel" rule reads as a sentence about speed, and its form asks for a speed.
            row = page.locator("#rules-body tr", has_text="Improbable travel")
            row.wait_for()
            sentence = row.locator(".rule-sentence").inner_text()
            check("same user signs in from places too far apart" in sentence and "faster than 900 km/h" in sentence,
                  f"the rule list reads the improbable travel rule ({sentence!r})")
            check(row.locator("button", has_text="Delete").count() == 0, "the improbable travel rule has no Delete button")
            row.locator("button", has_text="Edit").click()
            page.wait_for_selector("#dlg-rule[open]")
            check("Fastest believable travel (km/h)" in page.inner_text("#r-threshold-label"), "the improbable travel form asks for a speed")
            check(not page.is_visible("#r-window") and not page.is_visible("#r-group") and not page.is_visible("#r-kind"),
                  "the improbable travel form hides the window, grouping and kind")
            page.keyboard.press("Escape")
            page.wait_for_selector("#dlg-rule", state="hidden")
            page.click("#add-rule")
            page.wait_for_selector("#dlg-rule[open]")
            check(page.is_visible("#r-window") and page.is_visible("#r-group") and "At least" in page.inner_text("#r-threshold-label"),
                  "a new rule's form is unchanged after the improbable travel one")
            page.keyboard.press("Escape")
            page.wait_for_selector("#dlg-rule", state="hidden")

            # System > Software update: the release channel is Stable until Beta is chosen (and confirmed).
            page.goto(url + "#/system")
            page.wait_for_selector("#update-channel")
            check(page.get_attribute('[data-channel="stable"]', "aria-pressed") == "true" and page.get_attribute('[data-channel="beta"]', "aria-pressed") == "false",
                  "the release channel starts on Stable")
            page.click('[data-channel="beta"]')
            page.wait_for_selector("#dlg-confirm[open]")
            check("Beta" in page.inner_text("#c-title"), "choosing Beta asks first")
            page.click("#c-ok")
            page.wait_for_selector('[data-channel="beta"][aria-pressed="true"]')
            page.reload()
            page.wait_for_selector('[data-channel="beta"][aria-pressed="true"]')
            page.click('[data-channel="stable"]')  # going back to Stable needs no confirmation
            page.wait_for_selector('[data-channel="stable"][aria-pressed="true"]')
            check(True, "the release channel is kept, and Stable can be chosen again")

            # System > Automatic updates: schedules of days and times, saved and kept.
            page.goto(url + "#/system")
            page.wait_for_selector("#au-rows input")
            check(not page.is_checked("#au-enabled") and page.is_checked("#au-backup") and page.is_checked("#au-hold") and page.locator("#au-rows input").count() == 1,
                  "automatic updates start off, with a backup first, holding for alerts, and one time")
            # Tick boxes and switches are drawn by the page, not the browser.
            check(page.evaluate("getComputedStyle(document.getElementById('au-enabled')).appearance") == "none",
                  "tick boxes are the page's own, not the browser's")
            check(page.evaluate("getComputedStyle(document.querySelector('.switch .track')).borderTopWidth") != "0px",
                  "switches are the page's own: the track has an outline")
            page.check("#au-enabled")
            page.uncheck("#au-hold")
            row = page.locator(".au-row").nth(0)
            check(all(row.locator(f'[data-day="{d}"]').get_attribute("aria-pressed") == "true" for d in "0123456"), "a new schedule starts with every day picked")
            for d in ("0", "6"):
                row.locator(f'[data-day="{d}"]').click()
            row.locator("input").nth(0).fill("04:15")
            page.click("#au-add")
            row2 = page.locator(".au-row").nth(1)
            for d in "12345":
                row2.locator(f'[data-day="{d}"]').click()
            row2.locator("input").nth(0).fill("06:00")
            row2.locator("[data-add-time]").click()
            row2.locator("input").nth(1).fill("22:45")
            check(page.locator(".au-row").count() == 2 and row2.locator("input").count() == 2, "a second schedule with two times can be added")
            page.click("#au-save")
            page.wait_for_selector("#au-msg:not([hidden])")
            msg = page.inner_text("#au-msg")
            check("Saved" in msg and "04:15" in msg and "06:00, 22:45" in msg and "Sat, Sun" in msg, f"the update schedule saves ({msg!r})")
            page.reload()
            page.wait_for_selector("#au-rows input")
            check(page.is_checked("#au-enabled") and not page.is_checked("#au-hold") and page.locator(".au-row").count() == 2 and
                  page.locator(".au-row").nth(0).locator('[data-day="1"]').get_attribute("aria-pressed") == "true" and
                  page.locator(".au-row").nth(0).locator('[data-day="6"]').get_attribute("aria-pressed") == "false" and
                  page.locator(".au-row").nth(1).locator("input").count() == 2,
                  "the update schedule is kept after a reload")
            page.locator(".au-row").nth(1).get_by_text("Remove schedule").click()
            check(page.locator(".au-row").count() == 1, "a schedule can be removed")
            row.locator('[data-day="1"]').click()
            row.locator('[data-day="2"]').click()
            row.locator('[data-day="3"]').click()
            row.locator('[data-day="4"]').click()
            row.locator('[data-day="5"]').click()
            page.click("#au-save")
            page.wait_for_selector("#au-msg:not([hidden])")
            check("at least one day" in page.inner_text("#au-msg"), "a schedule with no day picked is refused")
            for d in "0123456":
                row.locator(f'[data-day="{d}"]').click()
            page.click("#au-save")
            page.wait_for_selector("#au-msg:has-text('Every day')")
            check(all(page.locator(".au-row").nth(0).locator(f'[data-day="{d}"]').get_attribute("aria-pressed") == "true" for d in "0123456"),
                  "picking all seven days keeps them all picked after saving")
            page.locator(".au-row").nth(0).locator("[data-add-time]").click()
            page.locator(".au-row").nth(0).locator("[data-add-time]").click()
            check(page.locator(".au-row").nth(0).locator("input").count() == 3, "times can be added to a schedule")

            # An AI agent token: make it on the Integrations page, see it once, and
            # connect to /mcp with it as an analyst.
            page.goto(url + "#/integrations")
            page.wait_for_selector("#int-mcp .integ-toggle")
            # AI Alerts has no model of its own: it can't be switched on until AI Parsers has one.
            page.wait_for_selector("#int-aialerts .integ-toggle")
            check(page.is_disabled("#int-aialerts .integ-switch input"), "AI Alerts can't be switched on without a model")
            page.click("#int-aialerts .integ-toggle")
            check("No model yet" in page.inner_text("#aia-model") and page.is_disabled("#aia-run"), "AI Alerts says it needs a model, and can't look")
            # AI Parsers in the cloud: "Allow free models" shows for OpenRouter only, off until chosen.
            page.click("#int-ai .integ-toggle")
            page.click('#int-ai [data-ai-provider="cloud"]')
            check(page.input_value("#ai-service") == "openrouter" and page.is_visible("#ai-free") and not page.is_checked("#ai-free"),
                  "OpenRouter shows 'Allow free models', off by default")
            page.select_option("#ai-service", "anthropic")
            check(not page.is_visible("#ai-free"), "'Allow free models' is not shown for other cloud services")
            check(page.locator("#int-threatfeeds").count() == 0, "Threat feeds is no longer an integration")
            # The Intel page: pick threat feeds, and keep lists of friendly addresses.
            page.click('a[data-nav="intel"]')
            page.wait_for_selector("#tf-list input")
            check(page.locator("#tf-list input").count() >= 4 and page.locator("#tf-list input:checked").count() == 0, "Intel lists the threat feeds on offer, none chosen")
            page.check("#tf-feodo")
            page.click("#tf-save")
            page.wait_for_selector("#tf-msg:not([hidden])")
            check("Saved" in page.inner_text("#tf-msg") and page.is_checked("#tf-feodo"), "choosing a threat feed saves it")
            time.sleep(3.5)  # the list is drawn again while a download is pending; an unsaved tick must survive that
            page.uncheck("#tf-feodo")
            page.click("#tf-save")
            page.wait_for_selector('#tf-msg:has-text("No feeds")')
            check(page.is_hidden("#fr-name") and page.get_attribute("#itab-feeds", "aria-selected") == "true", "Intel opens on Threat Feeds")
            page.click("#itab-friendlies")
            page.wait_for_selector("#fr-name")
            check(page.is_hidden("#tf-list") and "/intel/friendlies" in page.url, "the Friendlies tab shows its own page")
            page.fill("#fr-name", "Office")
            page.fill("#fr-desc", "HQ")
            page.click('#fr-new button[type="submit"]')
            page.wait_for_selector(".fr-list")
            page.fill('.fr-list textarea', "203.0.113.7, 198.51.100.9/24 nonsense")
            page.click(".fr-list .fr-add button")
            page.wait_for_selector(".fr-list .notice:not([hidden])")
            check("aren't IP addresses" in page.inner_text(".fr-list .notice") and page.locator(".fr-entries li").count() == 0, "a bad entry is refused and nothing is added")
            page.fill('.fr-list textarea', "203.0.113.7, 198.51.100.9/24")
            page.click(".fr-list .fr-add button")
            page.wait_for_selector(".fr-entries li")
            texts = page.locator(".fr-entries li .mono").all_inner_texts()
            check(sorted(texts) == ["198.51.100.0/24", "203.0.113.7"], f"addresses and ranges are listed as entered, normalized ({texts})")
            page.click('.fr-entries li button[aria-label="Remove 203.0.113.7"]')
            page.wait_for_selector(".fr-entries li:nth-child(1):last-child")
            page.click(".fr-list .btn-danger")
            page.click("#c-ok")
            page.wait_for_selector(".fr-list", state="detached")
            check(True, "a friendly list can be deleted")
            page.click("#itab-cve")
            page.wait_for_selector("#ipane-cve:not([hidden])")
            check("Coming soon" in page.inner_text("#ipane-cve"), "the CVE tab says it is coming soon")
            page.goto(url + "#/integrations")
            page.wait_for_selector("#int-mcp .integ-toggle")
            # Slack and Teams: off until an address is saved; a wrong address is refused with a reason.
            for kind, bad in (("slack", "https://example.com/hook"), ("teams", "https://hooks.slack.com/services/T/B/x")):
                page.wait_for_selector(f"#int-{kind} .integ-toggle")
                check(page.is_disabled(f"#int-{kind} .integ-switch input"), f"{kind} can't be switched on without an address")
                page.click(f"#int-{kind} .integ-toggle")
                page.fill(f"#chat-{kind}-hook", bad)
                page.click(f'#chat-{kind}-form button[type="submit"]')
                page.wait_for_selector(f"#chat-{kind}-msg:not([hidden])")
                check("look like" in page.inner_text(f"#chat-{kind}-msg"), f"a wrong {kind} address is refused ({page.inner_text(f'#chat-{kind}-msg')[:60]})")
            page.click("#int-mcp .integ-toggle")
            page.fill("#mcp-name", "e2e agent")
            page.select_option("#mcp-level", "analyst")
            page.click("#mcp-create")
            page.wait_for_selector("#dlg-agent[open]")
            agent_token = page.input_value("#ag-token")
            page.click('#ag-tabs button[data-agent="claude"]')
            command = page.inner_text("#ag-code-0")
            check(agent_token.startswith("slmcp_") and "claude mcp add --transport http siemlite" in command and agent_token in command,
                  "a new agent token is shown with a ready-to-run command")
            page.click('#ag-tabs button[data-agent="gemini"]')
            gemini = page.inner_text("#ag-code-0") + page.inner_text("#ag-code-1")
            page.click('#ag-tabs button[data-agent="opencode"]')
            opencode = page.inner_text("#ag-code-0")
            check("gemini mcp add --transport http" in gemini and '"httpUrl"' in gemini and agent_token in gemini,
                  "the dialog has the Gemini CLI command and settings.json")
            check('"type": "remote"' in opencode and '"mcp"' in opencode and agent_token in opencode, "the dialog has the OpenCode config")
            page.click("#dlg-agent .btn-primary")
            page.locator("#mcp-body tr", has_text="e2e agent").wait_for()
            check("Analyst" in page.locator("#mcp-body tr", has_text="e2e agent").inner_text(), "the token is listed with its level")
            # Integrations are listed by state: the agent card has a token, so it is installed and on.
            check(page.is_visible("#int-mcp"), "a card stays on screen while its settings are open after it moves")
            page.goto(url + "#/integrations/active")
            page.wait_for_selector("#gtab-active[aria-selected=true]")
            page.wait_for_selector("#int-mcp:not([hidden])")
            check(page.is_visible("#int-mcp") and page.is_hidden("#int-email") and page.is_hidden("#int-slack"), "Active lists only what is installed and on")
            page.goto(url + "#/integrations/deactivated")
            page.wait_for_selector("#gtab-deactivated[aria-selected=true]")
            page.wait_for_selector("#int-empty:not([hidden])")
            check(page.is_hidden("#int-mcp") and "Nothing is turned off" in page.inner_text("#int-empty"), "Deactivated is empty until one is turned off")
            page.click("#gtab-discover")
            page.wait_for_selector("#int-search")
            check(page.is_visible("#int-email") and page.is_hidden("#int-mcp") and page.inner_text("#int-email .integ-toggle") == "Install",
                  "Discover lists what isn't installed, each with an Install button")
            page.fill("#int-search", "slack")
            check(page.is_visible("#int-slack") and page.is_hidden("#int-email") and page.is_hidden("#int-teams"), "the Discover search narrows the list")
            page.fill("#int-search", "zzzz")
            check("No integration matches" in page.inner_text("#int-empty"), "a search with no match says so")
            page.goto(url + "#/integrations/active")
            page.wait_for_selector("#int-mcp:not([hidden])")
            if page.is_hidden("#mcp-body"):
                page.click("#int-mcp .integ-toggle")
            import json as _json, ssl as _ssl, urllib.request as _rq
            def mcp_call(method, params=None):
                body = _json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}).encode()
                req = _rq.Request(url.rstrip("/") + "/mcp", data=body, headers={"Authorization": "Bearer " + agent_token, "Content-Type": "application/json"})
                return _json.load(_rq.urlopen(req, context=_ssl._create_unverified_context()))
            tool_names = [t["name"] for t in mcp_call("tools/list")["result"]["tools"]]
            check("search_events" in tool_names and "set_alert_status" in tool_names and "create_source" not in tool_names,
                  "an analyst token lists the analyst tools and not the admin ones")
            found = mcp_call("tools/call", {"name": "search_events", "arguments": {"q": "failed", "limit": 3}})["result"]
            check(not found["isError"] and "events" in found["content"][0]["text"], "an agent can search events through /mcp")
            raised = mcp_call("tools/call", {"name": "create_alert", "arguments": {"title": "E2E agent finding", "severity": 4, "group_by": "src_ip",
                                                                                  "group_value": "10.2.3.4", "note": "found by the e2e agent"}})["result"]
            check("create_alert" in tool_names and not raised["isError"], "an analyst token can raise an alert through /mcp")
            page.locator("#mcp-body tr", has_text="e2e agent").get_by_role("button", name="Remove").click()
            page.click("#c-ok")
            page.locator("#mcp-body tr", has_text="e2e agent").wait_for(state="detached")
            try:
                mcp_call("tools/list")
                refused = False
            except Exception:
                refused = True
            check(refused, "a removed token is refused")

            # Acknowledge and close an alert.
            page.goto(url + "#/alerts")
            page.wait_for_selector("#alerts-body tr")
            agent_row = page.locator("#alerts-body tr", has_text="E2E agent finding")
            check(agent_row.count() == 1 and "found by the e2e agent" in agent_row.inner_text() and "10.2.3.4" in agent_row.inner_text(),
                  "an alert an agent raised is listed with its note")
            before = page.locator("#alerts-body tr").count()
            page.locator("#alerts-body tr").first.get_by_role("button", name="Acknowledge").click()
            # (Not wait_for_function: its predicate is eval'd in the page, which
            # the Content-Security-Policy forbids. Wait for the last row to go.)
            page.locator("#alerts-body tr").nth(before - 1).wait_for(state="detached")
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

            # The Connect screen fits a phone, and its code scrolls inside itself.
            phone.goto(url + "#/sources")
            phone.wait_for_selector("#view-sources tbody tr")
            phone.click("#add-source")
            phone.fill("#s-name", "Phone app")
            phone.click("#s-save")
            phone.wait_for_selector("#dlg-token", state="visible")
            for lang in ["curl", "go", "react"]:
                phone.click("#tab-" + lang)
                if lang == "go":
                    check(phone.evaluate("(() => { const p = document.getElementById('code-go'); return p.scrollWidth > p.clientWidth && getComputedStyle(p).overflowX === 'auto'; })()"),
                          "a long code block scrolls sideways inside itself")
                over = phone.evaluate("document.documentElement.scrollWidth - document.documentElement.clientWidth")
                dlg_over = phone.evaluate("(() => { const d = document.getElementById('dlg-token'); return d.scrollWidth - d.clientWidth; })()")
                check(over <= 0 and dlg_over <= 0, f"the Connect screen fits a phone on the {lang} tab (page {over}px, dialog {dlg_over}px)")
            phone.keyboard.press("Escape")

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
    main(sys.argv[1] if len(sys.argv) > 1 else "./siemlite", sys.argv[2] if len(sys.argv) > 2 else "./loggen")
