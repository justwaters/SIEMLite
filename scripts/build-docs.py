#!/usr/bin/env python3
"""Builds docs/ (the documentation subsite) from the project wiki.

    git clone https://github.com/justwaters/SIEMLite.wiki.git
    pip install markdown
    python3 scripts/build-docs.py SIEMLite.wiki

Every wiki page becomes docs/<page>.html (Home becomes index.html), wrapped in the
site's own look. The wiki is the source: edit it there, then rebuild and commit docs/.
"""
import html, pathlib, re, sys
import markdown

if len(sys.argv) != 2:
    sys.exit(__doc__)
wiki = pathlib.Path(sys.argv[1])
out = pathlib.Path(__file__).resolve().parent.parent / "docs"
pages = sorted(p.stem for p in wiki.glob("*.md") if not p.stem.startswith("_"))

def target(name):
    return "./" if name == "Home" else name.lower() + ".html"

def blank_before_lists(text):
    """GitHub lets a list follow a paragraph directly; Python-Markdown needs a blank line first."""
    out, fenced, prev = [], False, ""
    for line in text.split("\n"):
        if line.lstrip().startswith("```"):
            fenced = not fenced
        elif not fenced and re.match(r"[-*] ", line) and prev.strip() and not re.match(r"\s*([-*] |\d+\. )", prev) and not prev.startswith(" "):
            out.append("")
        out.append(line)
        prev = line
    return "\n".join(out)

def md(text):
    text = blank_before_lists(text)
    return markdown.markdown(text, extensions=["tables", "fenced_code", "toc"], extension_configs={"toc": {"permalink": False}})

def links(h):
    # Wiki links are bare page names, optionally with #anchor; leave everything else alone.
    def sub(m):
        name, frag = m.group(2), m.group(3) or ""
        return f'{m.group(1)}"{target(name)}{frag}"' if name in pages else m.group(0)
    return re.sub(r'(href=)"([A-Za-z0-9-]+)(#[^"]*)?"', sub, h)

def tables(h):
    return h.replace("<table>", '<div class="tablewrap"><table>').replace("</table>", "</table></div>")

side = links(md((wiki / "_Sidebar.md").read_text()))
TEMPLATE = (pathlib.Path(__file__).parent / "docs-template.html").read_text()

for name in pages:
    src = (wiki / f"{name}.md").read_text()
    body = tables(links(md(src)))
    title = re.search(r"^# (.+)$", src, re.M).group(1)
    first = re.search(r"^(?!#|\s*[-*|`>]|\s*$)(.+)$", src, re.M)
    desc = re.sub(r"\[([^\]]+)\]\([^)]*\)|[`*]", lambda m: m.group(1) or "", first.group(1))[:200] if first else "SIEMLite documentation"
    here = target(name)
    nav = re.sub(r'<a href="%s"' % re.escape(here), '<a aria-current="page" href="%s"' % here, side)
    page = (TEMPLATE.replace("{{title}}", html.escape(title) + (" · SIEMLite docs" if name != "Home" else ""))
            .replace("{{description}}", html.escape(desc, quote=True)).replace("{{nav}}", nav).replace("{{body}}", body))
    (out / ("index.html" if name == "Home" else name.lower() + ".html")).write_text(page)
print(f"built {len(pages)} pages in {out}")
