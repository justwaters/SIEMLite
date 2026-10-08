/* Turns the docs into a single-page app without giving up the static pages: every page is still its own
   file (so links, search engines and no-JS browsers work), and this swaps the page content in place
   when a link inside the docs is followed. */
(() => {
  const main = document.querySelector("main.doc");
  const side = document.querySelector(".side");
  if (!main || !side || !window.fetch || !history.pushState) return;

  const clean = (path) => path.replace(/index\.html$/, "");
  const root = clean(new URL("./", location.href).pathname);
  const pages = new Map();
  let current = clean(location.pathname);

  const inDocs = (url) => url.origin === location.origin && clean(url.pathname).startsWith(root) &&
    (url.pathname.endsWith("/") || url.pathname.endsWith(".html"));

  function fetchPage(url) {
    const key = clean(url.pathname);
    if (!pages.has(key)) {
      const p = fetch(url.pathname).then((r) => {
        if (!r.ok) throw new Error(r.statusText);
        return r.text();
      });
      p.catch(() => pages.delete(key));
      pages.set(key, p);
    }
    return pages.get(key);
  }

  function markCurrent(path) {
    for (const a of side.querySelectorAll("a")) {
      if (clean(new URL(a.href).pathname) === path) a.setAttribute("aria-current", "page");
      else a.removeAttribute("aria-current");
    }
  }

  function reveal(hash) {
    const target = hash.length > 1 && document.getElementById(decodeURIComponent(hash.slice(1)));
    if (target) target.scrollIntoView();
    else window.scrollTo(0, 0);
  }

  async function show(url, push) {
    if (clean(url.pathname) === current) {   // same page: only the #anchor changes
      if (push) history.pushState(null, "", url);
      reveal(url.hash);
      return;
    }
    try {
      const doc = new DOMParser().parseFromString(await fetchPage(url), "text/html");
      const next = doc.querySelector("main.doc");
      if (!next) throw new Error("not a docs page");
      main.innerHTML = next.innerHTML;
      document.title = doc.title;
      const desc = doc.querySelector('meta[name="description"]');
      if (desc) document.querySelector('meta[name="description"]')?.setAttribute("content", desc.content);
      current = clean(url.pathname);
      markCurrent(current);
      if (push) history.pushState(null, "", url);
      reveal(url.hash);
      // Keyboard and screen reader users start at the new page, as after a normal load.
      main.setAttribute("tabindex", "-1");
      main.focus({ preventScroll: true });
    } catch {
      location.href = url.href;   // anything unexpected: a normal page load
    }
  }

  document.addEventListener("click", (e) => {
    const a = e.target.closest?.("a[href]");
    if (!a || e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    if (a.target && a.target !== "_self" || a.hasAttribute("download")) return;
    const url = new URL(a.href);
    if (!inDocs(url)) return;
    e.preventDefault();
    show(url, true);
  });

  // Fetch a page as soon as someone points at its link, so the click feels instant.
  const warm = (e) => {
    const a = e.target.closest?.("a[href]");
    if (!a) return;
    const url = new URL(a.href);
    if (inDocs(url) && clean(url.pathname) !== current) fetchPage(url).catch(() => {});
  };
  document.addEventListener("mouseover", warm);
  document.addEventListener("focusin", warm);

  addEventListener("popstate", () => show(new URL(location.href), false));
  history.scrollRestoration = "manual";
})();
