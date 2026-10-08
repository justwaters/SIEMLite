# SIEMLite design

How the web UI looks, why, and how the light and dark themes work. Everything here is read from `web/static/index.html`
(the whole UI is one file: CSS, markup and script) as of v0.9.1. The marketing site (`web` branch) and the docs
subsite reuse the same tokens.

## The idea

**The interface is monochrome. Colour only ever means severity.** That is the one rule everything else follows
from (it's the first comment in the stylesheet). A SIEM is read for long stretches by someone hunting for the one
thing that matters, so the chrome stays out of the way: greys for structure, a single ink colour for emphasis, and
colour reserved for "how bad is this". If something is red it is a threat or an error; nothing is coloured just to
look good.

Consequences you can see in the UI:
- Primary buttons are not a brand colour. They are `--ink` on `--paper`, inverted (white on near-black in light,
  near-white on charcoal in dark).
- The current page, the selected segment and the hovered row all use the same `--raised` grey.
- The only colourful things on a page are severity swatches, threat markers, the "open alert" count and status text.
- No decoration: no gradients, no illustrations, almost no shadow (only floating things get one).

## Theme logic

Three choices in a segmented control at the bottom of the sidebar: **System** (default), **Light**, **Dark**.

| Piece | How it works |
|---|---|
| Storage | `localStorage["siemlite-theme"]` holds `"light"` or `"dark"`. **System** removes the key. Reads and writes are in `try/catch`, so a blocked storage just means no saved choice. |
| No flash | An inline script in `<head>` runs before first paint and sets `<html data-theme="…">` from storage, so a saved dark theme never flashes light. |
| Light | The default `:root` block (with `color-scheme: light`). |
| Dark, by choice | `:root[data-theme="dark"]` overrides every token. |
| Dark, by system | `@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) { … } }`. The `:not([data-theme="light"])` is what lets an explicit **Light** beat a dark system. |
| Native controls | `color-scheme: light` / `dark` is set with the tokens, so scrollbars, date pickers, form controls and the `<dialog>` backdrop follow the theme. |
| Switching | `setTheme()` sets or clears `data-theme`, updates storage, sets `aria-pressed` on the three buttons, and redraws the dashboard chart. Nothing else needs to change: every colour in the page comes from a CSS variable, including the chart (SVG fills are `var(--sev-5)` etc.), so a switch is instant. |
| Following the OS live | While on **System**, a change in the OS theme applies immediately, because it is pure CSS. |

Everything that has a colour reads a token. The only literal colours in the stylesheet are the overlays and
shadows (see "Elevation") and one `#fff` (see "Findings").

## Colour

Both themes use the same token names, so no component knows which theme it is in. Light is the default `:root`;
dark overrides every token.

### Core tokens

| Token | Light | Dark | Role |
|---|---|---|---|
| `--paper` | `#f2f3f1` | `#1a1e21` | Page background, sidebar, sticky bars. Light is a faint green-grey, not white; dark is a blue-leaning charcoal, not black. |
| `--surface` | `#ffffff` | `#21262a` | Containers: panels, tables, inputs, dialogs, tooltips. |
| `--raised` | `#e9ebe8` | `#2a3035` | Hover, selected, pressed; code blocks inside dialogs; the expanded event row. |
| `--ink` | `#1c1f21` | `#e4e6e3` | Primary text, focus outline, and the primary button's fill. Neither theme uses pure black or white. |
| `--ink-2` | `#5f666b` | `#8f979c` | Secondary text, labels, icons, placeholders. |
| `--rule` | `#d9dcd8` | `#30363a` | Every border and divider; also the switch track and chart gridlines. |
| `--chart-other` | `#5f666b` | `#7d858a` | Non-threat bars and the "Other events" series: a neutral, so red stands out. |

**How depth works.** Light puts the *lightest* colour on top: the page is grey, and containers are white, so
panels lift off it. Dark does the reverse in luminance but the same in structure: the page is darkest and
containers get lighter (`paper → surface → raised`). In both, depth comes from the surface step plus a 1px
`--rule` border, not from shadow. Because `--surface` is brighter than `--paper` in *both* themes, the same CSS
works unchanged.

**The primary button inverts with the theme:** `--ink` fill with `--paper` text, so it is near-black in light and
near-white in dark (13.4–14.9:1 either way).

### Severity (the only colour)

| Level | Name | Light | Dark |
|---|---|---|---|
| `--sev-0` | Unknown | `#8a949b` | `#78828a` |
| `--sev-1` | Informational | `#6c7a86` | `#8796a3` |
| `--sev-2` | Low | `#2f8463` | `#49a985` |
| `--sev-3` | Medium | `#a47f12` | `#cfa52a` |
| `--sev-4` | High | `#c35a1c` | `#e2793a` |
| `--sev-5` | Critical | `#c1333a` | `#e05257` |
| `--sev-6` | Fatal | `#8c2b69` | `#c0559a` |

The scale reads cool grey → green → amber → orange → red → magenta, so "worse" is also "hotter", and Fatal is a
distinct hue rather than just a deeper red.

**Why the two columns differ.** Each hue is re-tuned per theme rather than shared. Light uses deeper, darker
values so they hold against white and pale grey; dark uses lighter, slightly less saturated values so they don't
glare or vibrate on charcoal. Informational is the clearest case: it is darker than the page in light and
lighter than it in dark, so it stays the quiet end of the scale in both.

Where colour appears: the 9px square beside a severity name; the bars in "By severity"; the threat-intel series
and the red left edge (`inset 3px`) on threat rows and match boxes; the `INTEL` tag outline; status text (open =
red, acknowledged = amber, closed = grey); the green status dot and "on" pill (`--sev-2`); errors and the red
unread alert count; danger buttons (text only).

### Contrast, measured (WCAG ratios)

Core pairs:

| Pair | Light | Dark |
|---|---|---|
| `--ink` on `--paper` | 14.9 | 13.4 |
| `--ink` on `--surface` | 16.6 | 12.2 |
| `--ink` on `--raised` | 13.8 | 10.6 |
| `--ink-2` on `--paper` | 5.2 | 5.7 |
| `--ink-2` on `--surface` | 5.8 | 5.1 |
| `--ink-2` on `--raised` | 4.9 | **4.5** (at the AA line) |
| `--rule` on `--paper` | 1.2 | 1.4 (dividers only; not meant to be read) |
| White on `--sev-5` (alert count badge) | 5.5 | **3.8** |

Severity colours as they are actually used, as text or swatches on `--surface` (panels, tables) and `--paper`
(notices):

| Level | Light on surface / paper | Dark on surface / paper |
|---|---|---|
| 0 Unknown | 3.1 / 2.8 | 3.9 / 4.3 |
| 1 Informational | 4.4 / 4.0 | 5.0 / 5.5 |
| 2 Low | 4.6 / **4.1** | 5.3 / 5.8 |
| 3 Medium | **3.7** / 3.4 | 6.6 / 7.2 |
| 4 High | 4.4 / 3.9 | 5.1 / 5.6 |
| 5 Critical | 5.5 / 5.0 | **4.0** / 4.4 |
| 6 Fatal | 7.9 / 7.1 | **3.6** / 4.0 |

Swatches and bars only need 3:1; text needs 4.5:1. The bold values are where a colour is used as *text* and falls
short (see Findings). Swatches always come with a severity name beside them, so colour is never the only signal.

## Typography

Two families, both bundled as WOFF2 in the binary (`web/static/fonts/`) so the UI never contacts a font service.

| Family | Use | Axes |
|---|---|---|
| **Instrument Sans** | All interface text. | Variable: weight 400–700, width 75–100%. |
| **Spline Sans Mono** | Search input, log lines, IPs, tokens, code, parser patterns, dates. | Weight 400–600. |

The width axis is used on purpose: the wordmark and `h1` are condensed (`font-stretch: 88%` and `92%`), which
gives headings a tight, engineered feel without a third font. `font-display: swap`, and `-webkit-font-smoothing:
antialiased` for light-on-dark crispness.

| Element | Size / weight |
|---|---|
| Body | 15px / 1.5, 400 |
| Page title (`h1`) | 28px / 1.2, 600, `letter-spacing: -.3px`, width 92% |
| Wordmark | 19px, 650, `-.2px`, width 88% (26px on sign-in) |
| Dashboard hero figure | 52px, 600, `-1.2px` |
| Figures | 30px (26px on System), 600, `-.5px` |
| Dashboard search | 21px mono (17px on phones) |
| Dialog title | 19px, 600 |
| Panel title | 15px, 600 |
| Table cell / button | 15px (inherits) / 13.5px for small buttons and times |
| Labels, hints, subtext | 13px, `--ink-2` |
| Table header | 12.5px, weight 500, `--ink-2` |
| Chart axis, tags | 11.5px / 12px |
| Mono | 13px (12–12.5px inside dense blocks) |

Numbers use `font-variant-numeric: tabular-nums` wherever they stack (times, counts, fact lists), so columns
don't jitter as values change. Sentence case everywhere; there are no uppercase or tracked-out labels. Hierarchy
comes from size, weight and `--ink` versus `--ink-2`, not from colour.

## Spacing, shape and layout

There is no formal scale; the working rhythm is 4 / 6 / 8 / 10 / 12 / 14 / 16 / 18 / 20 / 22 px.

| Thing | Value |
|---|---|
| App shell | Two columns: sidebar `236px` + fluid main. Sidebar is sticky, full height, `1px` right rule, `22px 16px 18px` padding, `26px` gap between its groups. |
| Main | `padding: 0 40px 48px`; each page starts `34px` down. |
| Page header | Title left, actions right, `22px` below. |
| Nav item | `8px 10px` padding, `10px` icon gap, `2px` between items, `18px` icons (1.8 stroke, round caps). |
| Panel / figure | `18px 20px` padding. Dashboard cards sit `16px` apart. |
| Figures strip | One bordered rounded block with `1px` gaps showing `--rule` through: columns `1.4fr 1fr 1fr` (the first, "Events", is the hero). |
| Tables | Cell padding `9px 12px`; rows divided by `--rule`; no zebra. |
| Controls | Height `36px` (small `30px`, sign-in `42px`, phone date range `44px`). |
| Dialog | Width `min(520px, 100vw − 32px)` (`760px` for wide), form padding `22px`, gap `14px`. |
| Dashboard | Search is centred, `max-width: 820px`, `9vh` from the top; the figures start `56px` below it. |

**Radii** step with size: `6px` controls and nav items, `7–8px` segmented controls and small boxes, `10px`
panels, tables and search fields, `12px` dialogs, `50%` dots and the spinner, `2px` severity swatches.

**Alignment:** left-aligned throughout. Only empty states and the dashboard search hint centre.

### Responsive

- **≤ 1100px:** the parser editor stacks; the three dashboard lists become two columns.
- **≤ 860px:** the sidebar becomes an off-canvas drawer (`min(300px, 86vw)`, slides in over `.25s`), a top bar with a menu button appears, main padding drops to `16px`, figures go two-up (hero spans both), lists and forms go single-column.

## Components

- **Buttons:** 1px `--rule` border on `--surface`; hover goes to `--raised`; disabled is `.45` opacity. Primary inverts to `--ink`/`--paper` and hovers to `.88` opacity. Danger only changes the text to `--sev-5`.
- **Inputs:** `--surface` fill, `--rule` border, `6px` radius; focus changes the border to `--ink-2` (no glow).
- **Search field:** the exception. `10px` radius, and on focus the border darkens and a `4px` `--raised` ring appears.
- **Segmented control:** an inset track on `--surface`; the selected segment is `--raised`. Used for time range, themes and tabs.
- **Switch:** `32×18` track, `--rule` off, `--ink` on; the thumb is `--surface` and slides `14px`.
- **Tags and pills:** outlined, never filled: `INTEL` is a 1px `--sev-5` inset ring, plain tags a `--rule` ring. The "on" pill is a `--sev-2` ring.
- **Chart:** inline SVG, `220px` tall, gridlines in `--rule`, bars with rounded tops, stacked threat (red) over other (neutral). Tooltip is a small `--surface` card.
- **Dialogs:** native `<dialog>`; backdrop is `rgba(10,12,14,.45)`.
- **Sign-in and "restarting" screens:** full-screen `--paper`, centred, no card.

## Motion

Deliberately minimal: the interface does not animate for its own sake, and hover and selection changes are
instant.

| What | Timing |
|---|---|
| Switch track colour and thumb | `.15s` |
| Search field border and focus ring | `.2s` |
| Mobile sidebar slide | `.25s ease` |
| Spinner (loading, restoring, updating) | `.8s linear`, infinite |

`@media (prefers-reduced-motion: reduce)` turns every transition and animation off, including the spinner.
Page changes are hash-routed and swap immediately.

## Elevation

Only things that float get a shadow, and shadows are tuned for dark ground:
- Tooltip: `0 8px 24px -12px rgba(0,0,0,.4)`
- Dialog: `0 30px 80px -30px rgba(0,0,0,.55)`
- Open mobile drawer: a `100vmax` `rgba(0,0,0,.35)` dim around it.

The negative spread keeps the shadow tight under the element, so it reads in both themes.

## Accessibility

- Focus: `2px solid --ink` outline, `2px` offset, on every `:focus-visible`; the switch shows it on its track.
- Hidden-but-readable text uses a `.visually-hidden` class, and the switch's real checkbox stays in the page.
- Segmented buttons use `aria-pressed` / `aria-selected`; the current page is `aria-current="page"`; the chart's bars have focusable hit areas with the tooltip.
- Status is never colour alone: severity has a name beside the swatch, threats have the `INTEL` tag, and a disabled source is struck through.
- Touch targets: `.icon-btn` is 36px, controls 36px, phone date range 44px.

## Findings

Things I noticed while reading, not yet changed.

**Dark theme**
1. **Small red text is under AA.** `--sev-5` on `--surface` is 4.0:1 and on `--paper` 4.4:1, below the 4.5:1 for normal-size text. It's used for `.status-open`, `.notice.bad`, errors and the bold titles in threat-match boxes. Fatal (3.6:1) and Unknown (3.9:1) are only swatches, where 3:1 is enough. Lightening dark `--sev-5` a little (about `#ea6a6f`) would fix the text uses.
2. **The unread-alert count** is `#fff` on `--sev-5` at 12px bold, 3.8:1 (5.5:1 in light). Same fix: a lighter red in dark, or dark text on it.
3. **`--ink-2` on `--raised` is exactly 4.5:1.** Hovered rows, expanded event details and the selected segment all put secondary text there, so there is no headroom. Nudging dark `--ink-2` up one step would give some.

**Light theme**
4. **Amber text is the weakest pair in the app.** `--sev-3` on `--surface` is 3.7:1, and `.status-acknowledged` uses it as bold table text. Darkening light `--sev-3` (for example `#8a6a0e`) would pass.
5. **Green on the page background:** `.notice.ok` puts `--sev-2` text on `--paper` at 4.1:1 (4.6:1 on a panel). It's a small miss; darkening light `--sev-2` slightly fixes it.
6. **`--ink-2` is comfortable everywhere** (4.9–5.8:1), so light has none of the secondary-text problem dark has.

**Both**
7. **The dark token list is written twice** (the `prefers-color-scheme` block and the `[data-theme="dark"]` block). They are identical today, but will drift if only one is edited. Defining the palette once would remove the risk.
8. **A few literal colours bypass the tokens:** the shadows, the dialog backdrop and the `#fff` in finding 2. They are the places a future theme would miss.
9. **No hover or press transitions.** Consistent with the minimal approach, but buttons and rows change state with no easing; a `.1s` colour transition would soften it, and reduced-motion already covers it.
10. **Three copies of the palette.** The docs subsite (`docs/docs.css`) and the marketing site each carry their own light and dark tokens (a subset: no `sev-0`, `sev-6` or `chart-other`). Changing a token in the app means editing three files.
11. **Contrast was computed from the token values, not from rendered screens.** A component that overrides a colour inline, or text placed on a surface I didn't pair, wouldn't show up here.
