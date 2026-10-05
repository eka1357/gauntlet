# DESIGN.md — Gauntlet

## Direction
Gauntlet is a test instrument, like the telemetry sheet from a flight-test range: calm, exact, legible under pressure. The UI is monochrome ink on paper, and colour is reserved for meaning only: red = breached, teal = cleared, amber = in flight. Avoid hacker-terminal green-on-black and generic SaaS cards.

## The one memorable thing: the Range
A grid where rows are attack channels (email, web page, document, tool argument, image) and columns are generations. Every attack is a small square. Amber while running, grey if blocked, red if it breached. During a run, red squares cascade as evolution finds weaknesses. After hardening, the same grid replays and goes grey. Everything else on screen stays quiet so this carries the demo. A single large number beside it shows breach rate, with a before/after wipe when verification completes.

## Tokens (check contrast in realtimecolors.com before locking)
| Name | Hex | Use |
|---|---|---|
| Range paper | #EAEEF0 | Page background |
| Panel | #F8FAFB | Surfaces |
| Ink | #13232E | Text, primary buttons, icons |
| Rule | #C9D3D9 | Borders, grid lines |
| Breach | #C4352A | Breached attacks, critical severity |
| Cleared | #1E7A68 | Fixed or passing |
| In flight | #D9962B | Running, pending approval |
Buttons are solid Ink with Panel text; there is no separate brand accent. Optional dark theme: invert surfaces to #0F1A22 / #16252F and keep the same three semantic colours, lightened for contrast.

Put these in `web/styles/tokens.css` as CSS variables and map them in Tailwind. Components never use raw hex.

## Type
- Display and numbers: Bricolage Grotesque, weights 600-700, used for the page title, run name and the big breach-rate figure.
- Body and UI: IBM Plex Sans, 400/500.
- Traces, payloads, policy YAML: IBM Plex Mono. Mono is only for real code and traces, not decorative labels.
- Scale: 12 / 14 / 16 / 20 / 28 / 44, and 72 only for the breach-rate figure. Sentence case everywhere. Line length under 75 characters.

## Layout
```
+--------------------------------------------------------------+
| Gauntlet   Run: inbox-assistant #12         cost $0.41  4:12 |
+--------+-----------------------------------------+-----------+
| Config | THE RANGE                               | Findings  |
|        |   email   . . # . # # . .               | 3 root    |
| target |   web     . # . . # . . .               | causes    |
| budget |   doc     . . . # . . . .   38% -> 0.7% | > cluster |
| gens   |   tool    . # # . . . . .   breach rate | > trace   |
| [Run]  |   image   . . . . # . . .               |           |
+--------+-----------------------------------------+-----------+
| Charts: breach rate per generation | outcome flow | cost    |
+--------------------------------------------------------------+
```
- Left rail is narrow and fixed. Centre is the Range at full width. Right drawer opens on a cluster and shows the trace with the exact tool call that leaked.
- Left-align text. Numbers right-align in tables.
- Report page: a single column document, like a printed test report, with the before/after table first.
- No marketing landing page. The first screen is the product with the recorded run loaded and a clear "Start a live run" action.

## Motion
- One orchestrated moment: the before/after wipe when verification completes (Motion `layout` and `animate`, about 900 ms, ease-out).
- Responsive motion only: squares changing state, the findings drawer opening, counters ticking with real values.
- No scroll-triggered fade-ups, no hover lift on every card. Respect `prefers-reduced-motion` by swapping animation for instant state changes.

## Libraries: what to use (and what to skip)
- **shadcn/ui + Tailwind**: base components. Needed because Bklit installs through the shadcn registry.
- **Bklit UI (ui.bklit.com)**: use for the charts. Install with `npx shadcn@latest add @bklit/line-chart` (also `area-chart`, `ring-chart`, `sankey-chart`). Use: breach rate by generation (line), cluster share (ring), attack to channel to outcome flow (sankey). Theme with its CSS variables, mapped to the tokens above.
- **Motion (motion.dev)**: all animation. Use `AnimatePresence` for the drawer and `animate` for number tickers and the wipe.
- **realtimecolors.com**: paste the tokens to check contrast and a dark variant. Design aid only, not a dependency.
- **React Bits (reactbits.dev)**: at most one component, such as a number count-up, copied in via its CLI. Skip its backgrounds. Check the exact component name on the site first.
- **Skiper UI (skiper-ui.com), ui.watermelon.sh**: I could not verify these, so skip unless you find one specific component the design lacks. More effects make it look more generated, not less.
- **Manus (manus.im)** is an AI agent, not a component library. It is not part of the build.

## Real content, not placeholders
- Demo target is a fictional freight company. Generate 40+ realistic fake emails, 6 web pages, 4 documents and 3 invoice images with Nano once, review them, and commit as fixtures.
- Never show lorem ipsum, "Acme", or stock people.
- Error text says what happened and what to do ("Token Factory returned 429. Lower concurrency in Config and retry."). Empty states invite action ("No run yet. Start one, or open the recorded run.").

## Images and assets
- Logo: a simple SVG mark of two converging lines forming a gate (the corridor). Hand-authored SVG, no AI art.
- Favicon and app icon from the same SVG.
- Real screenshots only: a Playwright script (`scripts/screenshots.ts`) captures the Range mid-run, the finding drawer, the before/after, and the report at 1440 px and 390 px. Use them in the README, the Devpost gallery and the OG image (1200x630).
- Architecture diagram: Mermaid in the README, exported to SVG, drawn in the same palette.
- Invoice attack images are rendered by code (PIL) with a believable invoice layout.
- Optional: one monochrome line-art empty-state illustration. If you generate it, use the prompt in PROMPTS.md and keep it ink-on-paper.

## Anti-generated checklist (review before every demo)
- [ ] Colour only carries meaning; no gradients as decoration
- [ ] Radius scale by hierarchy (2 / 6 / 10 px), not one radius everywhere; panels are not a grid of identical cards
- [ ] No ALL-CAPS tracked eyebrow labels; no "01 / 02 / 03" except real sequences
- [ ] Headline has no single accented word
- [ ] No middle-dot meta strings, no arrows on every link
- [ ] Motion is limited to the wipe and state changes
- [ ] All numbers come from stored runs
- [ ] Keyboard focus visible; works at 390 px; 4.5:1 contrast
