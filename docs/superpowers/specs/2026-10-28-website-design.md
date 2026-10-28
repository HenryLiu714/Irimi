# irimi website: design

## Intent

A public website for irimi: a landing page plus documentation. Visitors are people who want to use
irimi, or who saw it online and are curious. Before they leave they should understand what irimi
is, what problem it solves, and be able to install and use it with little effort.

## Goals

- A homepage that explains irimi and its problem in the first screen, then shows install and use.
- Installation that is simple for a human, and has an agent-friendly path.
- Usage docs laid out like the docs sites of comparable tools (uv, Bun, Astro): left sidebar,
  content, "on this page" table of contents, search, prev/next.
- The docs come straight from the repo's `docs/*.md`, so the site never drifts from the repo.
- Modern startup look, verified working in a real browser at desktop and phone widths.

## Non-goals

- Hosting, domain and deploy. The team has a domain but has not settled it; the site builds to
  static files and runs locally. A deploy workflow is out of scope.
- Rewriting doc content. The website renders what `docs/` says.
- Blog, pricing, sign-up, analytics, newsletter.

## Anti-goals

- Low contrast or hard-to-read text. Readability beats looks: body text meets WCAG AA (4.5:1) in
  both themes, code blocks included.
- Overclaiming. The homepage keeps the README's honesty: it says what irimi does not catch.
- Doc copies that drift: no hand-maintained duplicate of a `docs/` page.

## Decisions (made with the owner)

- **Look: dark, terminal-first** (like uv, Bun, Warp). The real irimi summary output is the hero
  image. A light theme also exists, with dark the default.
- **Docs source: `docs/*.md`, directly.**
- **Homepage sections, in order:** nav; hero (headline, one-line pitch, install command with copy
  button, the real double-refund summary from the README); the problem; how it works (agent →
  irimi → service; reads pass, writes faked, later reads see the writes); install with Human /
  Agent tabs; comparison table (from the README "Why" table); supported services (from the README
  table); what irimi does not catch (short, linked to the limitations page); closing CTA; footer
  (GitHub, PyPI, Apache-2.0).
- **Agent install path:** the Agent tab offers a "Copy prompt" button. The prompt tells a coding
  agent to install irimi and run the user's agent under shadow, and points at `/llms.txt`. The site
  also serves `/llms.txt` (an index for AI tools, per llmstxt.org), `/llms-full.txt` (every docs
  page in one file) and a raw `.md` copy of every docs page. Docs pages have a "Copy page as
  Markdown" button.

## Builder's calls (made by Claude, open to change)

- **Stack:** Astro with the Starlight docs theme, in `website/` at the repo root. Node, npm,
  lockfile committed. Builds to static files in `website/dist/`. Starlight gives sidebar, TOC,
  search (Pagefind), dark/light toggle and mobile nav out of the box; the homepage is a custom
  Astro page with its own styling in the same palette.
- **Docs sync:** a script run before `dev` and `build` reads `docs/*.md` and writes generated
  pages into the Starlight content folder (gitignored). It takes the title from the first `# H1`
  (removing it from the body) and adds frontmatter; rewrites `foo.md#x` links to site routes;
  rewrites links that leave `docs/` (`../examples/...`, `../src/...`) to GitHub URLs. The `docs/`
  files are not edited. `docs/superpowers/` is excluded.
- **Getting started pages:** `docs/` has no install or quickstart page; those live in the root
  `README.md`. The sync script also extracts the README's Quickstart, What is supported and
  Troubleshooting sections into an Introduction and an Installation & quickstart page, so they
  stay from source too.
- **Homepage content from the README:** the hero's summary output (the code block under "What you
  get"), the comparison table ("Why") and the supported-services table are extracted from
  `README.md` by the same sync script into a JSON data file the homepage renders. The build fails
  loudly if a heading or block it expects is missing. The headline, pitch, how-it-works steps and
  the short "does not catch" list are hand-written marketing copy that links to the full pages.
  `docs/README.md` becomes the docs index page.
- **Sidebar groups,** following `docs/README.md`: Getting started (Introduction, Installation &
  quickstart, Concepts); Using irimi (How it works, Reading the summary, CLI, SDK, Serve mode,
  Replay, Limitations); Reference (Security, Service maps, Trace format, Control protocol);
  Contributing (Architecture, Adding a service).
- **Mermaid** diagrams (in `how-it-works.md`) render client-side, themed for dark and light.
- **GitHub URL:** `https://github.com/HenryLiu714/Irimi`, as the README uses. PyPI:
  `https://pypi.org/project/irimi/`.
- **Site URL** is a single config value (`site` in `astro.config.mjs`), placeholder until the
  domain is known; `llms.txt` and the agent prompt read it from there.
- **Repo integration:** `website/` stays out of the Python tooling (ruff, mypy, pytest do not see
  it). `make website` / `make website-dev` targets. A CI job that builds the site is in scope only
  if cheap; deploy is not.
- **Verification:** run the built site in a browser; check homepage, every docs page, copy buttons,
  tabs, search, theme toggle, mobile nav and 375px width; check links with a link checker on the
  built output. Adversarial review by subagents of the design and the finished site.
