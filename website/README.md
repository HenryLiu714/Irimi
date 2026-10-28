# irimi website

The landing page and docs site, built with [Astro](https://astro.build) and
[Starlight](https://starlight.astro.build). The docs pages are generated from `../docs/*.md` and
sections of `../README.md` by `scripts/sync.mjs` on every `dev` and `build`; edit those files, not
the generated ones under `src/content/docs/docs/`.

```
npm ci
npm run dev        # http://localhost:4321
npm run build      # static site in dist/
npm run test:unit  # the sync script
npm run test:links # broken links and anchors in dist/
npx playwright install chromium && npm run test:e2e   # browser tests against a fresh build
```

The public URL is `SITE` in `astro.config.mjs`.
