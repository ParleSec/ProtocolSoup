# ProtocolSoup GEL design tokens and brand assets

Canonical source for the ProtocolSoup Global Expression Language (GEL). The guidelines are at [docs.protocolsoup.com/developers/design-system](https://docs.protocolsoup.com/developers/design-system/).

| File | Consumed by |
|------|-------------|
| `tokens.css` | frontend, wallet-ui, docs (plain `--ps-*` custom properties) |
| `tailwind-theme.css` | frontend, wallet-ui (Tailwind v4 `@theme`, base layer, shared utilities) |
| `brand/wordmark.generated.ts` | frontend (`Wordmark` / `WordmarkArt` in `components/common/Brand.tsx`, also used by the `next/og` cards) |
| `brand/wordmark-dark.svg`, `brand/wordmark-light.svg` | frontend and wallet `public/brand/`, docs `src/assets/` (Starlight header, API reference, share cards) |

1. Edit the token files here, never the copies under `*/src/styles/design/`.
2. Run `node design/sync-tokens.mjs` from `ProtocolSoup/` and commit the copies with your change.
3. CI runs `node design/sync-tokens.mjs --check` and fails if a copy is stale.

## Regenerating the wordmark

The wordmark is JetBrains Mono Bold outlines with the bowl drawn as the "o" of Soup, so it renders identically everywhere regardless of font loading and never leaks letters into page text. To change it:

```sh
cd ProtocolSoup/design
npm install
npm run build:brand   # runs brand/build-wordmark.mjs, then the sync
```

Apps never depend on this package; only the generated outputs are committed and copied.
