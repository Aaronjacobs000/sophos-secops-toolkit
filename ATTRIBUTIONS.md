# Attributions and vendored code

## @notfusion/sophos-core (vendored)

`backend/src/vendor/sophos-core/` is a copy of `packages/sophos-core/src` from NotFusion, another project by the same author (private repository, commit `f3ba062`, 05/10/2026), licensed Apache-2.0 AND MIT. It is vendored for now and is meant to be replaced by a published package later, so the MCP server, NotFusion and this toolkit stop drifting apart.

Local modifications, each marked "SecOps Toolkit local modification" in the source:

| File | Change |
| --- | --- |
| `http.ts` | Adds `FetchLike` and `defaultFetch`. |
| `index.ts` | `createSophosCore` takes an optional `fetch`, passed to every client. |
| `auth/token-manager.ts`, `client/tenant-resolver.ts`, `client/sophos-client.ts`, `client/fusion-client.ts` | Call the injected fetch instead of the global one, so the toolkit's read-only, rate-limited transport sees every request. |
| `client/tenant-resolver.ts` | Keeps the full partner tenant records (`getTenantRecords`) and can reset the list (`resetTenants`). |
| `types/sophos.ts` | `SophosTenant` gains the optional `showAs`, `products` and `contact` fields the partner list returns. |
| `fusion/queries/search.ts`, `services/search.ts` (new, 29/10/2026) | Search GraphQL client: start or reuse a search, poll every 5 seconds to a deadline, read every page by cursor, with policies for partial results, failure and expiry. Adapted from the sophos-central-mcp-server Search tools (MIT). `index.ts` adds it to `createSophosCore` as `search`. |
| `fusion/queries/ai-defense.ts`, `services/ai-defense.ts` (new, 08/11/2026) | AI Defense reads: three query documents (overview, details, policy counts) trimmed to what the toolkit shows, the time window rule and a 90 s timeout. Adapted from the sophos-central-mcp-server AI Defense module (MIT, release 0.13.0). `index.ts` adds it to `createSophosCore` as `aiDefense`. No AI Defense write is ported. On 09/11/2026 the details read gained each user's actor id, and a fourth read was added, the toolkit's own: the flow (blocked and warned counts for the top 10 apps and users, one call, every slot a required variable). |

The toolkit uses only the read paths, plus the two Search GraphQL mutations that start a search job and change nothing in the tenant. The write methods that remain in the vendored files (isolation, scans, case writes) are never called, and the guard in `backend/src/sophos/guard.ts` refuses them even if one were.

## sophos-tenant-migration-tool (copied)

`backend/src/config/network.ts` and `backend/src/middleware/{local-host,client-ip,json-body,error-handler}.ts` are copied unchanged apart from a header and one message, MIT License. `backend/src/log.ts` is adapted from the same project's logger.

## sophos-mcp

Through sophos-core: `TokenManager`, `TenantResolver`, `SophosClient`, `FusionClient`, the case reference data cache, the GraphQL documents, the Search GraphQL flow and the AI Defense reads are adapted from sophos-central-mcp-server, MIT License (`LICENSE-MIT`).

## AI app logos (Simple Icons, CC0-1.0)

`frontend/js/ai-logos.js` bundles eight marks from [Simple Icons](https://simpleicons.org) 16.36.0 (npm `simple-icons`, released 25/10/2026, CC0-1.0), one 24 x 24 path each, so nothing loads at run time. Simple Icons releases its drawings under CC0, but each mark stays a trademark of its owner and Simple Icons asks users to follow each brand's terms. The AI usage screen shows a mark only to name the app AI Defense reported, in plain white or black, never as the toolkit's own mark and never to suggest the brand endorses it.

A brand is bundled only when Simple Icons carries it and the brand's published terms, checked 09/11/2026, do not ask for approval first, limit the mark to partners, or rule out showing it in one plain colour.

| Mark | Simple Icons slug | Source (from Simple Icons) | Brand terms checked |
| --- | --- | --- | --- |
| Cursor | `cursor` | https://cursor.com | cursor.com/brand publishes the assets and sets no usage rules |
| DeepSeek | `deepseek` | https://www.deepseek.com | No published logo terms found |
| ElevenLabs | `elevenlabs` | https://elevenlabs.io/brand | elevenlabs.io/brand: the mark in black or white, clear space kept, never redrawn |
| Hugging Face | `huggingface` | https://huggingface.co/brand | huggingface.co/brand offers the assets to use in your projects |
| Kimi | `kimi` | https://moonshotai.github.io/Branding-Guide | Moonshot AI's branding guide publishes the marks and sets no usage rules |
| Perplexity | `perplexity` | https://www.perplexity.ai | No published logo terms found |
| Poe | `poe` | https://poe.com | No published logo terms found for Poe or Quora |
| Windsurf | `windsurf` | https://windsurf.com/brand | windsurf.com/brand: the symbol in black or white for logo grids, no colour or effects |

Not bundled, so these apps get a monogram: OpenAI and ChatGPT (Simple Icons removed the mark because OpenAI's permission is not transferable), Claude and Anthropic (permission first, no recolouring), Google and Gemini (product icons need approval), Meta and Meta AI (every use needs approval), Mistral AI and its apps such as Vibe (partners, no recolouring, no frame), GitHub Copilot (written permission first) and Notion (permission first). Microsoft Copilot, HeyGen, Grok, Character.AI and Midjourney are not in Simple Icons. Simple Icons' "Monica" is a personal CRM, not the Monica AI assistant, so it is not matched. Check a brand's terms again before adding its mark.
