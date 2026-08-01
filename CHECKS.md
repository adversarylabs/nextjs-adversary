# Checks — what nextjs detects

This file is the **public audit list** of detectors for the **nextjs** adversary. High-confidence Next.js configuration and framework-boundary defects with file:line evidence. Component-level React issues are owned by `react`; this adversary covers what only the framework layer can see: `next.config.*`, middleware, Server Actions, and the client/server env boundary.

Runtime source of truth: [`src/spec.ts`](src/spec.ts) / [`src/rules.ts`](src/rules.ts).

**Scope:** `next.config.js|mjs|ts`, `middleware.ts|js`, `app/**` and `pages/**` server-side files, `"use server"` modules, `package.json` (Next version only).

**Precision stance:** Version-gated findings (CVE checks) fire only when the declared version range includes vulnerable releases. Server Action findings are LLM-gated — static analysis alone cannot judge auth sufficiency. Config findings fire on explicit insecure values, not defaults.

Public grounding: [CVE-2025-29927](https://nvd.nist.gov/vuln/detail/CVE-2025-29927) (middleware authorization bypass via `x-middleware-subrequest`, patched in 14.2.25 / 15.2.3), Next.js docs on Server Actions as public endpoints, and the `NEXT_PUBLIC_` env contract.

---

## Critical

### `nextjs.middleware-auth-bypass`

| | |
| --- | --- |
| **What** | Auth enforced in middleware on a Next.js version vulnerable to the middleware bypass |
| **Why** | CVE-2025-29927: a crafted `x-middleware-subrequest` header skips middleware entirely — if middleware is the only auth gate, every protected route is public. CVSS 9.1, actively probed in the wild since disclosure |
| **Looks for** | `middleware.ts|js` performing auth/redirect logic **and** `package.json` `next` range including versions < 14.2.25 / < 15.2.3 (or unpatched 12.x/13.x lines) |
| **Stays quiet when** | Patched versions; middleware doing only rewrites/i18n/headers; auth re-checked in the route/layout/data layer (downgrade to medium — defense in depth still warranted) |
| **Public examples** | CVE-2025-29927; Vercel advisory and the wave of March 2025 writeups |
| **Remediation** | Upgrade Next.js; treat middleware as convenience, never the sole authorization point — enforce auth where data is fetched |

---

## High

### `nextjs.public-env-secret`

| | |
| --- | --- |
| **What** | Secret-shaped values exposed through `NEXT_PUBLIC_` env vars |
| **Why** | Everything prefixed `NEXT_PUBLIC_` is inlined into the client bundle at build time — a secret there is published to every visitor. The single most common Next.js security mistake |
| **Looks for** | `NEXT_PUBLIC_X` references where X matches `SECRET|TOKEN|PRIVATE|API_KEY|PASSWORD|SERVICE_ROLE`, especially flowing into `Authorization` headers or privileged SDK constructors (e.g. Supabase `service_role`) |
| **Stays quiet when** | Publishable-by-design values (Stripe `pk_`, analytics IDs, Sentry DSNs, Firebase client config, Supabase `anon` key) |
| **Public examples** | Next.js env docs state the inlining behavior; leaked service-role-key incidents from client bundles |
| **Remediation** | Drop the `NEXT_PUBLIC_` prefix and move the call into a Route Handler / Server Action / server component |

### `nextjs.wildcard-origin`

| | |
| --- | --- |
| **What** | Server Actions origin allowlist wildcarded |
| **Why** | `experimental.serverActions.allowedOrigins: ['*']` (or equivalently broad entries) disables the origin check that protects Server Actions — mutation endpoints — from cross-origin forgery |
| **Looks for** | `allowedOrigins` containing `*` or scheme-less broad wildcards in `next.config.*` |
| **Stays quiet when** | Explicit trusted host list; setting absent (secure default: same-origin) |
| **Public examples** | Next.js Server Actions security docs |
| **Remediation** | List only trusted origins (the proxy/host domains that legitimately front the app) |

---

## Medium

### `nextjs.server-action-unauthenticated`

| | |
| --- | --- |
| **What** | `"use server"` mutation without a visible auth check |
| **Why** | Server Actions compile to public HTTP endpoints — colocation with a protected page provides zero protection, and devs habitually assume it does. LLM-gated: auth may live in a wrapper — static string matching would be an FP machine |
| **Looks for** | LLM-gated: exported `"use server"` functions performing writes (DB calls, mutations) with no session/auth check in the function or an obvious wrapper |
| **Stays quiet when** | Auth checked in the action or a wrapping helper (`withAuth`, session assertion); genuinely public actions (newsletter signup) — LLM judges intent |
| **Public examples** | Next.js docs: “Server Actions … create a public endpoint”; post-launch security reviews finding unauthenticated mutations |
| **Remediation** | Authenticate and authorize inside every mutating action, exactly as you would an API route |

### `nextjs.wildcard-images`

| | |
| --- | --- |
| **What** | Image optimizer remote patterns wildcarded |
| **Why** | `images.remotePatterns` with `hostname: '**'` turns `/_next/image` into an open image proxy: SSRF-adjacent fetch-from-anywhere, bandwidth/cost abuse, and attacker-hosted content served from your origin |
| **Looks for** | `remotePatterns` entries with `hostname: '**'` (or protocol-less `**`); legacy `images.domains` with obviously over-broad lists |
| **Stays quiet when** | Explicit trusted hostnames; `unoptimized: true` (optimizer off) |
| **Public examples** | Next.js image config docs; image-optimizer abuse writeups |
| **Remediation** | Allow only explicit trusted image hosts; prefer narrow `pathname` patterns on shared CDNs |

### `nextjs.production-sourcemaps`

| | |
| --- | --- |
| **What** | Browser source maps enabled for production builds |
| **Why** | `productionBrowserSourceMaps: true` ships your original source — including comments and any accidentally-bundled server logic — to every visitor. Not a vulnerability by itself; an information-exposure multiplier |
| **Looks for** | `productionBrowserSourceMaps: true` in `next.config.*` |
| **Stays quiet when** | Absent/false (default); maps uploaded privately to an error tracker (Sentry) without public serving |
| **Public examples** | Next.js config docs; source-map-recovered-secrets writeups |
| **Remediation** | Disable public source maps; upload them privately to the error tracker instead |

### `nextjs.build-errors-ignored`

| | |
| --- | --- |
| **What** | Type and lint errors suppressed at build time |
| **Why** | `typescript.ignoreBuildErrors: true` / `eslint.ignoreDuringBuilds: true` ships code the toolchain already flagged as broken; “temporary” in every repo where it appears, permanent in most |
| **Looks for** | Those flags set true in `next.config.*` |
| **Stays quiet when** | Absent/false; lint intentionally run as a separate CI gate (`ignoreDuringBuilds` with a visible lint job downgrades to low) |
| **Public examples** | Next.js config docs label these escape hatches |
| **Remediation** | Fix the errors; if builds must ship during migration, time-box the flag with a tracked issue |

---

## Out of scope (owned elsewhere)

| Concern | Owner |
| --- | --- |
| Component-level XSS sinks (`dangerouslySetInnerHTML`, href injection) | `react` |
| package.json / lockfile supply chain | `npm` / `yarn` |
| Committed secret values | `security/secrets` |
| Generic TS configuration | `typescript` |
| Deployment platform config (Vercel/Docker) | platform adversaries |
