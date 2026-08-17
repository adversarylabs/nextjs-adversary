# Checks

| Rule | Severity | Scans for |
| --- | --- | --- |
| `nextjs.build-errors-ignored` | Medium | Type and lint errors suppressed at build time |
| `nextjs.framework-control-flow-caught` | High | A broad catch can consume a framework-owned signal from `redirect`, `permanentRedirect`, or `notFound` |
| `nextjs.middleware-auth-bypass` | Critical | Auth enforced in middleware on a Next.js version vulnerable to the middleware bypass |
| `nextjs.production-sourcemaps` | Medium | Browser source maps enabled for production builds |
| `nextjs.public-env-secret` | High | Secret-shaped values exposed through `NEXT_PUBLIC_` env vars |
| `nextjs.wildcard-images` | Medium | Image optimizer remote patterns wildcarded |
