# web/nextjs — mission and scope

Source of truth for what this adversary is *for*.

- **Package:** `nextjs`
- **Factory routing:** human PR comments are attributed to this adversary only when they match **In scope**.
- **Languages / surfaces:** Next.js

## Mission

Review Next.js configuration for unsafe remote content, exposed source maps, and permissive origins.

## In scope (fair miss if humans raised it and we did not)

- Unsafe remote patterns
- Exposed source maps in prod config
- Over-permissive CORS/origins in Next config

## Out of scope (not a miss for this adversary)

- Generic React component logic without Next config
- Pure CI

## Factory grading rule

- **In scope + human raised it + this adversary did not surface it** → real miss → suggested issue for **this** package
- **Out of scope** → do not grade as a miss for this adversary
- **Better fit for another adversary** → route there; do not double-count as a miss here
- **Unclear** → prefer out-of-scope for grading
