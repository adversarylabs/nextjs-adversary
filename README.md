# Next.js adversary

Reviews Next.js configuration for unsafe remote content, exposed source maps, and permissive origins.

## Checks

- **Image configuration permits arbitrary remote hosts:** Allow only explicit trusted image hosts.
- **Production browser source maps are public:** Disable public source maps or upload them privately.
- **Server Actions accepts wildcard origins:** List only trusted Server Actions origins.

## Development

```sh
npm ci
npm test
adversary validate .
adversary pack --check .
```

## Automatic detection

`adversary auto` selects the nextjs adversary when changes include `next.config.js` or `next.config.mjs`, plus the other domain-specific patterns declared in `adversary.yaml`. Unrelated changes do not select it.
