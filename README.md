# Next.js adversary

Reviews Next.js configuration for unsafe remote content, exposed source maps, and framework boundary risks.

## Goals

The adversary is designed to produce a small number of high-confidence,
actionable findings grounded in concrete repository evidence. Its review should
be deterministic where possible, explicit about impact, and quiet when the
available evidence does not justify a finding.

## Scope

It evaluates Next.js configuration and source boundaries for build suppression, remote content, public secrets, middleware bypasses, server-action authorization, and framework control flow.

The complete detector or review inventory is maintained in
[CHECKS.md](CHECKS.md).

## Boundaries

It owns framework- or language-specific review in this domain. Infrastructure, CI, dependency-manager, and unrelated application concerns remain with specialist adversaries.
