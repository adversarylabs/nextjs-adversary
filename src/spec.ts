import { type Confidence, type Severity } from "@adversarylabs/sdk";

export interface MatchExpression { pattern: string; flags: string }
interface ContentMatch { kind: "content"; files: string[]; pattern: MatchExpression; requires: MatchExpression[] }
interface MissingContentMatch { kind: "missing-content"; files: string[]; trigger: MatchExpression; required: MatchExpression }
interface MissingFileMatch { kind: "missing-file"; triggerFiles: string[]; requiredFiles: string[] }
export interface RuleSpec {
  id: string; title: string; summary: string; category: string; severity: Severity; confidence: Confidence;
  whyItMatters: string; impact: string; recommendation: string; complexity: "trivial" | "small" | "medium" | "large"; tags: string[];
  match: ContentMatch | MissingContentMatch | MissingFileMatch;
}
export interface AdversarySpec { id: string; displayName: string; description: string; files: string[]; rules: RuleSpec[] }

export const spec = {
  "id": "nextjs",
  "displayName": "Next.js",
  "description": "Reviews Next.js configuration for unsafe remote content, exposed source maps, and permissive origins.",
  "files": [
    "next.config.js",
    "next.config.mjs",
    "next.config.ts",
    "**/next.config.js",
    "**/next.config.mjs",
    "**/next.config.ts"
  ],
  "rules": [
    {
      "id": "nextjs.wildcard-images",
      "title": "Image configuration permits arbitrary remote hosts",
      "summary": "Image configuration permits arbitrary remote hosts",
      "category": "security",
      "severity": "medium",
      "confidence": "high",
      "whyItMatters": "Image configuration permits arbitrary remote hosts weakens an important security boundary.",
      "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
      "recommendation": "Allow only explicit trusted image hosts.",
      "complexity": "small",
      "tags": [
        "security",
        "wildcard-images"
      ],
      "match": {
        "kind": "content",
        "files": [
          "next.config.js",
          "next.config.mjs",
          "next.config.ts",
          "**/next.config.js",
          "**/next.config.mjs",
          "**/next.config.ts"
        ],
        "pattern": {
          "pattern": "remotePatterns[\\s\\S]{0,260}hostname:\\s*[\"']\\*\\*?[\"']",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "nextjs.production-sourcemaps",
      "title": "Production browser source maps are public",
      "summary": "Production browser source maps are public",
      "category": "security",
      "severity": "medium",
      "confidence": "high",
      "whyItMatters": "Production browser source maps are public weakens an important security boundary.",
      "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
      "recommendation": "Disable public source maps or upload them privately.",
      "complexity": "small",
      "tags": [
        "security",
        "production-sourcemaps"
      ],
      "match": {
        "kind": "content",
        "files": [
          "next.config.js",
          "next.config.mjs",
          "next.config.ts",
          "**/next.config.js",
          "**/next.config.mjs",
          "**/next.config.ts"
        ],
        "pattern": {
          "pattern": "productionBrowserSourceMaps:\\s*true",
          "flags": "i"
        },
        "requires": []
      }
    },
    {
      "id": "nextjs.wildcard-origin",
      "title": "Server Actions accepts wildcard origins",
      "summary": "Server Actions accepts wildcard origins",
      "category": "security",
      "severity": "high",
      "confidence": "high",
      "whyItMatters": "Server Actions accepts wildcard origins weakens an important security boundary.",
      "impact": "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.",
      "recommendation": "List only trusted Server Actions origins.",
      "complexity": "small",
      "tags": [
        "security",
        "wildcard-origin"
      ],
      "match": {
        "kind": "content",
        "files": [
          "next.config.js",
          "next.config.mjs",
          "next.config.ts",
          "**/next.config.js",
          "**/next.config.mjs",
          "**/next.config.ts"
        ],
        "pattern": {
          "pattern": "allowedOrigins:\\s*\\[[^\\]]*[\"']\\*[\"']",
          "flags": "i"
        },
        "requires": []
      }
    }
  ]
} as const satisfies AdversarySpec;
