import { type Confidence, type Severity } from "@adversarylabs/sdk";
export interface MatchExpression {
    pattern: string;
    flags: string;
}
interface ContentMatch {
    kind: "content";
    files: string[];
    pattern: MatchExpression;
    requires: MatchExpression[];
}
interface MissingContentMatch {
    kind: "missing-content";
    files: string[];
    trigger: MatchExpression;
    required: MatchExpression;
}
interface MissingFileMatch {
    kind: "missing-file";
    triggerFiles: string[];
    requiredFiles: string[];
}
export interface RuleSpec {
    id: string;
    title: string;
    summary: string;
    category: string;
    severity: Severity;
    confidence: Confidence;
    whyItMatters: string;
    impact: string;
    recommendation: string;
    complexity: "trivial" | "small" | "medium" | "large";
    tags: string[];
    match: ContentMatch | MissingContentMatch | MissingFileMatch;
}
export interface AdversarySpec {
    id: string;
    displayName: string;
    description: string;
    files: string[];
    rules: RuleSpec[];
}
export declare const spec: {
    readonly id: "nextjs";
    readonly displayName: "Next.js";
    readonly description: "Reviews Next.js configuration for unsafe remote content, exposed source maps, and permissive origins.";
    readonly files: ["next.config.js", "next.config.mjs", "next.config.ts", "**/next.config.js", "**/next.config.mjs", "**/next.config.ts"];
    readonly rules: [{
        readonly id: "nextjs.wildcard-images";
        readonly title: "Image configuration permits arbitrary remote hosts";
        readonly summary: "Image configuration permits arbitrary remote hosts";
        readonly category: "security";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "Image configuration permits arbitrary remote hosts weakens an important security boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Allow only explicit trusted image hosts.";
        readonly complexity: "small";
        readonly tags: ["security", "wildcard-images"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["next.config.js", "next.config.mjs", "next.config.ts", "**/next.config.js", "**/next.config.mjs", "**/next.config.ts"];
            readonly pattern: {
                readonly pattern: "remotePatterns[\\s\\S]{0,260}hostname:\\s*[\"']\\*\\*?[\"']";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "nextjs.production-sourcemaps";
        readonly title: "Production browser source maps are public";
        readonly summary: "Production browser source maps are public";
        readonly category: "security";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "Production browser source maps are public weakens an important security boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "Disable public source maps or upload them privately.";
        readonly complexity: "small";
        readonly tags: ["security", "production-sourcemaps"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["next.config.js", "next.config.mjs", "next.config.ts", "**/next.config.js", "**/next.config.mjs", "**/next.config.ts"];
            readonly pattern: {
                readonly pattern: "productionBrowserSourceMaps:\\s*true";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "nextjs.wildcard-origin";
        readonly title: "Server Actions accepts wildcard origins";
        readonly summary: "Server Actions accepts wildcard origins";
        readonly category: "security";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "Server Actions accepts wildcard origins weakens an important security boundary.";
        readonly impact: "The repository may behave insecurely, unreliably, or differently from the reviewed configuration.";
        readonly recommendation: "List only trusted Server Actions origins.";
        readonly complexity: "small";
        readonly tags: ["security", "wildcard-origin"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["next.config.js", "next.config.mjs", "next.config.ts", "**/next.config.js", "**/next.config.mjs", "**/next.config.ts"];
            readonly pattern: {
                readonly pattern: "allowedOrigins:\\s*\\[[^\\]]*[\"']\\*[\"']";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }];
};
export {};
