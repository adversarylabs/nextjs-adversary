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
    readonly files: ["next.config.js", "next.config.mjs", "next.config.ts", "**/next.config.js", "**/next.config.mjs", "**/next.config.ts", "middleware.js", "middleware.ts", "**/middleware.js", "**/middleware.ts", "src/middleware.js", "src/middleware.ts", "**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx", "package.json", "**/package.json"];
    readonly rules: [{
        readonly id: "nextjs.middleware-auth-bypass";
        readonly title: "Middleware performs auth on a vulnerable Next.js line";
        readonly summary: "Middleware performs auth on a vulnerable Next.js line";
        readonly category: "security";
        readonly severity: "critical";
        readonly confidence: "medium";
        readonly whyItMatters: "CVE-2025-29927 lets x-middleware-subrequest skip middleware — sole auth in middleware is fully bypassable on unpatched versions.";
        readonly impact: "Protected routes become public without upgrading or re-checking auth at the data layer.";
        readonly recommendation: "Upgrade Next.js past patched versions and enforce auth where data is fetched, not only in middleware.";
        readonly complexity: "small";
        readonly tags: ["security", "middleware", "cve-2025-29927"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["middleware.js", "middleware.ts", "**/middleware.js", "**/middleware.ts", "src/middleware.js", "src/middleware.ts"];
            readonly pattern: {
                readonly pattern: "(?:getToken|getServerSession|auth\\(|withAuth|NextResponse\\.redirect\\([^)]*(?:login|signin|unauthorized)|unauthorized\\()";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }, {
        readonly id: "nextjs.public-env-secret";
        readonly title: "Secret-shaped value exposed via NEXT_PUBLIC_ env";
        readonly summary: "Secret-shaped value exposed via NEXT_PUBLIC_ env";
        readonly category: "secrets";
        readonly severity: "high";
        readonly confidence: "high";
        readonly whyItMatters: "NEXT_PUBLIC_ vars are inlined into the client bundle at build time.";
        readonly impact: "Service-role keys and API secrets are published to every visitor.";
        readonly recommendation: "Drop the NEXT_PUBLIC_ prefix and move the call into a Route Handler, Server Action, or server component.";
        readonly complexity: "small";
        readonly tags: ["secrets", "public-env"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx"];
            readonly pattern: {
                readonly pattern: "(?:process\\.env\\.)?NEXT_PUBLIC_[A-Z0-9_]*?(?:SECRET|TOKEN|PRIVATE|PASSWORD|API_KEY|SERVICE_ROLE)[A-Z0-9_]*";
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
        readonly whyItMatters: "allowedOrigins: ['*'] disables origin checks that protect Server Actions from CSRF-style abuse.";
        readonly impact: "Cross-origin callers can invoke Server Actions as the user.";
        readonly recommendation: "List only trusted origins (proxy/host domains that legitimately front the app).";
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
    }, {
        readonly id: "nextjs.wildcard-images";
        readonly title: "Image configuration permits arbitrary remote hosts";
        readonly summary: "Image configuration permits arbitrary remote hosts";
        readonly category: "security";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "hostname: '**' turns /_next/image into an open image proxy (SSRF-adjacent and cost abuse).";
        readonly impact: "Attacker-hosted content and arbitrary fetches served from your origin.";
        readonly recommendation: "Allow only explicit trusted image hosts; prefer narrow pathname patterns on shared CDNs.";
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
        readonly whyItMatters: "Public production source maps ship original source, comments, and accidental server logic to every visitor.";
        readonly impact: "Information exposure that multiplies the impact of other defects.";
        readonly recommendation: "Disable public source maps; upload them privately to the error tracker.";
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
        readonly id: "nextjs.build-errors-ignored";
        readonly title: "Type or lint errors suppressed at build time";
        readonly summary: "Type or lint errors suppressed at build time";
        readonly category: "reliability";
        readonly severity: "medium";
        readonly confidence: "high";
        readonly whyItMatters: "ignoreBuildErrors / ignoreDuringBuilds ships code the toolchain already flagged as broken.";
        readonly impact: "Type and lint defects reach production indefinitely under a temporary flag.";
        readonly recommendation: "Fix the errors; if needed during migration, time-box the flag with a tracked issue.";
        readonly complexity: "small";
        readonly tags: ["reliability", "build"];
        readonly match: {
            readonly kind: "content";
            readonly files: ["next.config.js", "next.config.mjs", "next.config.ts", "**/next.config.js", "**/next.config.mjs", "**/next.config.ts"];
            readonly pattern: {
                readonly pattern: "(?:ignoreBuildErrors|ignoreDuringBuilds):\\s*true";
                readonly flags: "i";
            };
            readonly requires: [];
        };
    }];
};
export {};
