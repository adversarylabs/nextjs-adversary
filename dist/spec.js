const CONFIG_FILES = [
    "next.config.js",
    "next.config.mjs",
    "next.config.ts",
    "**/next.config.js",
    "**/next.config.mjs",
    "**/next.config.ts",
];
const MIDDLEWARE_FILES = [
    "middleware.js",
    "middleware.ts",
    "**/middleware.js",
    "**/middleware.ts",
    "src/middleware.js",
    "src/middleware.ts",
];
const SOURCE_FILES = [
    "**/*.js",
    "**/*.jsx",
    "**/*.ts",
    "**/*.tsx",
    "package.json",
    "**/package.json",
];
export const spec = {
    "id": "nextjs",
    "displayName": "Next.js",
    "description": "Reviews Next.js configuration for unsafe remote content, exposed source maps, and permissive origins.",
    "files": [...CONFIG_FILES, ...MIDDLEWARE_FILES, ...SOURCE_FILES],
    "rules": [
        {
            "id": "nextjs.middleware-auth-bypass",
            "title": "Middleware performs auth on a vulnerable Next.js line",
            "summary": "Middleware performs auth on a vulnerable Next.js line",
            "category": "security",
            "severity": "critical",
            "confidence": "medium",
            "whyItMatters": "CVE-2025-29927 lets x-middleware-subrequest skip middleware — sole auth in middleware is fully bypassable on unpatched versions.",
            "impact": "Protected routes become public without upgrading or re-checking auth at the data layer.",
            "recommendation": "Upgrade Next.js past patched versions and enforce auth where data is fetched, not only in middleware.",
            "complexity": "small",
            "tags": ["security", "middleware", "cve-2025-29927"],
            "match": {
                "kind": "content",
                "files": [...MIDDLEWARE_FILES],
                "pattern": {
                    "pattern": "(?:getToken|getServerSession|auth\\(|withAuth|NextResponse\\.redirect\\([^)]*(?:login|signin|unauthorized)|unauthorized\\()",
                    "flags": "i"
                },
                "requires": []
            }
        },
        {
            "id": "nextjs.public-env-secret",
            "title": "Secret-shaped value exposed via NEXT_PUBLIC_ env",
            "summary": "Secret-shaped value exposed via NEXT_PUBLIC_ env",
            "category": "secrets",
            "severity": "high",
            "confidence": "high",
            "whyItMatters": "NEXT_PUBLIC_ vars are inlined into the client bundle at build time.",
            "impact": "Service-role keys and API secrets are published to every visitor.",
            "recommendation": "Drop the NEXT_PUBLIC_ prefix and move the call into a Route Handler, Server Action, or server component.",
            "complexity": "small",
            "tags": ["secrets", "public-env"],
            "match": {
                "kind": "content",
                "files": ["**/*.js", "**/*.jsx", "**/*.ts", "**/*.tsx"],
                "pattern": {
                    "pattern": "(?:process\\.env\\.)?NEXT_PUBLIC_[A-Z0-9_]*?(?:SECRET|TOKEN|PRIVATE|PASSWORD|API_KEY|SERVICE_ROLE)[A-Z0-9_]*",
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
            "whyItMatters": "allowedOrigins: ['*'] disables origin checks that protect Server Actions from CSRF-style abuse.",
            "impact": "Cross-origin callers can invoke Server Actions as the user.",
            "recommendation": "List only trusted origins (proxy/host domains that legitimately front the app).",
            "complexity": "small",
            "tags": ["security", "wildcard-origin"],
            "match": {
                "kind": "content",
                "files": [...CONFIG_FILES],
                "pattern": { "pattern": "allowedOrigins:\\s*\\[[^\\]]*[\"']\\*[\"']", "flags": "i" },
                "requires": []
            }
        },
        {
            "id": "nextjs.wildcard-images",
            "title": "Image configuration permits arbitrary remote hosts",
            "summary": "Image configuration permits arbitrary remote hosts",
            "category": "security",
            "severity": "medium",
            "confidence": "high",
            "whyItMatters": "hostname: '**' turns /_next/image into an open image proxy (SSRF-adjacent and cost abuse).",
            "impact": "Attacker-hosted content and arbitrary fetches served from your origin.",
            "recommendation": "Allow only explicit trusted image hosts; prefer narrow pathname patterns on shared CDNs.",
            "complexity": "small",
            "tags": ["security", "wildcard-images"],
            "match": {
                "kind": "content",
                "files": [...CONFIG_FILES],
                "pattern": { "pattern": "remotePatterns[\\s\\S]{0,260}hostname:\\s*[\"']\\*\\*?[\"']", "flags": "i" },
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
            "whyItMatters": "Public production source maps ship original source, comments, and accidental server logic to every visitor.",
            "impact": "Information exposure that multiplies the impact of other defects.",
            "recommendation": "Disable public source maps; upload them privately to the error tracker.",
            "complexity": "small",
            "tags": ["security", "production-sourcemaps"],
            "match": {
                "kind": "content",
                "files": [...CONFIG_FILES],
                "pattern": { "pattern": "productionBrowserSourceMaps:\\s*true", "flags": "i" },
                "requires": []
            }
        },
        {
            "id": "nextjs.build-errors-ignored",
            "title": "Type or lint errors suppressed at build time",
            "summary": "Type or lint errors suppressed at build time",
            "category": "reliability",
            "severity": "medium",
            "confidence": "high",
            "whyItMatters": "ignoreBuildErrors / ignoreDuringBuilds ships code the toolchain already flagged as broken.",
            "impact": "Type and lint defects reach production indefinitely under a temporary flag.",
            "recommendation": "Fix the errors; if needed during migration, time-box the flag with a tracked issue.",
            "complexity": "small",
            "tags": ["reliability", "build"],
            "match": {
                "kind": "content",
                "files": [...CONFIG_FILES],
                "pattern": {
                    "pattern": "(?:ignoreBuildErrors|ignoreDuringBuilds):\\s*true",
                    "flags": "i"
                },
                "requires": []
            }
        }
    ]
};
