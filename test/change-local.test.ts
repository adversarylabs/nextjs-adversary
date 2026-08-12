import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import { createApp } from "../src/index.ts";

const execute = promisify(execFile);

test("an unrelated config edit does not surface a legacy source-map finding", async () => {
  const repo = await repositoryWithLegacyConfig();
  await writeFile(join(repo, "next.config.js"), nextConfig("new diagnostic"));

  const result = await changedReview(repo, ["next.config.js"]);
  assert.equal(
    result.findings.some((finding) => finding.ruleId === "nextjs.production-sourcemaps"),
    false,
  );
});

test("an added Next.js config remains fully eligible", async () => {
  const repo = await repositoryWithLegacyConfig();
  await writeFile(join(repo, "next.config.mjs"), nextConfig("added file"));

  const result = await changedReview(repo, ["next.config.mjs"]);
  assert.equal(
    result.findings.some((finding) => finding.ruleId === "nextjs.production-sourcemaps"),
    true,
  );
});

test("an unchanged first regex occurrence does not hide a later changed occurrence", async () => {
  const repo = await repositoryWithLegacyConfig();
  await writeFile(join(repo, "env.ts"), publicEnv("NEXT_PUBLIC_SAFE_VALUE"));
  await execute("git", ["add", "env.ts"], { cwd: repo });
  await execute("git", ["commit", "--quiet", "-m", "env fixture"], { cwd: repo });
  await writeFile(join(repo, "env.ts"), publicEnv("NEXT_PUBLIC_SECOND_SECRET"));

  const result = await changedReview(repo, ["env.ts"], true);
  const observation = result.rawObservations?.find(
    (item) => item.ruleId === "nextjs.public-env-secret",
  );
  assert.equal(observation?.location?.line, 2);
  assert.match(observation?.location?.snippet ?? "", /NEXT_PUBLIC_SECOND_SECRET/);
});

test("an unrelated line inside remotePatterns does not revive a legacy wildcard host", async () => {
  const repo = await repositoryWithLegacyConfig();
  await writeFile(join(repo, "next.config.js"), wildcardConfig("old diagnostic"));
  await execute("git", ["add", "next.config.js"], { cwd: repo });
  await execute("git", ["commit", "--quiet", "-m", "wildcard fixture"], { cwd: repo });
  await writeFile(join(repo, "next.config.js"), wildcardConfig("new diagnostic"));

  const result = await changedReview(repo, ["next.config.js"]);
  assert.equal(
    result.findings.some((finding) => finding.ruleId === "nextjs.wildcard-images"),
    false,
  );
});

test("a changed control-flow call uses unchanged import and catch context", async () => {
  const repo = await repositoryWithLegacyConfig();
  await writeFile(join(repo, "action.ts"), caughtRedirect("console.log(destination)"));
  await execute("git", ["add", "action.ts"], { cwd: repo });
  await execute("git", ["commit", "--quiet", "-m", "action fixture"], { cwd: repo });
  await writeFile(join(repo, "action.ts"), caughtRedirect("redirect(destination)"));

  const result = await changedReview(repo, ["action.ts"], true);
  const observation = result.rawObservations?.find(
    (item) => item.ruleId === "nextjs.framework-control-flow-caught",
  );
  assert.equal(observation?.location?.line, 5);
  assert.equal(observation?.location?.snippet, "redirect(destination);");
});

test("an unchanged caught redirect does not hide a later changed call", async () => {
  const repo = await repositoryWithLegacyConfig();
  await writeFile(join(repo, "actions.ts"), twoCaughtCalls("console.log('/second')"));
  await execute("git", ["add", "actions.ts"], { cwd: repo });
  await execute("git", ["commit", "--quiet", "-m", "actions fixture"], { cwd: repo });
  await writeFile(join(repo, "actions.ts"), twoCaughtCalls("redirect('/second')"));

  const result = await changedReview(repo, ["actions.ts"], true);
  const observations = result.rawObservations?.filter(
    (item) => item.ruleId === "nextjs.framework-control-flow-caught",
  ) ?? [];
  assert.deepEqual(observations.map((item) => item.location?.line), [13]);
});

async function repositoryWithLegacyConfig(): Promise<string> {
  const repo = await mkdtemp(join(tmpdir(), "nextjs-change-local-"));
  await execute("git", ["init", "--quiet"], { cwd: repo });
  await execute("git", ["config", "user.email", "tests@example.com"], { cwd: repo });
  await execute("git", ["config", "user.name", "Tests"], { cwd: repo });
  await writeFile(join(repo, "next.config.js"), nextConfig("old diagnostic"));
  await execute("git", ["add", "next.config.js"], { cwd: repo });
  await execute("git", ["commit", "--quiet", "-m", "fixture"], { cwd: repo });
  return repo;
}

function nextConfig(diagnostic: string): string {
  return `module.exports = {
  productionBrowserSourceMaps: true,
  env: { DIAGNOSTIC: ${JSON.stringify(diagnostic)} },
};
`;
}

function publicEnv(second: string): string {
  return `export const first = process.env.NEXT_PUBLIC_API_SECRET;
export const second = process.env.${second};
`;
}

function wildcardConfig(diagnostic: string): string {
  return `module.exports = {
  images: {
    remotePatterns: [{
      protocol: "https",
      pathname: ${JSON.stringify(`/images/${diagnostic}/**`)},
      hostname: "**",
    }],
  },
};
`;
}

function caughtRedirect(statement: string): string {
  return `import { redirect } from "next/navigation";

export function navigate(destination: string) {
  try {
    ${statement};
  } catch (error) {
    console.error(error);
  }
}
`;
}

function twoCaughtCalls(second: string): string {
  return `import { redirect } from "next/navigation";

export function first() {
  try {
    redirect('/first');
  } catch (error) {
    console.error(error);
  }
}

export function second() {
  try {
    ${second};
  } catch (error) {
    console.error(error);
  }
}
`;
}

async function changedReview(
  repoPath: string,
  changedFiles: string[],
  includeRawObservations = false,
) {
  return createApp().run({
    includeRawObservations,
    input: {
      source: { path: repoPath },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "changed",
        changed_files: changedFiles,
      },
    },
  });
}
