import { execFile } from "node:child_process";
import { readdir } from "node:fs/promises";
import { join, sep } from "node:path";
import { promisify } from "node:util";
import ts from "typescript";
import { observationFor } from "./rules.js";
import { spec } from "./spec.js";
const SKIPPED = new Set([".adversary", ".git", ".hg", ".next", ".svn", "coverage", "dist", "node_modules", "target", "vendor"]);
const MAX_FILES = 5000;
const execute = promisify(execFile);
export async function analyzeRepository(ctx) {
    // Full tree for existence/context checks; content uses CLI/SDK review scope.
    const allPaths = await walk(ctx.repoPath);
    const scoped = await ctx.loadInScopeSources({
        include: (path) => !path.split("/").some((segment) => SKIPPED.has(segment)) &&
            spec.files.some((glob) => matchesGlob(path, glob)),
        limit: MAX_FILES,
    });
    const wholeTarget = ctx.change === null || ctx.change.scanMode === "all";
    const sources = [];
    for (const file of scoped) {
        if (wholeTarget || file.status === "repository") {
            sources.push({
                path: file.path,
                source: file.content,
                changedLines: new Set(),
                status: "repository",
            });
            continue;
        }
        const change = await changedSource(ctx, file.path);
        sources.push({
            path: file.path,
            source: file.content,
            changedLines: change.changedLines,
            status: change.status,
        });
    }
    ctx.summary.files_scanned = sources.length;
    const detections = spec.rules.flatMap((rule) => evaluate(rule, sources, allPaths));
    detections.sort((a, b) => a.rule.id.localeCompare(b.rule.id) || a.file.localeCompare(b.file) || a.line - b.line || a.label.localeCompare(b.label));
    for (const detection of detections)
        ctx.observe(observationFor(detection));
    if (sources.length > 0 && detections.length === 0) {
        ctx.review.positive({
            key: `${spec.id}.reviewed`,
            summary: `Reviewed ${sources.length} ${spec.displayName} configuration file${sources.length === 1 ? "" : "s"} without finding a material issue.`,
            evidence: sources.slice(0, 5).map((file) => ({ file: file.path, line: 1 })),
        });
    }
}
function evaluate(rule, sources, allPaths) {
    const match = rule.match;
    if (match.kind === "missing-file") {
        const triggers = allPaths.filter((path) => match.triggerFiles.some((glob) => matchesGlob(path, glob))).sort();
        const required = allPaths.some((path) => match.requiredFiles.some((glob) => matchesGlob(path, glob)));
        if (triggers.length === 0 || required)
            return [];
        return [{ rule, file: triggers[0] ?? ".", line: 1, snippet: triggers[0] ?? "", label: rule.title, data: { triggerFiles: triggers.slice(0, 10), requiredFiles: match.requiredFiles } }];
    }
    const matchingSources = sources.filter((file) => match.files.some((glob) => matchesGlob(file.path, glob)));
    if (match.kind === "framework-control-flow-caught") {
        return matchingSources.flatMap((file) => findCaughtFrameworkControlFlow(rule, file));
    }
    if (match.kind === "missing-content") {
        return matchingSources.flatMap((file) => {
            if (!test(file.source, match.trigger) || test(file.source, match.required))
                return [];
            const location = locate(file, match.trigger);
            if (location === undefined)
                return [];
            return [{ rule, file: file.path, ...location, label: rule.title, data: { requiredPattern: match.required.pattern } }];
        });
    }
    return matchingSources.flatMap((file) => {
        if (!match.requires.every((pattern) => test(file.source, pattern)))
            return [];
        const location = locate(file, match.pattern, match.anchors);
        if (location === undefined)
            return [];
        return [{ rule, file: file.path, ...location, label: rule.title, data: { matchedPattern: match.pattern.pattern } }];
    });
}
const CONTROL_FLOW_APIS = new Set(["notFound", "permanentRedirect", "redirect"]);
function findCaughtFrameworkControlFlow(rule, source) {
    const scriptKind = source.path.endsWith(".tsx") ? ts.ScriptKind.TSX
        : source.path.endsWith(".jsx") ? ts.ScriptKind.JSX
            : source.path.endsWith(".js") ? ts.ScriptKind.JS
                : ts.ScriptKind.TS;
    const file = ts.createSourceFile(source.path, source.source, ts.ScriptTarget.Latest, true, scriptKind);
    const importedApis = new Map();
    const navigationNamespaces = new Set();
    const rethrowFunctions = new Set();
    for (const statement of file.statements) {
        if (!ts.isImportDeclaration(statement) || !ts.isStringLiteral(statement.moduleSpecifier) || statement.moduleSpecifier.text !== "next/navigation")
            continue;
        const bindings = statement.importClause?.namedBindings;
        if (bindings && ts.isNamespaceImport(bindings))
            navigationNamespaces.add(bindings.name.text);
        if (bindings && ts.isNamedImports(bindings)) {
            for (const element of bindings.elements) {
                const imported = element.propertyName?.text ?? element.name.text;
                if (CONTROL_FLOW_APIS.has(imported))
                    importedApis.set(element.name.text, imported);
                if (imported === "unstable_rethrow")
                    rethrowFunctions.add(element.name.text);
            }
        }
    }
    if (importedApis.size === 0 && navigationNamespaces.size === 0)
        return [];
    const detections = [];
    const reportedCalls = new Set();
    function visit(node) {
        if (ts.isTryStatement(node) && node.catchClause && !catchPreservesFrameworkErrors(node.catchClause, rethrowFunctions, navigationNamespaces)) {
            visitTryBody(node.tryBlock, (call, api) => {
                const start = call.expression.getStart(file);
                if (reportedCalls.has(start))
                    return;
                reportedCalls.add(start);
                const location = locateFromIndex(source.source, start);
                if (!isEligibleLine(source, location.line))
                    return;
                detections.push({
                    rule,
                    file: source.path,
                    ...location,
                    label: `${api}() is inside a catchable try block`,
                    data: { api, catchLine: file.getLineAndCharacterOfPosition(node.catchClause?.getStart(file) ?? start).line + 1 },
                });
            });
        }
        ts.forEachChild(node, visit);
    }
    function visitTryBody(node, onCall) {
        if (node !== node.parent && ts.isFunctionLike(node))
            return;
        if (ts.isCallExpression(node)) {
            const api = importedControlFlowApi(node, importedApis, navigationNamespaces);
            if (api)
                onCall(node, api);
        }
        ts.forEachChild(node, (child) => visitTryBody(child, onCall));
    }
    visit(file);
    return detections;
}
function importedControlFlowApi(call, importedApis, namespaces) {
    const expression = call.expression;
    if (ts.isIdentifier(expression) && !isLocallyShadowed(call, expression.text))
        return importedApis.get(expression.text);
    if (ts.isPropertyAccessExpression(expression) && ts.isIdentifier(expression.expression) && !isLocallyShadowed(call, expression.expression.text) && namespaces.has(expression.expression.text) && CONTROL_FLOW_APIS.has(expression.name.text)) {
        return expression.name.text;
    }
    return undefined;
}
function isLocallyShadowed(node, name) {
    let current = node.parent;
    while (current && !ts.isSourceFile(current)) {
        if (ts.isFunctionLike(current) && current.parameters.some((parameter) => bindingContains(parameter.name, name)))
            return true;
        if (ts.isBlock(current)) {
            for (const statement of current.statements) {
                if (ts.isFunctionDeclaration(statement) && statement.name?.text === name)
                    return true;
                if (ts.isClassDeclaration(statement) && statement.name?.text === name)
                    return true;
                if (ts.isVariableStatement(statement) && statement.declarationList.declarations.some((declaration) => bindingContains(declaration.name, name)))
                    return true;
            }
        }
        if (ts.isCatchClause(current) && current.variableDeclaration && bindingContains(current.variableDeclaration.name, name))
            return true;
        current = current.parent;
    }
    return false;
}
function bindingContains(binding, name) {
    if (ts.isIdentifier(binding))
        return binding.text === name;
    return binding.elements.some((element) => !ts.isOmittedExpression(element) && bindingContains(element.name, name));
}
function catchPreservesFrameworkErrors(clause, rethrowFunctions, namespaces) {
    const caught = clause.variableDeclaration?.name;
    if (!caught || !ts.isIdentifier(caught))
        return false;
    const first = clause.block.statements[0];
    if (!first)
        return false;
    if (ts.isThrowStatement(first) && first.expression && ts.isIdentifier(first.expression) && first.expression.text === caught.text)
        return true;
    if (!ts.isExpressionStatement(first) || !ts.isCallExpression(first.expression))
        return false;
    const call = first.expression;
    if (call.arguments.length !== 1 || !ts.isIdentifier(call.arguments[0]) || call.arguments[0].text !== caught.text)
        return false;
    if (ts.isIdentifier(call.expression))
        return rethrowFunctions.has(call.expression.text);
    return ts.isPropertyAccessExpression(call.expression) && ts.isIdentifier(call.expression.expression) &&
        namespaces.has(call.expression.expression.text) && call.expression.name.text === "unstable_rethrow";
}
function test(source, expression) {
    return new RegExp(expression.pattern, expression.flags).test(source);
}
function locate(file, expression, anchors) {
    const flags = expression.flags.includes("g") ? expression.flags : `${expression.flags}g`;
    const pattern = new RegExp(expression.pattern, flags);
    const sourceLines = file.source.split(/\r?\n/);
    for (const match of file.source.matchAll(pattern)) {
        if (match.index === undefined)
            continue;
        const startLine = file.source.slice(0, match.index).split(/\r?\n/).length;
        const endLine = startLine + (match[0]?.match(/\r?\n/g)?.length ?? 0);
        const line = file.status === "modified" && anchors !== undefined
            ? eligibleSemanticAnchor(file, match[0], match.index, anchors)
            : eligibleLine(file, startLine, endLine);
        if (line === undefined)
            continue;
        return { line, snippet: sourceLines[line - 1]?.trim().slice(0, 240) ?? "" };
    }
    return undefined;
}
function eligibleSemanticAnchor(file, matchedSource, offset, anchors) {
    for (const anchor of anchors) {
        const flags = anchor.flags.includes("g") ? anchor.flags : `${anchor.flags}g`;
        for (const match of matchedSource.matchAll(new RegExp(anchor.pattern, flags))) {
            if (match.index === undefined)
                continue;
            const startLine = file.source.slice(0, offset + match.index).split(/\r?\n/).length;
            const endLine = startLine + (match[0]?.match(/\r?\n/g)?.length ?? 0);
            const line = eligibleLine(file, startLine, endLine);
            if (line !== undefined)
                return line;
        }
    }
    return undefined;
}
function locateFromIndex(source, index) {
    const line = source.slice(0, index).split(/\r?\n/).length;
    return { line, snippet: source.split(/\r?\n/)[line - 1]?.trim().slice(0, 240) ?? "" };
}
function eligibleLine(file, startLine, endLine) {
    if (file.status === "repository" || file.status === "added")
        return startLine;
    for (let line = startLine; line <= endLine; line += 1) {
        if (file.changedLines.has(line))
            return line;
    }
    return undefined;
}
function isEligibleLine(file, line) {
    return file.status === "repository" || file.status === "added" || file.changedLines.has(line);
}
async function changedSource(ctx, path) {
    const base = ctx.change?.baseRef;
    if (base === undefined || !(await existsAtRevision(ctx.repoPath, base, path))) {
        return { changedLines: new Set(), status: "added" };
    }
    const args = ["diff", "--unified=0", base];
    const head = ctx.change?.headRef;
    if (head !== undefined && !ctx.change?.worktree)
        args.push(head);
    args.push("--", path);
    const patch = await gitOutput(ctx.repoPath, args);
    return { changedLines: changedLineNumbers(patch), status: "modified" };
}
async function existsAtRevision(repoPath, revision, path) {
    try {
        await execute("git", ["-C", repoPath, "cat-file", "-e", `${revision}:${path}`], {
            maxBuffer: 1024 * 1024,
        });
        return true;
    }
    catch {
        return false;
    }
}
async function gitOutput(repoPath, args) {
    const result = await execute("git", ["-C", repoPath, ...args], {
        encoding: "utf8",
        maxBuffer: 8 * 1024 * 1024,
    });
    return result.stdout;
}
function changedLineNumbers(patch) {
    const lines = new Set();
    for (const match of patch.matchAll(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm)) {
        const start = Number(match[1]);
        const count = match[2] === undefined ? 1 : Number(match[2]);
        for (let line = start; line < start + count; line += 1)
            lines.add(line);
    }
    return lines;
}
async function walk(root) {
    const files = [];
    async function visit(relative) {
        if (files.length >= MAX_FILES)
            return;
        const entries = await readdir(join(root, relative), { withFileTypes: true });
        entries.sort((a, b) => a.name.localeCompare(b.name));
        for (const entry of entries) {
            if (files.length >= MAX_FILES)
                return;
            const path = relative ? join(relative, entry.name) : entry.name;
            if (entry.isDirectory() && !SKIPPED.has(entry.name))
                await visit(path);
            else if (entry.isFile())
                files.push(path.split(sep).join("/"));
        }
    }
    await visit("");
    return files.sort();
}
function matchesGlob(path, glob) {
    let pattern = "^";
    for (let index = 0; index < glob.length; index += 1) {
        const character = glob[index];
        if (character === "*" && glob[index + 1] === "*") {
            if (glob[index + 2] === "/") {
                pattern += "(?:.*/)?";
                index += 2;
            }
            else {
                pattern += ".*";
                index += 1;
            }
        }
        else if (character === "*")
            pattern += "[^/]*";
        else if (character === "?")
            pattern += "[^/]";
        else
            pattern += character !== undefined && "^$+?.()|{}[]".includes(character) ? "\\" + character : character;
    }
    return new RegExp(`${pattern}$`, "i").test(path);
}
