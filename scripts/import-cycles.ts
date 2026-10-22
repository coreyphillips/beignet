/**
 * Fails when the value imports under src/ form a cycle. Usage:
 *   npx ts-node scripts/import-cycles.ts
 * An edge is any static import or re-export not marked `type`, which is what
 * runs under `verbatimModuleSyntax` or an ESM build, where a cycle can leave
 * a class `undefined` at import time. Lint enforces `import type` for imports
 * used only as types, so these edges are the ones that load at runtime. Lazy
 * `require()` and `import()` calls inside functions are not edges.
 */
import * as fs from 'fs';
import * as path from 'path';
import * as ts from 'typescript';

const ROOT = path.resolve(__dirname, '..');
const SRC = path.join(ROOT, 'src');

/** The module specifiers a file loads when it is itself loaded. */
export function valueImportSpecifiers(source: ts.SourceFile): string[] {
	const specifiers: string[] = [];
	for (const statement of source.statements) {
		if (ts.isImportDeclaration(statement)) {
			if (statement.importClause?.isTypeOnly) continue;
			specifiers.push((statement.moduleSpecifier as ts.StringLiteral).text);
		} else if (ts.isExportDeclaration(statement)) {
			if (statement.isTypeOnly || !statement.moduleSpecifier) continue;
			specifiers.push((statement.moduleSpecifier as ts.StringLiteral).text);
		} else if (
			ts.isImportEqualsDeclaration(statement) &&
			!statement.isTypeOnly &&
			ts.isExternalModuleReference(statement.moduleReference)
		) {
			const expr = statement.moduleReference.expression;
			if (ts.isStringLiteral(expr)) specifiers.push(expr.text);
		}
	}
	return specifiers;
}

/**
 * The strongly connected components that form a cycle: more than one file,
 * or one file importing itself. Tarjan's algorithm, iterative so a deep
 * import chain cannot overflow the stack.
 */
export function findCycles(graph: Map<string, string[]>): string[][] {
	const index = new Map<string, number>();
	const low = new Map<string, number>();
	const onStack = new Set<string>();
	const stack: string[] = [];
	const components: string[][] = [];
	let next = 0;

	const visit = (node: string): void => {
		index.set(node, next);
		low.set(node, next++);
		stack.push(node);
		onStack.add(node);
	};

	for (const start of graph.keys()) {
		if (index.has(start)) continue;
		visit(start);
		const work: { node: string; edge: number }[] = [{ node: start, edge: 0 }];
		while (work.length > 0) {
			const frame = work[work.length - 1];
			const edges = graph.get(frame.node) ?? [];
			if (frame.edge < edges.length) {
				const to = edges[frame.edge++];
				if (!index.has(to)) {
					visit(to);
					work.push({ node: to, edge: 0 });
				} else if (onStack.has(to)) {
					low.set(frame.node, Math.min(low.get(frame.node)!, index.get(to)!));
				}
				continue;
			}
			work.pop();
			if (work.length > 0) {
				const parent = work[work.length - 1].node;
				low.set(parent, Math.min(low.get(parent)!, low.get(frame.node)!));
			}
			if (low.get(frame.node) === index.get(frame.node)) {
				const component: string[] = [];
				let member: string;
				do {
					member = stack.pop()!;
					onStack.delete(member);
					component.push(member);
				} while (member !== frame.node);
				components.push(component);
			}
		}
	}
	return components.filter(
		(component) =>
			component.length > 1 ||
			(graph.get(component[0]) ?? []).includes(component[0])
	);
}

function listSources(dir: string, out: string[] = []): string[] {
	for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
		const full = path.join(dir, entry.name);
		if (entry.isDirectory()) listSources(full, out);
		else if (entry.name.endsWith('.ts') && !entry.name.endsWith('.d.ts')) {
			out.push(full);
		}
	}
	return out;
}

/** Relative specifiers only: a package cannot import back into src/. */
function resolveSource(from: string, specifier: string): string | undefined {
	if (!specifier.startsWith('.')) return undefined;
	const base = path.resolve(path.dirname(from), specifier);
	return [`${base}.ts`, path.join(base, 'index.ts')].find((candidate) =>
		fs.existsSync(candidate)
	);
}

/** Each file under src/ mapped to the files under src/ it loads. */
export function sourceGraph(): Map<string, string[]> {
	const graph = new Map<string, string[]>();
	for (const file of listSources(SRC)) {
		const source = ts.createSourceFile(
			file,
			fs.readFileSync(file, 'utf8'),
			ts.ScriptTarget.Latest
		);
		const targets = new Set<string>();
		for (const specifier of valueImportSpecifiers(source)) {
			const target = resolveSource(file, specifier);
			if (target) targets.add(target);
		}
		graph.set(file, [...targets]);
	}
	return graph;
}

if (require.main === module) {
	const graph = sourceGraph();
	const cycles = findCycles(graph);
	const rel = (file: string): string => path.relative(ROOT, file);
	if (cycles.length === 0) {
		console.log(`No import cycles across ${graph.size} files under src/.`);
	}
	for (const component of cycles) {
		const members = new Set(component);
		console.error(`Import cycle across ${component.length} files:`);
		for (const file of [...component].sort()) {
			const inCycle = graph.get(file)!.filter((to) => members.has(to));
			console.error(`  ${rel(file)} -> ${inCycle.map(rel).join(', ')}`);
		}
	}
	if (cycles.length > 0) process.exit(1);
}
