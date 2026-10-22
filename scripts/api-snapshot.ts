/**
 * Records the exported API: for each package.json `exports` entry, one sorted
 * line per exported name and per public member, read from the declarations
 * the build emits to dist/types/, plus a list of every declaration tagged
 * `@deprecated`. Usage:
 *   npm run api:snapshot   rewrite tests/api-snapshot/
 * tests/api-snapshot/api-snapshot.test.ts fails while a file there is stale,
 * so a change to the public surface shows up as a diff of those files.
 */
import * as fs from 'fs';
import * as path from 'path';
import * as ts from 'typescript';

const ROOT = path.resolve(__dirname, '..');
export const SNAPSHOT_DIR = path.join(ROOT, 'tests/api-snapshot');
export const DEPRECATED_FILE = 'deprecated.txt';

export interface IEntryPoint {
	/** What a consumer imports, e.g. `beignet/lightning`. */
	specifier: string;
	/** Its `types` declaration file, relative to the repository root. */
	types: string;
	/** Its snapshot file under tests/api-snapshot/. */
	file: string;
}

export interface IApiLine {
	/** The qualified name, which is the sort key: `node.LightningNode.close`. */
	name: string;
	/** Kind, qualified name and signature. */
	text: string;
	deprecated: boolean;
}

/** Read from package.json, so a new entry point cannot go unrecorded. */
export function entryPoints(): IEntryPoint[] {
	const pkg = JSON.parse(
		fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')
	) as { name: string; exports: Record<string, string | { types?: string }> };
	return Object.entries(pkg.exports).flatMap(([subpath, target]) => {
		if (typeof target !== 'object' || !target.types) return [];
		const specifier = pkg.name + subpath.slice(1);
		return [
			{
				specifier,
				types: target.types,
				file: `${specifier.replace(/\//g, '-')}.txt`
			}
		];
	});
}

const formatHost: ts.FormatDiagnosticsHost = {
	getCanonicalFileName: (file) => file,
	getCurrentDirectory: () => ROOT,
	getNewLine: () => '\n'
};

/**
 * The .d.ts files `npm run build` writes, keyed by absolute path, emitted in
 * memory so a stale or missing dist/ does not matter.
 */
export function emitDeclarations(): {
	files: Map<string, string>;
	options: ts.CompilerOptions;
} {
	const config = ts.getParsedCommandLineOfConfigFile(
		path.join(ROOT, 'tsconfig.json'),
		undefined,
		{
			...ts.sys,
			onUnRecoverableConfigFileDiagnostic: (diagnostic) => {
				throw new Error(ts.formatDiagnostics([diagnostic], formatHost));
			}
		}
	);
	if (!config || config.errors.length) {
		throw new Error(ts.formatDiagnostics(config?.errors ?? [], formatHost));
	}
	const program = ts.createProgram(config.fileNames, config.options);
	const files = new Map<string, string>();
	const { emitSkipped, diagnostics } = program.emit(
		undefined,
		(file, text) => {
			if (file.endsWith('.d.ts')) files.set(path.resolve(file), text);
		},
		undefined,
		true
	);
	if (emitSkipped || diagnostics.length) {
		throw new Error(ts.formatDiagnostics(diagnostics, formatHost));
	}
	return { files, options: config.options };
}

/**
 * A program over in-memory declaration files. Paths under `dir` are served
 * from `files` only, never from disk, so a file left in dist/types/ by an
 * older build cannot stand in for one the build no longer emits.
 */
export function declarationProgram(
	files: Map<string, string>,
	dir: string,
	roots: string[],
	options: ts.CompilerOptions = {}
): ts.Program {
	const inside = (file: string): boolean => {
		const resolved = path.resolve(file);
		return resolved === dir || resolved.startsWith(dir + path.sep);
	};
	const dirs = new Set<string>();
	for (const file of files.keys()) {
		for (let d = path.dirname(file); inside(d); d = path.dirname(d)) {
			dirs.add(d);
			if (d === dir) break;
		}
	}
	const host = ts.createCompilerHost(options, true);
	const { fileExists, readFile, directoryExists, getSourceFile } = host;
	host.fileExists = (file): boolean =>
		inside(file) ? files.has(path.resolve(file)) : fileExists(file);
	host.readFile = (file): string | undefined =>
		inside(file) ? files.get(path.resolve(file)) : readFile(file);
	host.directoryExists = (d): boolean =>
		inside(d) ? dirs.has(path.resolve(d)) : directoryExists?.(d) ?? true;
	host.getSourceFile = (
		file,
		languageVersion,
		...rest
	): ts.SourceFile | undefined => {
		if (!inside(file)) return getSourceFile(file, languageVersion, ...rest);
		const text = files.get(path.resolve(file));
		return text === undefined
			? undefined
			: ts.createSourceFile(file, text, languageVersion, true);
	};
	return ts.createProgram(roots, { ...options, noEmit: true }, host);
}

const printer = ts.createPrinter({ removeComments: true });

/**
 * A node as declared, on one line. Module paths in `import("...").X` types
 * are dropped, so moving a file inside src/ does not change the snapshot.
 */
function print(node: ts.Node): string {
	return printer
		.printNode(ts.EmitHint.Unspecified, node, node.getSourceFile())
		.replace(/\s+/g, ' ')
		.replace(/import\((["'])[^"']*\1\)\./g, '')
		.trim();
}

function typeParameters(node: {
	typeParameters?: ts.NodeArray<ts.TypeParameterDeclaration>;
}): string {
	return node.typeParameters
		? `<${node.typeParameters.map(print).join(', ')}>`
		: '';
}

function signature(node: ts.SignatureDeclarationBase): string {
	const result = node.type ? `: ${print(node.type)}` : '';
	return `${typeParameters(node)}(${node.parameters
		.map(print)
		.join(', ')})${result}`;
}

function heritage(node: ts.ClassDeclaration | ts.InterfaceDeclaration): string {
	return (node.heritageClauses ?? []).map((c) => ` ${print(c)}`).join('');
}

const MODIFIERS: [ts.ModifierFlags, string][] = [
	[ts.ModifierFlags.Protected, 'protected'],
	[ts.ModifierFlags.Static, 'static'],
	[ts.ModifierFlags.Abstract, 'abstract'],
	[ts.ModifierFlags.Readonly, 'readonly']
];

function modifiers(node: ts.Declaration): string {
	const flags = ts.getCombinedModifierFlags(node);
	return MODIFIERS.filter(([flag]) => flags & flag)
		.map(([, word]) => `${word} `)
		.join('');
}

function isDeprecated(node: ts.Node): boolean {
	return ts.getJSDocDeprecatedTag(node) !== undefined;
}

function apiLine(name: string, text: string, node: ts.Node): IApiLine {
	return { name, text, deprecated: isDeprecated(node) };
}

/** One line per member a consumer can reach; private ones are skipped. */
function memberLines(
	owner: string,
	members: readonly (ts.ClassElement | ts.TypeElement)[]
): IApiLine[] {
	return members.flatMap((member) => {
		if (ts.getCombinedModifierFlags(member) & ts.ModifierFlags.Private) {
			return [];
		}
		if (member.name && ts.isPrivateIdentifier(member.name)) return [];
		const name = member.name ? `${owner}.${print(member.name)}` : owner;
		const optional =
			'questionToken' in member && member.questionToken ? '?' : '';
		let text: string;
		if (ts.isPropertyDeclaration(member) || ts.isPropertySignature(member)) {
			// A readonly literal is declared by its value: `readonly port = 0`.
			const type = member.type ? `: ${print(member.type)}` : '';
			const value = member.initializer ? ` = ${print(member.initializer)}` : '';
			text = `property ${name}${optional}${type}${value}`;
		} else if (ts.isMethodDeclaration(member) || ts.isMethodSignature(member)) {
			text = `method ${name}${optional}${signature(member)}`;
		} else if (ts.isGetAccessor(member)) {
			text = `get ${name}${signature(member)}`;
		} else if (ts.isSetAccessor(member)) {
			text = `set ${name}${signature(member)}`;
		} else if (ts.isConstructorDeclaration(member)) {
			text = `constructor ${owner}${signature(member)}`;
		} else if (ts.isConstructSignatureDeclaration(member)) {
			text = `new ${owner}${signature(member)}`;
		} else if (ts.isCallSignatureDeclaration(member)) {
			text = `call ${owner}${signature(member)}`;
		} else if (ts.isIndexSignatureDeclaration(member)) {
			const keys = member.parameters.map(print).join(', ');
			text = `index ${owner}[${keys}]: ${print(member.type)}`;
		} else {
			throw new Error(`${owner}: no rule for ${ts.SyntaxKind[member.kind]}`);
		}
		return [apiLine(name, modifiers(member) + text, member)];
	});
}

/** The lines for one declaration of an exported name (namespaces aside). */
function declarationLines(
	name: string,
	node: ts.Declaration,
	typeOnly: boolean
): IApiLine[] {
	const only = typeOnly ? 'type-only ' : '';
	if (ts.isFunctionDeclaration(node)) {
		return [apiLine(name, `${only}function ${name}${signature(node)}`, node)];
	}
	if (ts.isClassDeclaration(node)) {
		const text = `${only}${modifiers(node)}class ${name}${typeParameters(
			node
		)}${heritage(node)}`;
		return [apiLine(name, text, node), ...memberLines(name, node.members)];
	}
	if (ts.isInterfaceDeclaration(node)) {
		const text = `interface ${name}${typeParameters(node)}${heritage(node)}`;
		return [apiLine(name, text, node), ...memberLines(name, node.members)];
	}
	if (ts.isTypeAliasDeclaration(node)) {
		const text = `type ${name}${typeParameters(node)} = ${print(node.type)}`;
		return [apiLine(name, text, node)];
	}
	if (ts.isEnumDeclaration(node)) {
		const isConst = ts.getCombinedModifierFlags(node) & ts.ModifierFlags.Const;
		const text = `${only}${isConst ? 'const ' : ''}enum ${name}`;
		return [
			apiLine(name, text, node),
			...node.members.map((member) => {
				const memberName = `${name}.${print(member.name)}`;
				const value = member.initializer
					? ` = ${print(member.initializer)}`
					: '';
				return apiLine(memberName, `member ${memberName}${value}`, member);
			})
		];
	}
	if (ts.isVariableDeclaration(node)) {
		const flags = node.parent.flags;
		const kind =
			flags & ts.NodeFlags.Const
				? 'const'
				: flags & ts.NodeFlags.Let
				? 'let'
				: 'var';
		const type = node.type ? `: ${print(node.type)}` : '';
		const value = node.initializer ? ` = ${print(node.initializer)}` : '';
		return [apiLine(name, `${only}${kind} ${name}${type}${value}`, node)];
	}
	throw new Error(`${name}: no rule for ${ts.SyntaxKind[node.kind]}`);
}

/**
 * Whether the name is exported with `export type`, which keeps a class,
 * enum, function or variable out of value positions.
 */
function isTypeOnlyExport(checker: ts.TypeChecker, symbol: ts.Symbol): boolean {
	for (
		let s: ts.Symbol | undefined = symbol;
		s && s.flags & ts.SymbolFlags.Alias;
		s = checker.getImmediateAliasedSymbol(s)
	) {
		if (s.declarations?.some(ts.isTypeOnlyImportOrExportDeclaration)) {
			return true;
		}
	}
	return false;
}

function compare(a: string, b: string): number {
	return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Every exported name of the module `entry`, namespaces walked, sorted by
 * qualified name so a class's members follow it.
 */
export function apiLines(program: ts.Program, entry: string): IApiLine[] {
	const checker = program.getTypeChecker();
	const source = program.getSourceFile(entry);
	const moduleSymbol = source && checker.getSymbolAtLocation(source);
	if (!moduleSymbol) throw new Error(`${entry} is not an emitted module`);
	const lines: IApiLine[] = [];
	const walk = (
		container: ts.Symbol,
		prefix: string,
		open: ts.Symbol[]
	): void => {
		for (const exported of checker.getExportsOfModule(container)) {
			const name = prefix + exported.name;
			const target =
				exported.flags & ts.SymbolFlags.Alias
					? checker.getAliasedSymbol(exported)
					: exported;
			const declarations = target.declarations ?? [];
			if (!declarations.length) {
				throw new Error(`${name} does not resolve to a declaration`);
			}
			const typeOnly =
				isTypeOnlyExport(checker, exported) &&
				(target.flags & ts.SymbolFlags.Value) !== 0;
			const namespaces = declarations.filter(
				(d) => ts.isSourceFile(d) || ts.isModuleDeclaration(d)
			);
			for (const node of declarations) {
				if (!namespaces.includes(node)) {
					lines.push(...declarationLines(name, node, typeOnly));
				}
			}
			if (!namespaces.length) continue;
			lines.push({
				name,
				text: `namespace ${name}`,
				deprecated: namespaces.some(isDeprecated)
			});
			if (open.includes(target)) {
				throw new Error(`${name} re-exports a namespace that contains it`);
			}
			walk(target, `${name}.`, [...open, target]);
		}
	};
	walk(moduleSymbol, '', [moduleSymbol]);
	lines.sort((a, b) => compare(a.name, b.name) || compare(a.text, b.text));
	return lines.filter((line, i) => i === 0 || line.text !== lines[i - 1].text);
}

/** Every file under tests/api-snapshot/, keyed by name, as it should read. */
export function renderSnapshots(): Map<string, string> {
	const { files, options } = emitDeclarations();
	const dir = options.declarationDir;
	if (!dir) throw new Error('tsconfig.json sets no declarationDir');
	const entries = entryPoints();
	const program = declarationProgram(
		files,
		dir,
		entries.map((entry) => path.join(ROOT, entry.types)),
		options
	);
	const snapshots = new Map<string, string>();
	const deprecated: string[] = [];
	for (const entry of entries) {
		const lines = apiLines(program, path.join(ROOT, entry.types));
		snapshots.set(
			entry.file,
			[
				`# The exported API of ${entry.specifier}. Regenerate with npm run api:snapshot; do not edit.`,
				...lines.map((line) => line.text),
				''
			].join('\n')
		);
		for (const line of lines) {
			if (line.deprecated) deprecated.push(`${entry.specifier}: ${line.text}`);
		}
	}
	snapshots.set(
		DEPRECATED_FILE,
		[
			'# Every exported declaration tagged @deprecated. Regenerate with npm run api:snapshot; do not edit.',
			...deprecated,
			''
		].join('\n')
	);
	return snapshots;
}

if (require.main === module) {
	const snapshots = renderSnapshots();
	fs.mkdirSync(SNAPSHOT_DIR, { recursive: true });
	for (const name of fs.readdirSync(SNAPSHOT_DIR)) {
		if (name.endsWith('.txt') && !snapshots.has(name)) {
			fs.unlinkSync(path.join(SNAPSHOT_DIR, name));
			console.log(`tests/api-snapshot/${name}: removed`);
		}
	}
	for (const [name, text] of snapshots) {
		const file = path.join(SNAPSHOT_DIR, name);
		if (fs.existsSync(file) && fs.readFileSync(file, 'utf8') === text) continue;
		fs.writeFileSync(file, text);
		console.log(`tests/api-snapshot/${name}: written`);
	}
}
