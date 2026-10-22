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
	/**
	 * A member of an object type inside another line's signature, which that
	 * line already records, so it is listed in deprecated.txt only.
	 */
	inner?: boolean;
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

/**
 * The name a recorded signature gives the declaration a reference resolves
 * to, set by apiLines for each entry point. That is the name the entry point
 * exports it under, or `beignet#Wallet` for one another entry point exports.
 * An unexported declaration keeps its own name, with its file in front
 * (`./webhooks#WebhookRegistration`) when another declaration has that name.
 * Without it, `invoice.IFallbackAddress` and `offer.IFallbackAddress` would
 * both print as `IFallbackAddress`, and switching between them would show no
 * change.
 */
let identityOf: (node: ts.Node) => string | undefined = () => undefined;

const printer = ts.createPrinter(
	{ removeComments: true },
	{
		substituteNode: (_, node) => {
			const identity = identityOf(node);
			return identity === undefined
				? node
				: ts.factory.createIdentifier(identity);
		}
	}
);

/**
 * A node as declared, on one line. String and template literals are part of
 * the type, so their text is kept as is. References print as identityOf
 * names them, and module paths in `import("...").X` types are dropped:
 * moving a file inside src/ is not an API change.
 */
function print(node: ts.Node): string {
	return printer
		.printNode(ts.EmitHint.Unspecified, node, node.getSourceFile())
		.replace(
			/("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`)|(\s+)|import\((["'])[^"']*\3\)\./g,
			(_, literal?: string, space?: string) => literal ?? (space ? ' ' : '')
		)
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
	[ts.ModifierFlags.Private, 'private'],
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

/**
 * The members tagged @deprecated in the object types inside a one-line
 * signature, such as an options parameter or an aliased object type.
 */
function deprecatedInside(owner: string, node: ts.Node): IApiLine[] {
	const found: IApiLine[] = [];
	const visit = (child: ts.Node): void => {
		if (!ts.isTypeLiteralNode(child)) {
			ts.forEachChild(child, visit);
			return;
		}
		for (const line of memberLines(owner, child.members)) {
			if (line.deprecated) found.push({ ...line, inner: true });
		}
	};
	visit(node);
	return found;
}

/**
 * One line per member a consumer can reach. Private ones are skipped, except
 * a private constructor, which is what stops a consumer calling `new`.
 */
function memberLines(
	owner: string,
	members: readonly (ts.ClassElement | ts.TypeElement)[]
): IApiLine[] {
	return members.flatMap((member) => {
		if (
			ts.getCombinedModifierFlags(member) & ts.ModifierFlags.Private &&
			!ts.isConstructorDeclaration(member)
		) {
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
		return [
			apiLine(name, modifiers(member) + text, member),
			...deprecatedInside(name, member)
		];
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
		const text = `${only}function ${name}${signature(node)}`;
		return [apiLine(name, text, node), ...deprecatedInside(name, node)];
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
		return [apiLine(name, text, node), ...deprecatedInside(name, node.type)];
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
		return [
			apiLine(name, `${only}${kind} ${name}${type}${value}`, node),
			...deprecatedInside(name, node)
		];
	}
	throw new Error(`${name}: no rule for ${ts.SyntaxKind[node.kind]}`);
}

/**
 * Whether an import or export the name goes through passes `test`, such as
 * `export type`, which keeps a class, enum, function or variable out of value
 * positions, or a @deprecated tag on `export { run as oldRun }`.
 */
function viaAlias(
	checker: ts.TypeChecker,
	symbol: ts.Symbol,
	test: (node: ts.Declaration) => boolean
): boolean {
	for (
		let s: ts.Symbol | undefined = symbol;
		s && s.flags & ts.SymbolFlags.Alias;
		s = checker.getImmediateAliasedSymbol(s)
	) {
		if (s.declarations?.some(test)) return true;
	}
	return false;
}

/**
 * `bitcoinjs-lib#Transaction` for a declaration a dependency exports, so a
 * renamed import (`Transaction as Psbt`) or a same-named type from another
 * package is a change. Globals such as Buffer keep their own name.
 */
function dependencyName(
	program: ts.Program,
	symbol: ts.Symbol
): string | undefined {
	const file = symbol.declarations?.[0]?.getSourceFile();
	if (!file || !program.isSourceFileFromExternalLibrary(file)) return undefined;
	const qualified = /^"([^"]*)"\.(.+)$/.exec(
		program.getTypeChecker().getFullyQualifiedName(symbol)
	);
	if (!qualified) return undefined;
	const [, module, name] = qualified;
	const pkg = /.*\/node_modules\/((?:@[^/]+\/)?[^/]+)/.exec(module)?.[1];
	return `${pkg ?? module}#${name}`;
}

function compare(a: string, b: string): number {
	return a < b ? -1 : a > b ? 1 : 0;
}

function declaresApi(node: ts.Node): boolean {
	return (
		ts.isClassDeclaration(node) ||
		ts.isInterfaceDeclaration(node) ||
		ts.isTypeAliasDeclaration(node) ||
		ts.isEnumDeclaration(node) ||
		ts.isFunctionDeclaration(node) ||
		ts.isVariableDeclaration(node)
	);
}

/**
 * The declarations that recorded signatures use but no entry point exports,
 * such as a base class: consumers depend on their members as much as on the
 * exported ones.
 */
function unexportedDeclarations(
	program: ts.Program,
	declared: ts.Node[],
	exported: Set<ts.Symbol>
): Map<ts.Symbol, ts.Declaration[]> {
	const checker = program.getTypeChecker();
	const seen = new Set(exported);
	const found = new Map<ts.Symbol, ts.Declaration[]>();
	const visit = (node: ts.Node): void => {
		const reference = ts.isTypeReferenceNode(node)
			? node.typeName
			: ts.isExpressionWithTypeArguments(node)
			? node.expression
			: ts.isTypeQueryNode(node)
			? node.exprName
			: ts.isImportTypeNode(node)
			? node.qualifier
			: ts.isComputedPropertyName(node)
			? node.expression
			: undefined;
		let symbol = reference && checker.getSymbolAtLocation(reference);
		if (symbol && symbol.flags & ts.SymbolFlags.Alias) {
			symbol = checker.getAliasedSymbol(symbol);
		}
		if (symbol && !seen.has(symbol)) {
			seen.add(symbol);
			for (const declaration of symbol.declarations ?? []) {
				const file = declaration.getSourceFile();
				if (
					!declaresApi(declaration) ||
					program.isSourceFileFromExternalLibrary(file) ||
					program.isSourceFileDefaultLibrary(file)
				) {
					continue;
				}
				found.set(symbol, [...(found.get(symbol) ?? []), declaration]);
				visit(declaration);
			}
		}
		ts.forEachChild(node, visit);
	};
	declared.forEach(visit);
	return found;
}

/**
 * For each module in `entries`, every exported name, namespaces walked, and
 * the unexported declarations their signatures use. Lines are sorted by
 * qualified name so a class's members follow it. Within a name they keep
 * declaration order, as overload order changes what a consumer's types see.
 */
export function apiLines(
	program: ts.Program,
	entries: Pick<IEntryPoint, 'specifier' | 'types'>[]
): IApiLine[][] {
	const checker = program.getTypeChecker();
	const exported = new Set<ts.Symbol>();
	const walked = entries.map((entry) => {
		const file = path.resolve(ROOT, entry.types);
		const source = program.getSourceFile(file);
		const moduleSymbol = source && checker.getSymbolAtLocation(source);
		if (!moduleSymbol) throw new Error(`${file} is not an emitted module`);
		// Printed once every entry point's names are known, as a signature can
		// use a declaration only another entry point exports.
		const pending: (() => IApiLine[])[] = [];
		const declared: ts.Node[] = [];
		// The first in sort order, when one is exported under several names.
		const names = new Map<ts.Symbol, string>();
		const walk = (
			container: ts.Symbol,
			prefix: string,
			open: ts.Symbol[]
		): void => {
			for (const symbol of checker.getExportsOfModule(container)) {
				const name = prefix + symbol.name;
				const target =
					symbol.flags & ts.SymbolFlags.Alias
						? checker.getAliasedSymbol(symbol)
						: symbol;
				const declarations = target.declarations ?? [];
				if (!declarations.length) {
					throw new Error(`${name} does not resolve to a declaration`);
				}
				exported.add(target);
				const known = names.get(target);
				if (known === undefined || compare(name, known) < 0) {
					names.set(target, name);
				}
				const typeOnly =
					viaAlias(checker, symbol, ts.isTypeOnlyImportOrExportDeclaration) &&
					(target.flags & ts.SymbolFlags.Value) !== 0;
				const deprecatedName = viaAlias(checker, symbol, isDeprecated);
				const namespaces = declarations.filter(
					(d) => ts.isSourceFile(d) || ts.isModuleDeclaration(d)
				);
				for (const node of declarations) {
					if (!namespaces.includes(node)) {
						pending.push(() => {
							const [head, ...rest] = declarationLines(name, node, typeOnly);
							const deprecated = head.deprecated || deprecatedName;
							return [{ ...head, deprecated }, ...rest];
						});
						declared.push(node);
					}
				}
				if (!namespaces.length) continue;
				const text = `${typeOnly ? 'type-only ' : ''}namespace ${name}`;
				const deprecated = deprecatedName || namespaces.some(isDeprecated);
				pending.push(() => [{ name, text, deprecated }]);
				if (open.includes(target)) {
					throw new Error(`${name} re-exports a namespace that contains it`);
				}
				walk(target, `${name}.`, [...open, target]);
			}
		};
		walk(moduleSymbol, '', [moduleSymbol]);
		return { file, pending, declared, names };
	});
	return walked.map(({ file, pending, declared, names }) => {
		const unexported = unexportedDeclarations(program, declared, exported);
		const identities = new Map(names);
		const uses = new Map<string, number>();
		for (const name of names.values()) uses.set(name, 1);
		for (const { name } of unexported.keys()) {
			uses.set(name, (uses.get(name) ?? 0) + 1);
		}
		for (const [symbol, [first]] of unexported) {
			// Named by file as well when another declaration has its name.
			const from = path
				.relative(path.dirname(file), first.getSourceFile().fileName)
				.replace(/\.d\.ts$/, '');
			identities.set(
				symbol,
				uses.get(symbol.name) === 1
					? symbol.name
					: `${from.startsWith('.') ? '' : './'}${from}#${symbol.name}`
			);
		}
		identityOf = (node): string | undefined => {
			if (
				!ts.isIdentifier(node) &&
				!ts.isQualifiedName(node) &&
				!ts.isPropertyAccessExpression(node)
			) {
				return undefined;
			}
			let symbol = checker.getSymbolAtLocation(node);
			if (symbol && symbol.flags & ts.SymbolFlags.Alias) {
				symbol = checker.getAliasedSymbol(symbol);
			}
			if (!symbol) return undefined;
			const own = identities.get(symbol);
			if (own !== undefined) return own;
			const i = walked.findIndex((other) => other.names.has(symbol!));
			return i < 0
				? dependencyName(program, symbol)
				: `${entries[i].specifier}#${walked[i].names.get(symbol)}`;
		};
		const lines = pending.flatMap((render) => render());
		for (const [symbol, declarations] of unexported) {
			for (const declaration of declarations) {
				const [head, ...rest] = declarationLines(
					identities.get(symbol)!,
					declaration,
					false
				);
				lines.push({ ...head, text: `unexported ${head.text}` }, ...rest);
			}
		}
		lines.sort((a, b) => compare(a.name, b.name));
		return lines.filter(
			(line, i) => i === 0 || line.text !== lines[i - 1].text
		);
	});
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
	const perEntry = apiLines(program, entries);
	for (const [i, entry] of entries.entries()) {
		const lines = perEntry[i];
		snapshots.set(
			entry.file,
			[
				`# The exported API of ${entry.specifier}. Regenerate with npm run api:snapshot; do not edit.`,
				...lines.filter((line) => !line.inner).map((line) => line.text),
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
