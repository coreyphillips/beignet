/**
 * Generates the event and option reference tables in the READMEs from the
 * typed maps and option interfaces, so the documentation lists exactly what
 * the code declares. Usage:
 *   npx ts-node scripts/doc-tables.ts           rewrite the tables
 *   npx ts-node scripts/doc-tables.ts --check   exit 1 if a table is stale
 * Each table sits between `<!-- <kind>:<Interface>:start -->` and
 * `<!-- <kind>:<Interface>:end -->` in its README.
 */
import * as fs from 'fs';
import * as path from 'path';
import * as ts from 'typescript';

const ROOT = path.resolve(__dirname, '..');

export interface IDocTable {
	/** An event map (listener signatures) or an options interface. */
	kind: 'events' | 'options';
	/** The file that declares the interface. */
	source: string;
	/** The interface or type alias name. */
	name: string;
	/** The README that carries the table. */
	readme: string;
	/** An extra events column, computed per event name. */
	column?: { header: string; value: () => (event: string) => string };
}

/**
 * The daemon decides at runtime which BeignetNode events reach SSE and
 * webhooks, so the column asks getRelayedEvents rather than reading its
 * source. Loaded lazily: it pulls in the whole CLI.
 */
function relayedOverSse(): (event: string) => string {
	// eslint-disable-next-line @typescript-eslint/no-var-requires
	const { getRelayedEvents } = require('../src/cli/daemon') as {
		getRelayedEvents: (htlcEvents?: boolean) => string[];
	};
	const always = new Set(getRelayedEvents(false));
	const withHtlc = new Set(getRelayedEvents(true));
	return (event) =>
		always.has(event) ? 'yes' : withHtlc.has(event) ? '`htlcEvents`' : 'no';
}

export const DOC_TABLES: IDocTable[] = [
	{
		kind: 'events',
		source: 'src/lightning/node/events.ts',
		name: 'LightningNodeEvents',
		readme: 'src/lightning/README.md'
	},
	{
		kind: 'options',
		source: 'src/lightning/node/types.ts',
		name: 'INodeConfig',
		readme: 'src/lightning/README.md'
	},
	{
		kind: 'events',
		source: 'src/cli/types.ts',
		name: 'BeignetNodeEvents',
		readme: 'src/cli/README.md',
		column: { header: 'SSE', value: relayedOverSse }
	},
	{
		kind: 'options',
		source: 'src/cli/beignet-node.ts',
		name: 'BeignetNodeOptions',
		readme: 'src/cli/README.md'
	}
];

let program: ts.Program | undefined;

/** One program over every source, since each pulls in most of the tree. */
function getProgram(): ts.Program {
	program ??= ts.createProgram(
		DOC_TABLES.map((table) => path.join(ROOT, table.source)),
		{
			noEmit: true,
			strict: true,
			target: ts.ScriptTarget.ES2020,
			module: ts.ModuleKind.CommonJS,
			esModuleInterop: true,
			resolveJsonModule: true,
			skipLibCheck: true
		}
	);
	return program;
}

const printer = ts.createPrinter({ removeComments: true });

function oneLine(text: string): string {
	return text.replace(/\s+/g, ' ').replace(/\|/g, '\\|').trim();
}

/** A type as written, on one line, without comments or import() prefixes. */
function typeText(node: ts.Node): string {
	return oneLine(
		printer.printNode(ts.EmitHint.Unspecified, node, node.getSourceFile())
	)
		.replace(/import\((["'])[^"']*\1\)\./g, '')
		.replace(/\(\s+/g, '(')
		.replace(/\s+\)/g, ')')
		.replace(/;\s*}/g, ' }');
}

/** The listener's parameter list as written, `()` for none. */
function argumentsOf(declaration: ts.Declaration): string {
	if (
		ts.isPropertySignature(declaration) &&
		declaration.type &&
		ts.isFunctionTypeNode(declaration.type)
	) {
		const params = declaration.type.parameters.map((p) => typeText(p));
		return `(${params.join(', ')})`;
	}
	throw new Error(`${declaration.getText()} is not a listener signature`);
}

/**
 * Prose for a table cell. Outside code spans `<url>` would be read as an HTML
 * tag and dropped from the rendered page, so angle brackets are escaped there.
 */
function prose(text: string): string {
	return oneLine(text)
		.split('`')
		.map((part, i) =>
			i % 2 === 0 ? part.replace(/</g, '&lt;').replace(/>/g, '&gt;') : part
		)
		.join('`');
}

/** The doc comment's first paragraph; the rest stays in the source and the API reference. */
function describe(symbol: ts.Symbol, checker: ts.TypeChecker): string {
	const text = prose(
		ts
			.displayPartsToString(symbol.getDocumentationComment(checker))
			.split(/\n\s*\n/)[0]
	);
	const deprecated = symbol
		.getJsDocTags(checker)
		.find((tag) => tag.name === 'deprecated');
	if (!deprecated) return text;
	const reason = prose(ts.displayPartsToString(deprecated.text));
	return `**Deprecated.** ${reason ? `${reason} ` : ''}${text}`.trim();
}

/** The object literal an option is typed as, if it is one. */
function literalOf(node: ts.TypeNode | undefined): ts.TypeLiteralNode | null {
	if (!node) return null;
	if (ts.isTypeLiteralNode(node)) return node;
	if (ts.isParenthesizedTypeNode(node)) return literalOf(node.type);
	return null;
}

function eventRows(
	table: IDocTable,
	checker: ts.TypeChecker,
	type: ts.Type
): string[] {
	const extra = table.column?.value();
	const header = ['Event', 'Arguments', 'Description'];
	if (table.column) header.splice(2, 0, table.column.header);
	const rows = checker.getPropertiesOfType(type).map((property) => {
		const declaration = property.declarations?.[0];
		if (!declaration) throw new Error(`${property.name} has no declaration`);
		const cells = [
			`\`${property.name}\``,
			`\`${argumentsOf(declaration)}\``,
			describe(property, checker)
		];
		if (extra) cells.splice(2, 0, extra(property.name));
		return `| ${cells.join(' | ')} |`;
	});
	return [
		`| ${header.join(' | ')} |`,
		`|${header.map((h) => '-'.repeat(h.length + 2)).join('|')}|`,
		...rows
	];
}

/** One row per option; an inline object option gets a row per field too. */
function optionRows(
	checker: ts.TypeChecker,
	type: ts.Type,
	prefix = ''
): string[] {
	return checker.getPropertiesOfType(type).flatMap((property) => {
		const declaration = property.declarations?.[0];
		if (!declaration || !ts.isPropertySignature(declaration)) {
			throw new Error(`${prefix}${property.name} is not a property signature`);
		}
		const optional = declaration.questionToken ? '?' : '';
		const literal = literalOf(declaration.type);
		const shown = declaration.type
			? literal
				? 'object'
				: typeText(declaration.type)
			: 'any';
		const row = `| \`${prefix}${
			property.name
		}${optional}\` | \`${shown}\` | ${describe(property, checker)} |`;
		if (!literal) return [row];
		return [
			row,
			...optionRows(
				checker,
				checker.getTypeAtLocation(literal),
				`${prefix}${property.name}.`
			)
		];
	});
}

/** The markdown table for one interface. */
export function renderTable(table: IDocTable): string {
	const file = path.join(ROOT, table.source);
	const checker = getProgram().getTypeChecker();
	const sourceFile = getProgram().getSourceFile(file);
	if (!sourceFile) throw new Error(`cannot read ${table.source}`);
	const moduleSymbol = checker.getSymbolAtLocation(sourceFile);
	const symbol =
		moduleSymbol &&
		checker.getExportsOfModule(moduleSymbol).find((s) => s.name === table.name);
	if (!symbol) throw new Error(`${table.name} is not in ${table.source}`);
	const type = checker.getDeclaredTypeOfSymbol(symbol);
	if (table.kind === 'events') {
		return eventRows(table, checker, type).join('\n');
	}
	return [
		'| Option | Type | Description |',
		'|--------|------|-------------|',
		...optionRows(checker, type)
	].join('\n');
}

function markers(table: IDocTable): [string, string] {
	return [
		`<!-- ${table.kind}:${table.name}:start -->`,
		`<!-- ${table.kind}:${table.name}:end -->`
	];
}

/** The README with the table between its markers replaced by `rendered`. */
export function withTable(
	readme: string,
	table: IDocTable,
	rendered: string
): string {
	const [start, end] = markers(table);
	const from = readme.indexOf(start);
	const to = readme.indexOf(end);
	if (from === -1 || to < from) {
		throw new Error(`the README has no ${start} ... ${end} block`);
	}
	return (
		readme.slice(0, from + start.length) +
		'\n' +
		rendered +
		'\n' +
		readme.slice(to)
	);
}

if (require.main === module) {
	const check = process.argv.includes('--check');
	let stale = false;
	for (const table of DOC_TABLES) {
		const readmePath = path.join(ROOT, table.readme);
		const current = fs.readFileSync(readmePath, 'utf8');
		const next = withTable(current, table, renderTable(table));
		if (next === current) continue;
		if (check) {
			stale = true;
			console.error(
				`${table.readme}: the ${table.name} table is out of date; run npm run docs:tables`
			);
		} else {
			fs.writeFileSync(readmePath, next);
			console.log(`${table.readme}: wrote the ${table.name} table`);
		}
	}
	if (stale) process.exit(1);
}
