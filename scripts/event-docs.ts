/**
 * Generates the event reference tables in the READMEs from the event maps,
 * so the documentation lists exactly what the emitters declare. Usage:
 *   npx ts-node scripts/event-docs.ts           rewrite the tables
 *   npx ts-node scripts/event-docs.ts --check   exit 1 if a table is stale
 * Each table sits between `<!-- events:<Interface>:start -->` and
 * `<!-- events:<Interface>:end -->` in its README.
 */
import * as fs from 'fs';
import * as path from 'path';
import * as ts from 'typescript';

const ROOT = path.resolve(__dirname, '..');

export interface IEventTable {
	/** The file that declares the map. */
	source: string;
	/** The map's interface or type alias name. */
	name: string;
	/** The README that carries the table. */
	readme: string;
}

export const EVENT_TABLES: IEventTable[] = [
	{
		source: 'src/lightning/node/events.ts',
		name: 'LightningNodeEvents',
		readme: 'src/lightning/README.md'
	}
];

function oneLine(text: string): string {
	return text.replace(/\s+/g, ' ').replace(/\|/g, '\\|').trim();
}

/** The listener's parameter list as written, `()` for none. */
function argumentsOf(declaration: ts.Declaration): string {
	if (
		ts.isPropertySignature(declaration) &&
		declaration.type &&
		ts.isFunctionTypeNode(declaration.type)
	) {
		const params = declaration.type.parameters.map((p) => p.getText());
		return oneLine(`(${params.join(', ')})`)
			.replace(/\(\s+/g, '(')
			.replace(/\s+\)/g, ')')
			.replace(/;\s*}/g, ' }');
	}
	throw new Error(`${declaration.getText()} is not a listener signature`);
}

/** The markdown table for one event map, one row per event. */
export function renderEventTable(table: IEventTable): string {
	const file = path.join(ROOT, table.source);
	const program = ts.createProgram([file], {
		noEmit: true,
		strict: true,
		target: ts.ScriptTarget.ES2020,
		module: ts.ModuleKind.CommonJS,
		esModuleInterop: true,
		skipLibCheck: true
	});
	const checker = program.getTypeChecker();
	const sourceFile = program.getSourceFile(file);
	if (!sourceFile) throw new Error(`cannot read ${table.source}`);
	const moduleSymbol = checker.getSymbolAtLocation(sourceFile);
	const symbol =
		moduleSymbol &&
		checker.getExportsOfModule(moduleSymbol).find((s) => s.name === table.name);
	if (!symbol) throw new Error(`${table.name} is not in ${table.source}`);
	const rows = checker
		.getPropertiesOfType(checker.getDeclaredTypeOfSymbol(symbol))
		.map((property) => {
			const declaration = property.declarations?.[0];
			if (!declaration) throw new Error(`${property.name} has no declaration`);
			const description = oneLine(
				ts.displayPartsToString(property.getDocumentationComment(checker))
			);
			return `| \`${property.name}\` | \`${argumentsOf(
				declaration
			)}\` | ${description} |`;
		});
	return [
		'| Event | Arguments | Description |',
		'|-------|-----------|-------------|',
		...rows
	].join('\n');
}

function markers(name: string): [string, string] {
	return [`<!-- events:${name}:start -->`, `<!-- events:${name}:end -->`];
}

/** The README with the table between its markers replaced by `rendered`. */
export function withTable(
	readme: string,
	name: string,
	rendered: string
): string {
	const [start, end] = markers(name);
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
	for (const table of EVENT_TABLES) {
		const readmePath = path.join(ROOT, table.readme);
		const current = fs.readFileSync(readmePath, 'utf8');
		const next = withTable(current, table.name, renderEventTable(table));
		if (next === current) continue;
		if (check) {
			stale = true;
			console.error(
				`${table.readme}: the ${table.name} table is out of date; run npm run docs:events`
			);
		} else {
			fs.writeFileSync(readmePath, next);
			console.log(`${table.readme}: wrote the ${table.name} table`);
		}
	}
	if (stale) process.exit(1);
}
